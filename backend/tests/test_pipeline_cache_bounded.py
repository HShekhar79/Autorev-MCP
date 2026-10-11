"""
backend/tests/test_pipeline_cache_bounded.py

Targeted tests for Fix 3: Pipeline cache correctness and bounded memory.
Verifies:
1. Cache hit returns equivalent result.
2. Mutation isolation: modifying returned object does not mutate cached object.
3. Cache invalidation on file modification: changing file size/mtime invalidates entry.
4. Bounded capacity: cache stays bounded to max_size under high insertion volume.
5. Explicit invalidation via _invalidate_cache(path).
6. Partial failures are not cached.
7. Concurrent access safety under multi-threaded load.
"""

import os
import time
import threading
from unittest.mock import patch
import pytest

from services import analysis_pipeline as pipeline
from services.analysis_pipeline import BoundedPipelineCache, _get_file_identity, PipelineExtractionFailedError


@pytest.fixture(autouse=True)
def clean_cache():
    pipeline._pipeline_cache.clear()
    yield
    pipeline._pipeline_cache.clear()


def test_cache_hit_and_mutation_isolation(tmp_path):
    """Test that cache hits return equal result but distinct objects (isolated from mutation)."""
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 32)

    dummy_result = {
        "analysis": {"results": []},
        "functions": ["f1"],
        "calls": [],
        "imports": ["user32.dll"],
        "strings": ["hello"],
        "behaviors": {"behaviors": [], "_detail": []},
        "capabilities": [],
        "capability_scores": {},
        "deduplicated_capabilities": [],
        "capa_results": {},
        "capa_status": {},
        "mitre_results": {},
        "capability_mitre_results": {},
        "final_mitre": {},
        "mitre_candidates": [],
        "features": {},
        "risk": {"combined_score": 10},
        "ranked_functions": [],
        "cvss_results": {},
        "arise_verdict": {"verdict": "BENIGN"},
        "analysis_meta": {"filename": "sample.exe"},
    }

    calls = []
    def fake_unified(p):
        calls.append(p)
        return {"functions": [{"name": "f1"}], "imports": ["user32.dll"], "strings": ["hello"], "calls": []}

    with patch.object(pipeline, "run_unified_extraction", fake_unified), \
         patch.object(pipeline, "analyze_functions", lambda p, **kw: {"results": []}):
        r1 = pipeline.run_analysis_pipeline(str(sample))
        assert len(calls) == 1

        # Second call should be a cache hit
        r2 = pipeline.run_analysis_pipeline(str(sample))
        assert len(calls) == 1
        assert r1 == r2
        assert r1 is not r2  # Distinct objects

        # Mutate r1
        r1["functions"].append("MUTATED")
        r1["analysis_meta"]["polluted"] = True

        # r2 and subsequent cache lookups must be unaffected
        r3 = pipeline.run_analysis_pipeline(str(sample))
        assert "MUTATED" not in r3["functions"]
        assert "polluted" not in r3["analysis_meta"]


def test_file_modification_invalidates_cache(tmp_path):
    """Test that modifying a file's content/size at the same path invalidates stale cached results."""
    sample = tmp_path / "target.bin"
    sample.write_bytes(b"MZinitialcontent")

    calls = []
    def fake_unified(p):
        calls.append(len(calls))
        return {"functions": [{"name": f"f_{len(calls)}"}], "imports": [], "strings": [], "calls": []}

    with patch.object(pipeline, "run_unified_extraction", fake_unified), \
         patch.object(pipeline, "analyze_functions", lambda p, **kw: {"results": []}):
        r1 = pipeline.run_analysis_pipeline(str(sample))
        assert len(calls) == 1

        # Same file without change -> hit
        r2 = pipeline.run_analysis_pipeline(str(sample))
        assert len(calls) == 1

        # Overwrite file with different size
        sample.write_bytes(b"MZdifferentcontentslongerbinarypayload")
        r3 = pipeline.run_analysis_pipeline(str(sample))
        assert len(calls) == 2  # Cache miss because file identity changed


def test_explicit_invalidation(tmp_path):
    """Test _invalidate_cache properly removes path and file identity."""
    sample = tmp_path / "inv.bin"
    sample.write_bytes(b"MZcontent")

    calls = []
    def fake_unified(p):
        calls.append(p)
        return {"functions": [{"name": "f"}], "imports": [], "strings": [], "calls": []}

    with patch.object(pipeline, "run_unified_extraction", fake_unified), \
         patch.object(pipeline, "analyze_functions", lambda p, **kw: {"results": []}):
        pipeline.run_analysis_pipeline(str(sample))
        assert len(calls) == 1

        pipeline._invalidate_cache(str(sample))

        pipeline.run_analysis_pipeline(str(sample))
        assert len(calls) == 2


def test_bounded_capacity():
    """Test that BoundedPipelineCache respects max_size and evicts oldest items."""
    cache = BoundedPipelineCache(max_size=5)

    for i in range(10):
        ident = (f"/path/{i}", i, i * 100)
        cache.set_entry(ident, f"/path/{i}", {"index": i})

    assert len(cache) == 5
    # The oldest entries 0..4 should have been evicted
    for i in range(5):
        assert cache.get_entry((f"/path/{i}", i, i * 100), f"/path/{i}") is None

    # The newest entries 5..9 should be present
    for i in range(5, 10):
        res = cache.get_entry((f"/path/{i}", i, i * 100), f"/path/{i}")
        assert res is not None
        assert res["index"] == i


def test_partial_failures_not_cached():
    """Test that extraction failures are not stored in cache."""
    with patch.object(pipeline, "run_unified_extraction",
                      return_value={"functions": [], "imports": [], "strings": [], "calls": [], "_meta": {}}), \
         patch.object(pipeline, "analyze_functions", return_value={"results": []}):
        with pytest.raises(PipelineExtractionFailedError):
            pipeline.run_analysis_pipeline("nonexistent_failure.bin")

    assert len(pipeline._pipeline_cache) == 0


def test_concurrent_cache_access():
    """Test thread-safe concurrent access under multiple threads."""
    cache = BoundedPipelineCache(max_size=10)
    errors = []

    def worker(worker_id):
        try:
            for i in range(50):
                key = f"/file_{i % 15}"
                ident = (key, 100, 200)
                if i % 2 == 0:
                    cache.set_entry(ident, key, {"worker": worker_id, "i": i})
                else:
                    cache.get_entry(ident, key)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(cache) <= 10
