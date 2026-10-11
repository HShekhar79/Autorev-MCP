"""
backend/tests/test_truthful_engine_metadata.py

Targeted tests for Fix 5: Truthful extraction-engine metadata.
Verifies:
1. Radare2 success correctly propagates radare2_available=True and extraction_engine.
2. Radare2 unavailable with Ghidra fallback success propagates radare2_available=False
   and ghidra_available=True, with extraction_engine='ghidra'.
3. Total extraction failure raises PipelineExtractionFailedError and does not claim
   engines were available.
4. Unified extractor does not claim radare2_available=True merely because wrapper functions
   returned empty lists when radare2 failed to open.
5. Partial results from a successful engine are preserved.
"""

from unittest.mock import patch
import pytest

from engines.unified_extractor import unified_extractor as ue
from services import analysis_pipeline as pipeline


@pytest.fixture(autouse=True)
def clean_cache():
    pipeline._pipeline_cache.clear()
    yield
    pipeline._pipeline_cache.clear()


def test_radare2_success_metadata():
    """Test truthful metadata when Radare2 succeeds."""
    fake_extract = {
        "functions": [{"name": "f1"}],
        "imports": ["kernel32.dll"],
        "strings": ["test"],
        "calls": ["VirtualAlloc"],
        "_meta": {
            "radare2_available": True,
            "ghidra_available": False,
            "extraction_engine": "radare2",
            "elapsed_seconds": 1.2,
        },
    }

    with patch.object(pipeline, "run_unified_extraction", return_value=fake_extract), \
         patch.object(pipeline, "analyze_functions", return_value={"results": []}):
        result = pipeline.run_analysis_pipeline("sample_r2.bin")

        meta = result["analysis_meta"]
        assert meta["radare2_available"] is True
        assert meta["ghidra_available"] is False
        assert meta["extraction_engine"] == "radare2"


def test_radare2_unavailable_with_ghidra_success():
    """Test truthful metadata when Radare2 is unavailable but Ghidra succeeds."""
    fake_extract = {
        "functions": [{"name": "ghidra_func"}],
        "imports": [],
        "strings": ["ghidra_str"],
        "calls": ["CreateFileW"],
        "_meta": {
            "radare2_available": False,
            "ghidra_available": True,
            "extraction_engine": "ghidra",
            "elapsed_seconds": 2.5,
        },
    }

    with patch.object(pipeline, "run_unified_extraction", return_value=fake_extract), \
         patch.object(pipeline, "analyze_functions", return_value={"results": []}):
        result = pipeline.run_analysis_pipeline("sample_ghidra.bin")

        meta = result["analysis_meta"]
        assert meta["radare2_available"] is False
        assert meta["ghidra_available"] is True
        assert meta["extraction_engine"] == "ghidra"
        # Verify Ghidra's extracted evidence survived
        assert len(result["functions"]) == 1
        assert result["calls"] == ["CreateFileW"]


def test_total_extraction_failure_honest_metadata():
    """Test total extraction failure honestly raises PipelineExtractionFailedError."""
    fake_extract = {
        "functions": [],
        "imports": [],
        "strings": [],
        "calls": [],
        "_meta": {
            "radare2_available": False,
            "ghidra_available": False,
            "extraction_engine": "none",
            "reason": "both engines unavailable",
        },
    }

    with patch.object(pipeline, "run_unified_extraction", return_value=fake_extract), \
         patch.object(pipeline, "analyze_functions", return_value={"results": []}):
        with pytest.raises(pipeline.PipelineExtractionFailedError) as exc_info:
            pipeline.run_analysis_pipeline("unextractable.bin")

        assert "no usable evidence" in str(exc_info.value)
        assert "both engines unavailable" in str(exc_info.value)


def test_unified_extractor_does_not_claim_r2_on_silent_empty_failure(monkeypatch):
    """Test that when wrappers return [] because r2 session failed, r2_available is False."""
    # Mock wrappers returning empty lists as they do when catching exceptions
    monkeypatch.setattr(ue, "r2_extract_functions", lambda p: [])
    monkeypatch.setattr(ue, "r2_extract_imports", lambda p: [])
    monkeypatch.setattr(ue, "r2_extract_strings", lambda p: [])

    # Mock RadareExtractor.open() raising an error
    class FailingExtractor:
        def __init__(self, p): pass
        def open(self): raise RuntimeError("r2 failed to open binary")
        def close(self): pass

    monkeypatch.setattr(ue, "RadareExtractor", FailingExtractor)
    monkeypatch.setattr(ue, "_GHIDRA_MODULE_AVAILABLE", False)

    result = ue.run_unified_extraction("corrupt.bin")
    meta = result["_meta"]

    # Must NOT claim radare2_available=True
    assert meta["radare2_available"] is False
    assert meta["extraction_engine"] == "none"
