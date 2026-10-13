"""
test_analysis_pipeline_architecture.py

Focused architecture/compatibility tests for the shared analysis pipeline.
Expensive engines are replaced with stubs in services.analysis_pipeline.

Run with:
    python -m pytest -q test_analysis_pipeline_architecture.py test_pipeline_failure_boundary.py
"""
import contextlib
import copy
import os
from unittest.mock import patch

import pytest

import analysis
from services import analysis_pipeline as pipeline

STAGES = ["extraction", "function_analysis", "capa", "behaviour_capability",
          "mitre", "scoring", "complete"]

AUTHORITATIVE_KEYS = [
    "analysis", "imports", "strings", "behaviors", "capabilities",
    "capability_scores", "deduplicated_capabilities", "capa_results",
    "capa_status", "mitre_results", "capability_mitre_results", "final_mitre",
    "features", "risk", "ranked_functions", "cvss_results", "arise_verdict",
    "analysis_meta",
]


class _CapEngine:
    def run(self, x):
        return {"capabilities": ["cap_a"], "scores": {"cap_a": 1.0}}


class _CapMitreEngine:
    def run(self, caps, scores):
        return {"mitre_techniques": ["T1055"]}


def _stubs():
    return dict(
        run_unified_extraction=lambda p: {
            "functions": [{"name": "f"}], "imports": ["kernel32.dll"],
            "strings": ["s"], "calls": ["VirtualAlloc"],
            "_meta": {"radare2_available": True, "ghidra_available": False},
        },
        analyze_functions=lambda p, strings=None, imports=None: {
            "results": [{"function_name": "f", "behaviours": []}],
            "global_behaviours": [], "global_capabilities": [],
        },
        run_capa_analysis=lambda p: {"status": "success", "capabilities": [],
                                     "normalized_capabilities": [],
                                     "function_capabilities": {}},
        get_capa_status_summary=lambda r: {"status": "success", "enabled": True},
        merge_function_capabilities_with_capa=lambda res, caps: [
            {"function_name": "merged_by_capa", "capabilities": ["x"]}],
        analyze_imports_for_behaviour=lambda i: [],
        normalize_behavior=lambda b: b,
        deduplicate_capabilities=lambda behavior_capabilities, capa_capabilities: [
            {"name": "inject", "confidence": 0.9}],
        _raw_extract_features=lambda f, i, s, b: {"import_count": len(i)},
        CapabilityEngine=_CapEngine,
        CapabilityMitreEngine=_CapMitreEngine,
        map_behaviour_to_mitre=lambda b: {"mitre_techniques": ["T1055"]},
        merge_mitre_results=lambda a, b, weight_capabilities=False: {
            "mitre_techniques": ["T1055"]},
        calculate_combined_risk=lambda **k: {"combined_score": 42},
        rank_suspicious_functions=lambda r: [],
        calculate_cvss_score=lambda ids: {"cvss_score": 7.5, "risk_level": "HIGH"},
        arise_verdict=lambda **k: {"verdict": "MALICIOUS", "confidence": 90},
    )


@pytest.fixture(autouse=True)
def stubbed_engines():
    pipeline._pipeline_cache.clear()
    with contextlib.ExitStack() as stack:
        for name, repl in _stubs().items():
            stack.enter_context(patch.object(pipeline, name, repl))
        yield
    pipeline._pipeline_cache.clear()


# --- A: one shared implementation -----------------------------------------

def test_a_legacy_wrapper_delegates_to_shared_pipeline():
    assert analysis._shared_pipeline is pipeline.run_analysis_pipeline


def test_a_route_uses_shared_pipeline():
    pytest.importorskip("fastapi")
    route = pytest.importorskip("api.routes.analysis")
    assert route.run_analysis_pipeline is pipeline.run_analysis_pipeline
    assert route._pipeline_cache is pipeline._pipeline_cache
    # route must not carry its own copy of the pipeline body
    assert route.full_pipeline.__code__.co_firstlineno != \
        pipeline.run_analysis_pipeline.__code__.co_firstlineno
    assert not hasattr(route, "analyze_functions")


def test_a_celery_uses_shared_pipeline():
    pytest.importorskip("celery")
    cw = pytest.importorskip("celery_worker")
    assert cw._run_pipeline is pipeline.run_analysis_pipeline


def test_a_mcp_uses_shared_pipeline():
    pytest.importorskip("mcp")
    ms = pytest.importorskip("mcp_server")
    assert ms._run_analysis_pipeline is pipeline.run_analysis_pipeline


def test_service_is_framework_neutral():
    import ast
    import inspect
    imported = set()
    for node in ast.walk(ast.parse(inspect.getsource(pipeline))):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert not imported & {"fastapi", "celery", "api", "core", "celery_worker",
                           "mcp_server", "analysis"}


# --- B: progress callback -------------------------------------------------

def test_b_progress_callback_reports_major_stages_and_keeps_result():
    plain = pipeline.run_analysis_pipeline("a.bin")
    pipeline._pipeline_cache.clear()
    seen = []
    with_cb = pipeline.run_analysis_pipeline(
        "a.bin", progress_cb=lambda s, p: seen.append((s, p)))
    assert [s for s, _ in seen] == STAGES
    assert [p for _, p in seen] == sorted(p for _, p in seen)
    assert with_cb == plain


# --- C: callback failure isolation ---------------------------------------

def test_c_callback_exception_does_not_fail_or_alter_analysis():
    plain = pipeline.run_analysis_pipeline("b.bin")
    pipeline._pipeline_cache.clear()

    def boom(stage, pct):
        raise RuntimeError("progress backend down")

    assert pipeline.run_analysis_pipeline("b.bin", progress_cb=boom) == plain


def test_c_real_pipeline_errors_still_propagate_with_callback():
    def broken(*a, **k):
        raise ValueError("engine bug")
    with patch.object(pipeline, "calculate_combined_risk", broken):
        with pytest.raises(ValueError):
            pipeline.run_analysis_pipeline("c.bin", progress_cb=lambda s, p: None)


def test_function_analysis_tracks_final_results_after_capa_merge():
    r = pipeline.run_analysis_pipeline("d.bin")
    assert r["function_analysis"] is r["analysis"]["results"]
    assert r["function_analysis"][0]["function_name"] == "merged_by_capa"


def test_cache_is_per_full_path_and_reused():
    calls = []
    orig = _stubs()["run_unified_extraction"]

    def counting(p):
        calls.append(p)
        return orig(p)
    with patch.object(pipeline, "run_unified_extraction", counting):
        r1 = pipeline.run_analysis_pipeline("/up/one/x.bin")
        assert pipeline.run_analysis_pipeline("/up/one/x.bin") == r1
        assert pipeline.run_analysis_pipeline("/up/one/x.bin") is not r1  # isolated copy
        pipeline.run_analysis_pipeline("/up/two/x.bin")  # same basename
    assert calls == ["/up/one/x.bin", "/up/two/x.bin"]


# --- D: Celery compatibility ---------------------------------------------

def test_d_celery_task_calls_pipeline_with_progress_cb(tmp_path):
    pytest.importorskip("celery")
    cw = pytest.importorskip("celery_worker")
    f = tmp_path / "sample.bin"
    f.write_bytes(b"MZ" + b"\x00" * 64)
    states = []
    with patch.object(cw.run_analysis_task, "update_state",
                      side_effect=lambda **k: states.append(k["meta"]["stage"])):
        out = cw.run_analysis_task.run(str(f), "sample.exe")
    assert states == STAGES                      # progress_cb accepted, no TypeError
    assert not f.exists()                        # worker still cleans up
    assert out["hashes"]["sha256"] != "N/A"      # worker still hashes
    assert out["file_type"].startswith("PE")
    assert out["analysis_meta"]["filename"] == "sample.exe"


# --- E: legacy wrapper ----------------------------------------------------

def test_e_legacy_wrapper_works_without_and_with_callback():
    r = analysis.run_analysis_pipeline("e.bin")
    assert r["risk_score"] == 42 and r["mitre"] == ["T1055"]
    seen = []
    analysis.run_analysis_pipeline("e2.bin", progress_cb=lambda s, p: seen.append(s))
    assert seen == STAGES


def test_e_legacy_wrapper_propagates_extraction_failure():
    with patch.object(pipeline, "run_unified_extraction",
                      lambda p: {"functions": [], "imports": [], "strings": [],
                                 "calls": [], "_meta": {"reason": "boom"}}), \
         patch.object(pipeline, "analyze_functions",
                      lambda p, strings=None, imports=None: {"results": []}):
        with pytest.raises(analysis.PipelineExtractionFailedError):
            analysis.run_analysis_pipeline("f.bin")
    assert analysis.PipelineExtractionFailedError is pipeline.PipelineExtractionFailedError


# --- F: result compatibility ---------------------------------------------

def test_f_authoritative_keys_preserved_and_legacy_fields_added():
    raw = pipeline.run_analysis_pipeline("g.bin")
    for k in AUTHORITATIVE_KEYS:
        assert k in raw, k
    before = copy.deepcopy(raw)
    legacy = pipeline.to_legacy_result(raw)
    assert raw == before                          # cached result not mutated
    for k in AUTHORITATIVE_KEYS:
        assert legacy[k] == raw[k]
    assert legacy["mitre"] == ["T1055"]
    assert legacy["risk_score"] == 42
    assert legacy["cvss"]["cvss_score"] == 7.5 and legacy["cvss_score"] == 7.5
    assert legacy["verdict"]["verdict"] == "MALICIOUS"
    assert legacy["functions"] and legacy["calls"] == ["VirtualAlloc"]
    assert legacy["behaviours"] == raw["behaviors"]["behaviors"]


def test_f_celery_normalised_result_contract():
    pytest.importorskip("celery")
    cw = pytest.importorskip("celery_worker")
    norm = cw._normalise_result(
        pipeline.to_legacy_result(pipeline.run_analysis_pipeline("h.bin")),
        1.0, "h.exe")
    for k in ("capabilities", "mitre", "risk_score", "cvss", "verdict"):
        assert k in norm
    assert norm["capabilities"] == ["cap_a"] and norm["mitre"] == ["T1055"]
    assert norm["risk_score"] == 42.0 and norm["cvss"] == 7.5
    assert norm["verdict"]["verdict"] == "MALICIOUS"


def test_concurrent_same_file_runs_pipeline_once(tmp_path):
    """Concurrent calls for the same file must share one analysis result."""
    import threading

    sample = tmp_path / "same.bin"
    sample.write_bytes(b"sample-binary-content")

    calls = []
    calls_lock = threading.Lock()
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()
    results = {}
    errors = []

    def fake_extraction(path):
        with calls_lock:
            calls.append(path)
            call_number = len(calls)

        if call_number == 1:
            first_entered.set()
            assert release_first.wait(timeout=5), "First extraction was not released"
        else:
            second_entered.set()

        return {
            "functions": [{"name": "sample_function"}],
            "imports": ["kernel32.dll"],
            "strings": ["sample"],
            "calls": [],
            "_meta": {"radare2_available": True, "ghidra_available": False},
        }

    def worker(key):
        try:
            results[key] = pipeline.run_analysis_pipeline(str(sample))
        except Exception as exc:
            errors.append(exc)

    with patch.object(pipeline, "run_unified_extraction", fake_extraction):
        first = threading.Thread(target=worker, args=("first",))
        second = threading.Thread(target=worker, args=("second",))

        first.start()
        assert first_entered.wait(timeout=5), "First analysis never started"

        second.start()

        # Without single-flight coordination, the second extraction enters here.
        # With coordination, the second call waits for the first result.
        duplicate_started = second_entered.wait(timeout=0.3)
        release_first.set()

        first.join(timeout=5)
        second.join(timeout=5)

    assert not first.is_alive() and not second.is_alive(), "Pipeline thread hung"
    assert not errors, f"Unexpected pipeline errors: {errors}"
    assert not duplicate_started, "Duplicate extraction started for the same file"
    assert len(calls) == 1
    assert results["first"] == results["second"]
    assert results["first"] is not results["second"]


def test_concurrent_different_files_can_run_in_parallel(tmp_path):
    """Per-file coordination must not serialize different file identities."""
    import threading

    first_path = tmp_path / "first.bin"
    second_path = tmp_path / "second.bin"
    first_path.write_bytes(b"first-binary")
    second_path.write_bytes(b"second-binary")

    both_entered = threading.Barrier(2, timeout=5)
    errors = []
    results = {}

    def fake_extraction(path):
        both_entered.wait()
        return {
            "functions": [{"name": "sample_function"}],
            "imports": ["kernel32.dll"],
            "strings": ["sample"],
            "calls": [],
            "_meta": {"radare2_available": True, "ghidra_available": False},
        }

    def worker(key, path):
        try:
            results[key] = pipeline.run_analysis_pipeline(str(path))
        except Exception as exc:
            errors.append(exc)

    with patch.object(pipeline, "run_unified_extraction", fake_extraction):
        first = threading.Thread(target=worker, args=("first", first_path))
        second = threading.Thread(target=worker, args=("second", second_path))

        first.start()
        second.start()
        first.join(timeout=7)
        second.join(timeout=7)

    assert not first.is_alive() and not second.is_alive(), "Pipeline thread hung"
    assert not errors, f"Unexpected pipeline errors: {errors}"
    assert "first" in results
    assert "second" in results


def test_pipeline_lock_released_after_failure_allows_retry(tmp_path):
    """A failed analysis must release its per-file lock for subsequent retry."""
    sample = tmp_path / "retry.bin"
    sample.write_bytes(b"retry-binary-content")

    calls = []

    def fail_once_then_succeed(path):
        calls.append(path)
        if len(calls) == 1:
            return {
                "functions": [],
                "imports": [],
                "strings": [],
                "calls": [],
                "_meta": {"reason": "intentional test failure"},
            }
        return {
            "functions": [{"name": "recovered_function"}],
            "imports": ["kernel32.dll"],
            "strings": ["recovered"],
            "calls": [],
            "_meta": {"radare2_available": True, "ghidra_available": False},
        }

    identity = pipeline._get_file_identity(str(sample))

    with patch.object(pipeline, "run_unified_extraction", fail_once_then_succeed), \
         patch.object(pipeline, "analyze_functions", return_value={"results": []}), \
         patch.object(pipeline, "extract_imports", return_value=[]), \
         patch.object(pipeline, "extract_strings", return_value=[]):

        with pytest.raises(pipeline.PipelineExtractionFailedError):
            pipeline.run_analysis_pipeline(str(sample))

        assert identity not in pipeline._pipeline_lock_registry

        result = pipeline.run_analysis_pipeline(str(sample))

    assert len(calls) == 2
    assert result["functions"] == [{"name": "recovered_function"}]
    assert identity not in pipeline._pipeline_lock_registry
