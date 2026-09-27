"""
test_pipeline_failure_boundary.py

Task 9 focused regression tests for finding #2: analysis.py's narrow
FAILED-vs-COMPLETED boundary on total primary extraction failure.

These test run_analysis_pipeline()'s new PipelineExtractionFailedError
boundary in isolation, with run_unified_extraction and analyze_functions
monkeypatched (the same approach the existing test suite uses for
isolating a pipeline stage — see test_ghidra_unavailable.py /
test_r2_failure.py's mocking style). Downstream stages (behaviour,
capability, MITRE, scoring, CVSS, verdict) are exercised through their
real implementations for the COMPLETED cases; only extraction and
function-analysis are patched, since those are the two inputs finding #2
is about.

Run with:
    python -m pytest -q test_pipeline_failure_boundary.py
"""
from unittest.mock import patch

import pytest

import analysis
from analysis import run_analysis_pipeline, PipelineExtractionFailedError


def _empty_meta(reason):
    return {
        "functions": [], "imports": [], "strings": [], "calls": [],
        "_meta": {"extraction_engine": "none", "reason": reason,
                   "ghidra_available": False, "radare2_available": False},
    }


def _radare_ok(functions=None, imports=None, strings=None, calls=None,
               ghidra_available=False):
    return {
        "functions": functions or [], "imports": imports or [],
        "strings": strings or [], "calls": calls or [],
        "_meta": {
            "extraction_engine": "radare2+ghidra" if ghidra_available else "radare2",
            "reason": "", "ghidra_available": ghidra_available,
            "radare2_available": True,
        },
    }


def _empty_function_analysis():
    return {"results": [], "global_behaviours": [], "global_capabilities": []}


def _some_function_analysis():
    return {
        "results": [{"function_name": "f", "calls": [], "behaviours": [],
                     "capabilities": [], "mitre_techniques": [], "risk_score": 0}],
        "global_behaviours": [], "global_capabilities": [],
    }


# ---------------------------------------------------------------------------
# 4. total primary extraction failure → failed
# ---------------------------------------------------------------------------

def test_total_extraction_failure_raises():
    with patch.object(analysis, "run_unified_extraction",
                       return_value=_empty_meta("radare2_failed: simulated")), \
         patch.object(analysis, "analyze_functions",
                       return_value=_empty_function_analysis()):
        with pytest.raises(PipelineExtractionFailedError):
            run_analysis_pipeline("dummy.bin")


# ---------------------------------------------------------------------------
# 5. useful error_message is persisted
# ---------------------------------------------------------------------------

def test_total_extraction_failure_error_message_contains_reason():
    with patch.object(analysis, "run_unified_extraction",
                       return_value=_empty_meta("file_not_found")), \
         patch.object(analysis, "analyze_functions",
                       return_value=_empty_function_analysis()):
        try:
            run_analysis_pipeline("dummy.bin")
            pytest.fail("expected PipelineExtractionFailedError")
        except PipelineExtractionFailedError as exc:
            assert "file_not_found" in str(exc)
            assert "no usable evidence" in str(exc)


# ---------------------------------------------------------------------------
# 6. failed path never calls set_result()
#
# run_analysis_pipeline() itself has no direct dependency on job_manager
# (that wiring lives in the upload/worker route, which was not part of
# this batch of uploaded files). What we CAN verify at this layer is the
# stronger, sufficient guarantee: on total failure, control never reaches
# the `return {...}` statement at all, so no result dict is ever produced
# for a caller to persist via set_result() in the first place.
# ---------------------------------------------------------------------------

def test_total_extraction_failure_never_returns_a_result_dict():
    with patch.object(analysis, "run_unified_extraction",
                       return_value=_empty_meta("radare2_failed: x")), \
         patch.object(analysis, "analyze_functions",
                       return_value=_empty_function_analysis()):
        try:
            result = run_analysis_pipeline("dummy.bin")
            pytest.fail(f"expected an exception, got a result dict: {result!r}")
        except PipelineExtractionFailedError:
            pass  # no result dict was ever constructed


# ---------------------------------------------------------------------------
# 7. Radare2 success + Ghidra failure → completed
# ---------------------------------------------------------------------------

def test_radare_success_ghidra_failure_completes():
    with patch.object(analysis, "run_unified_extraction",
                       return_value=_radare_ok(functions=[{"name": "f"}],
                                                ghidra_available=False)), \
         patch.object(analysis, "analyze_functions",
                       return_value=_empty_function_analysis()):
        result = run_analysis_pipeline("dummy.bin")
    assert "verdict" in result
    assert result["analysis_meta"]["ghidra_available"] is False


# ---------------------------------------------------------------------------
# 8. CAPA failure remains completed (capa is supplementary, not primary
#    extraction — never touches functions/imports/strings/calls)
# ---------------------------------------------------------------------------

def test_capa_failure_remains_completed():
    with patch.object(analysis, "run_unified_extraction",
                       return_value=_radare_ok(functions=[{"name": "f"}],
                                                imports=["kernel32.dll"])), \
         patch.object(analysis, "analyze_functions",
                       return_value=_empty_function_analysis()), \
         patch.object(analysis, "run_capa_analysis",
                       return_value={"capabilities": [], "mitre_techniques": [],
                                      "status": "failed"}):
        result = run_analysis_pipeline("dummy.bin")
    assert result["analysis_meta"]["capa_enabled"] is False
    assert "verdict" in result


# ---------------------------------------------------------------------------
# 9. partial usable extraction → completed
# ---------------------------------------------------------------------------

def test_partial_extraction_completes():
    # Zero functions/imports/strings/calls from the extractor, but
    # function_analysis produced usable evidence — must NOT be FAILED.
    with patch.object(analysis, "run_unified_extraction",
                       return_value=_empty_meta("radare2_failed: partial")), \
         patch.object(analysis, "analyze_functions",
                       return_value=_some_function_analysis()):
        result = run_analysis_pipeline("dummy.bin")
    assert "verdict" in result
    assert len(result["function_analysis"]) == 1


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
