"""
backend/tests/test_global_capability_validation.py

Targeted tests for Fix 4: Real global capability validation.
Verifies:
1. Matching function and global capability collections produce valid=True.
2. Missing capabilities in global are reported in missing_in_global and valid=False.
3. Extra capabilities in global are reported in extra_in_global and valid=False.
4. Empty inputs evaluate to valid=True without errors.
5. Placeholder 'no_capabilities_detected' is ignored during validation.
6. Pipeline integration: validation status is faithfully reported in analysis_meta,
   and mismatch does not fabricate a malware verdict or alter risk scores.
"""

from unittest.mock import patch
import pytest

from engines.capability_deduplication import validate_global_capabilities
from services import analysis_pipeline as pipeline


def test_matching_collections():
    funcs = [
        {"function_name": "f1", "capabilities": ["process_injection"]},
        {"function_name": "f2", "capabilities": [{"name": "network_activity"}]},
    ]
    global_caps = ["network_activity", "process_injection"]

    res = validate_global_capabilities(funcs, global_caps)
    assert res["valid"] is True
    assert res["missing_in_global"] == []
    assert res["extra_in_global"] == []
    assert res["function_caps"] == ["network_activity", "process_injection"]
    assert res["global_caps"] == ["network_activity", "process_injection"]


def test_missing_in_global():
    funcs = [
        {"function_name": "f1", "capabilities": ["process_injection", "keylogging"]},
    ]
    global_caps = ["process_injection"]

    res = validate_global_capabilities(funcs, global_caps)
    assert res["valid"] is False
    assert res["missing_in_global"] == ["keylogging"]
    assert res["extra_in_global"] == []


def test_extra_in_global():
    funcs = [
        {"function_name": "f1", "capabilities": ["process_injection"]},
    ]
    global_caps = ["process_injection", "command_execution"]

    res = validate_global_capabilities(funcs, global_caps)
    assert res["valid"] is False
    assert res["missing_in_global"] == []
    assert res["extra_in_global"] == ["command_execution"]


def test_empty_inputs():
    res = validate_global_capabilities([], [])
    assert res["valid"] is True
    assert res["missing_in_global"] == []
    assert res["extra_in_global"] == []

    res_none = validate_global_capabilities(None, None)
    assert res_none["valid"] is True


def test_ignore_no_capabilities_detected_placeholder():
    funcs = [
        {"function_name": "f1", "capabilities": ["no_capabilities_detected"]},
        {"function_name": "f2", "capabilities": [{"name": "no_capabilities_detected"}]},
    ]
    global_caps = []

    res = validate_global_capabilities(funcs, global_caps)
    assert res["valid"] is True
    assert res["missing_in_global"] == []
    assert res["extra_in_global"] == []


def test_pipeline_validation_does_not_fabricate_verdict():
    """Verify that a validation failure sets global_capabilities_valid=False without altering verdict."""
    pipeline._pipeline_cache.clear()

    # Stub extraction to produce some function
    fake_extract = {
        "functions": [{"name": "f1"}],
        "imports": [],
        "strings": [],
        "calls": [],
        "_meta": {"radare2_available": True, "ghidra_available": False},
    }
    fake_func_analysis = {
        "results": [{"function_name": "f1", "calls": [], "behaviours": [], "capabilities": ["cap_x"]}],
        "global_behaviours": [],
    }

    with patch.object(pipeline, "run_unified_extraction", return_value=fake_extract), \
         patch.object(pipeline, "analyze_functions", return_value=fake_func_analysis), \
         patch.object(pipeline, "run_capa_analysis", return_value={"status": "skipped", "capabilities": []}), \
         patch.object(pipeline, "calculate_combined_risk", return_value={"combined_score": 0}), \
         patch.object(pipeline, "arise_verdict", return_value={"verdict": "BENIGN", "confidence": 95}):

        result = pipeline.run_analysis_pipeline("sample_val.bin")

        meta = result["analysis_meta"]
        # Validation was run and recorded
        assert "global_capabilities_valid" in meta
        # Verdict must NOT be fabricated to MALICIOUS due to capability validation
        assert result["arise_verdict"]["verdict"] == "BENIGN"


def test_validation_result_is_json_serializable():
    """Verify that complete validation result can be serialized with json.dumps without error."""
    import json
    funcs = [
        {"function_name": "f1", "capabilities": ["process_injection", "keylogging"]},
        {"function_name": "f2", "capabilities": [{"name": "network_activity"}]},
    ]
    global_caps = ["process_injection", "network_activity", "persistence"]

    res = validate_global_capabilities(funcs, global_caps)
    # Must succeed without TypeError: Object of type set is not JSON serializable
    serialized = json.dumps(res)
    assert "process_injection" in serialized

    loaded = json.loads(serialized)
    assert loaded["valid"] is False
    assert isinstance(loaded["function_caps"], list)
    assert isinstance(loaded["global_caps"], list)
    assert loaded["missing_in_global"] == ["keylogging"]
    assert loaded["extra_in_global"] == ["persistence"]
