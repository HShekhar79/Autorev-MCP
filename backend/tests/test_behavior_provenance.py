"""
backend/tests/test_behavior_provenance.py

Targeted tests for Fix 7: Behavior aggregation provenance and mutation isolation.
Verifies:
1. In-place mutation of input dicts inside function_results is prevented.
2. Function provenance (function_name) is preserved in aggregated _detail.
3. Multiple functions sharing behavior names merge sources cleanly without cross-mutating
   the original function dicts.
4. Behavior labels and canonical naming are preserved unchanged.
"""

import copy
import pytest

from services.analysis_pipeline import collect_all_behaviours


def test_collect_all_behaviours_does_not_mutate_input_dicts():
    """Verify that calling collect_all_behaviours leaves input dicts completely unmutated."""
    orig_b1 = {"name": "process_injection", "mitre": "T1055"}
    orig_b2 = {"name": "network_activity", "mitre": "T1071"}

    func_1 = {
        "function_name": "fcn.00401000",
        "behaviours": [orig_b1],
    }
    func_2 = {
        "function_name": "fcn.00402000",
        "behaviours": [orig_b2],
    }

    func_results = {
        "results": [func_1, func_2],
        "global_behaviours": [],
    }

    snapshot = copy.deepcopy(func_results)

    result = collect_all_behaviours(
        function_results=func_results,
        imports=["connect", "socket"],
        capa_results={"status": "skipped", "capabilities": []},
    )

    # 1. Input dictionaries must remain identical to their snapshot
    assert func_results == snapshot
    assert func_1["behaviours"][0] is orig_b1
    assert "source" not in orig_b1  # orig_b1 was not mutated in-place!

    # 2. Aggregated output contains behaviors
    assert "process_injection" in result["behaviors"]
    assert "network_communication" in result["behaviors"]

    # 3. Aggregated detail preserves function provenance
    detail_by_name = {d["name"]: d for d in result["_detail"]}
    assert detail_by_name["process_injection"].get("function") == "fcn.00401000"
    assert detail_by_name["process_injection"].get("functions") == ["fcn.00401000"]
    assert "function" in detail_by_name["process_injection"]["source"]

    # 4. Modifying detail post-collection does not affect the input dicts
    detail_by_name["process_injection"]["name"] = "MODIFIED"
    assert orig_b1["name"] == "process_injection"


def test_behavior_provenance_multi_source_merging():
    """Verify that merging behaviors across functions, imports, and CAPA preserves provenance."""
    func_results = {
        "results": [
            {
                "function_name": "fcn.inject",
                "behaviours": [{"name": "process_injection", "confidence": 0.8}],
            }
        ],
        "global_behaviours": [],
    }

    capa_results = {
        "status": "success",
        "capabilities": [{"name": "process_injection", "confidence": 0.9}],
    }

    result = collect_all_behaviours(
        function_results=func_results,
        imports=[],
        capa_results=capa_results,
    )

    detail = {d["name"]: d for d in result["_detail"]}
    inj = detail["process_injection"]

    # Higher confidence from CAPA should be kept, and sources merged
    assert "capa" in inj["source"]
    assert "function" in inj["source"]
    assert inj.get("function") == "fcn.inject"
    assert inj.get("functions") == ["fcn.inject"]
    assert inj["confidence"] == 0.9


def test_behavior_provenance_multiple_functions_same_behavior():
    """Verify that multiple functions contributing the same behavior preserve plural provenance and evidence."""
    b_alpha = {"name": "process_injection", "confidence": 0.8, "evidence": {"call": "VirtualAllocEx"}}
    b_beta = {"name": "process_injection", "confidence": 0.85, "evidence": {"call": "WriteProcessMemory"}}

    func_alpha = {
        "function_name": "fcn.alpha",
        "behaviours": [b_alpha],
    }
    func_beta = {
        "function_name": "fcn.beta",
        "behaviours": [b_beta],
    }

    func_results = {
        "results": [func_alpha, func_beta],
        "global_behaviours": [],
    }

    snapshot = copy.deepcopy(func_results)

    result = collect_all_behaviours(
        function_results=func_results,
        imports=[],
        capa_results={"status": "skipped", "capabilities": []},
    )

    # 1. Source dictionaries and nested evidence must NOT be mutated
    assert func_results == snapshot
    assert func_alpha["behaviours"][0]["evidence"]["call"] == "VirtualAllocEx"
    assert func_beta["behaviours"][0]["evidence"]["call"] == "WriteProcessMemory"

    # 2. Aggregated detail preserves singular function AND plural functions
    detail = {d["name"]: d for d in result["_detail"]}
    inj = detail["process_injection"]
    assert inj.get("function") in ("fcn.alpha", "fcn.beta")
    assert inj.get("functions") == ["fcn.alpha", "fcn.beta"]
    assert "function" in inj["source"]
    # Higher confidence 0.85 from beta kept
    assert inj["confidence"] == 0.85
