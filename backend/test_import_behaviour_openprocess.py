"""Regression: OpenProcess import presence must not imply process_injection.

Run from backend/:  python -m pytest -q test_import_behaviour_openprocess.py
Uses the real project modules (no stubs, mocks, or monkeypatching).
"""
from engines.behaviour_engine.import_behaviour_engine import (
    IMPORT_LOOKUP,
    analyze_imports_for_behaviour,
)


def _names(result):
    return [b["name"] for b in result]


def test_openprocess_not_mapped_to_process_injection():
    assert IMPORT_LOOKUP.get("openprocess") != "process_injection"


def test_openprocess_import_does_not_yield_process_injection():
    result = analyze_imports_for_behaviour(["OpenProcess"])
    assert "process_injection" not in _names(result)


def test_virtualallocex_still_yields_memory_allocation():
    result = analyze_imports_for_behaviour(["VirtualAllocEx"])
    assert "memory_allocation" in _names(result)


def test_writeprocessmemory_still_yields_process_injection():
    result = analyze_imports_for_behaviour(["WriteProcessMemory"])
    assert "process_injection" in _names(result)


def test_createremotethread_still_yields_process_injection():
    result = analyze_imports_for_behaviour(["CreateRemoteThread"])
    assert "process_injection" in _names(result)