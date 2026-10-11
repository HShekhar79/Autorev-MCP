"""Regression: ExitProcess import presence must not imply process_termination.

Run from backend/:  python -m pytest -q test_import_behaviour_exitprocess.py
Uses the real project modules (no stubs, mocks, or monkeypatching).
"""
from engines.behaviour_engine.import_behaviour_engine import (
    IMPORT_LOOKUP,
    analyze_imports_for_behaviour,
)


def _names(result):
    return [b["name"] for b in result]


def test_exitprocess_not_mapped_to_process_termination():
    assert IMPORT_LOOKUP.get("exitprocess") != "process_termination"


def test_terminateprocess_still_mapped_to_process_termination():
    assert IMPORT_LOOKUP["terminateprocess"] == "process_termination"


def test_terminateprocess_import_still_detected():
    result = analyze_imports_for_behaviour(["TerminateProcess"])
    assert "process_termination" in _names(result)


def test_exitprocess_import_does_not_yield_process_termination():
    result = analyze_imports_for_behaviour(["ExitProcess"])
    assert "process_termination" not in _names(result)