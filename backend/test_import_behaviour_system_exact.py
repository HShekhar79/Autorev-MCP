"""Regression: short command patterns ("system", "cmd") must match whole API names only.

Run from backend/:  python -m pytest -q test_import_behaviour_system_exact.py
Uses the real project modules (no stubs, mocks, or monkeypatching).
"""
from engines.behaviour_engine.import_behaviour_engine import (
    analyze_imports_for_behaviour,
)


def _names(api):
    return [b["name"] for b in analyze_imports_for_behaviour([api])]


def test_unrelated_system_substrings_not_command_execution():
    for api in ["SystemTime", "GetSystemTime", "SystemFunction032", "ZwSystemDebugControl"]:
        assert "command_execution" not in _names(api), api


def test_exact_short_names_still_command_execution():
    for api in ["system", "System", "cmd", "CMD"]:
        assert "command_execution" in _names(api), api


def test_existing_command_apis_still_work():
    for api in ["CreateProcess", "WinExec", "ShellExecute"]:
        assert "command_execution" in _names(api), api


def test_getsysteminfo_remains_system_discovery():
    assert "system_discovery" in _names("GetSystemInfo")
    assert "command_execution" not in _names("GetSystemInfo")