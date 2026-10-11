"""
test_unified_extractor_calls.py

Focused tests for Radare2 + Ghidra call merging in unified_extractor.
Engines are mocked; RadareExtractor's hardened call API is reused, not
reimplemented, so these tests only cover the unified layer.

Run with:
    python -m pytest -q test_unified_extractor_calls.py
"""
import contextlib
from unittest.mock import patch

import pytest

from engines.unified_extractor import unified_extractor as ue

FUNCS = [{"name": "main"}, {"name": "sub_1"}]
IMPORTS = ["kernel32.dll!VirtualAlloc"]
STRINGS = ["hello", "world"]


def _run(r2_calls=(), ghidra=None, r2_ok=True):
    """Run run_unified_extraction with everything mocked."""
    def funcs(p):
        if not r2_ok:
            raise RuntimeError("r2 down")
        return list(FUNCS)

    with contextlib.ExitStack() as st:
        st.enter_context(patch.object(ue, "r2_extract_functions", funcs))
        st.enter_context(patch.object(ue, "r2_extract_imports", lambda p: list(IMPORTS)))
        st.enter_context(patch.object(ue, "r2_extract_strings", lambda p: list(STRINGS)))
        calls_mock = st.enter_context(
            patch.object(ue, "_r2_extract_calls", return_value=list(r2_calls)))
        st.enter_context(patch.object(ue, "_GHIDRA_MODULE_AVAILABLE", ghidra is not None))
        st.enter_context(patch.object(ue, "run_ghidra_analysis", (lambda p: ghidra) if ghidra is not None else None))
        result = ue.run_unified_extraction("sample.exe")
    return result, calls_mock


def test_r2_only_calls_when_ghidra_unavailable():
    r, _ = _run(r2_calls=["CreateFileA", "VirtualAlloc"], ghidra=None)
    assert r["calls"] == ["CreateFileA", "VirtualAlloc"]
    assert r["_meta"]["ghidra_available"] is False


def test_r2_only_calls_when_ghidra_ran_but_empty():
    ghidra = {"functions": [], "strings": [], "calls": [], "_meta": {}}
    r, _ = _run(r2_calls=["CreateFileA"], ghidra=ghidra)
    assert r["calls"] == ["CreateFileA"]
    assert r["_meta"]["ghidra_available"] is True


def test_ghidra_only_calls_when_r2_calls_empty():
    ghidra = {"functions": [], "strings": [], "calls": ["WriteFile", "ReadFile"]}
    r, _ = _run(r2_calls=[], ghidra=ghidra)
    assert r["calls"] == ["WriteFile", "ReadFile"]


def test_duplicates_deduplicated_with_deterministic_order():
    ghidra = {"functions": [], "strings": [], "calls": ["VirtualAlloc", "WriteFile", "WriteFile", ""]}
    r, _ = _run(r2_calls=["CreateFileA", "VirtualAlloc"], ghidra=ghidra)
    # r2 first, then new ghidra entries; first occurrence wins
    assert r["calls"] == ["CreateFileA", "VirtualAlloc", "WriteFile"]
    again, _ = _run(r2_calls=["CreateFileA", "VirtualAlloc"], ghidra=ghidra)
    assert again["calls"] == r["calls"]


def test_functions_imports_strings_and_schema_preserved():
    r, _ = _run(r2_calls=["CreateFileA"], ghidra=None)
    assert set(r) == {"functions", "imports", "strings", "calls", "_meta"}
    assert r["functions"] == FUNCS
    assert r["imports"] == IMPORTS
    assert r["strings"] == STRINGS
    assert r["_meta"]["extraction_engine"] == "radare2"


def test_call_count_matches_merged_calls():
    ghidra = {"functions": [], "strings": [], "calls": ["VirtualAlloc", "WriteFile"]}
    r, _ = _run(r2_calls=["CreateFileA", "VirtualAlloc"], ghidra=ghidra)
    assert r["_meta"]["call_count"] == len(r["calls"]) == 3


def test_empty_r2_calls_degrade_gracefully():
    r, _ = _run(r2_calls=[], ghidra=None)
    assert r["calls"] == [] and r["_meta"]["call_count"] == 0
    assert r["functions"] == FUNCS


def test_r2_call_extraction_skipped_when_r2_itself_failed():
    r, calls_mock = _run(r2_calls=["X"], ghidra=None, r2_ok=False)
    calls_mock.assert_not_called()
    assert r["calls"] == []
    assert r["_meta"]["radare2_available"] is False


def test_legacy_single_arg_merge_calls_unchanged():
    assert ue._merge_calls(["a", "b", "a", ""]) == ["a", "b"]


# --- _r2_extract_calls delegates to the RadareExtractor API ----------------

class _FakeExtractor:
    log = []
    fail_at = None
    calls = ["VirtualAlloc"]

    def __init__(self, path):
        type(self).log.append(("init", path))

    def open(self):
        type(self).log.append("open")
        if type(self).fail_at == "open":
            raise TimeoutError("open timed out")

    def get_calls_from_all_functions(self):
        type(self).log.append("get_calls")
        if type(self).fail_at == "get_calls":
            raise RuntimeError("boom")
        return list(type(self).calls)

    def close(self):
        type(self).log.append("close")


@pytest.fixture
def fake_extractor():
    _FakeExtractor.log, _FakeExtractor.fail_at = [], None
    with patch.object(ue, "RadareExtractor", _FakeExtractor):
        yield _FakeExtractor


def test_helper_uses_existing_api_and_always_closes(fake_extractor):
    assert ue._r2_extract_calls("s.exe") == ["VirtualAlloc"]
    assert fake_extractor.log == [("init", "s.exe"), "open", "get_calls", "close"]


@pytest.mark.parametrize("stage", ["open", "get_calls"])
def test_helper_failure_returns_empty_and_closes(fake_extractor, stage):
    fake_extractor.fail_at = stage
    assert ue._r2_extract_calls("s.exe") == []
    assert fake_extractor.log[-1] == "close"


def test_helper_missing_binary_returns_empty():
    # real RadareExtractor raises FileNotFoundError in __init__ → degrade
    assert ue._r2_extract_calls("definitely_missing_file.bin") == []
