"""
Task 11 security regression test.

Covers ONLY the confirmed fix in RadareExtractor.get_calls_from_all_functions():
attacker-controlled function/symbol names (from the untrusted sample's `aflj`
output) must never be interpolated into an r2 command string. The numeric
function offset must be used instead.

Mocks the r2 session — no real radare2 binary or malicious executable is
invoked.
"""

import sys
import time
import types
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

try:
    import pytest
except ImportError:  # pragma: no cover - test runner fallback only
    pytest = None

# ---------------------------------------------------------------------------
# Import target module without requiring the full backend package layout.
# ---------------------------------------------------------------------------
MODULE_PATH = (
    Path(__file__).resolve().parent
    / "engines" / "extractor_engine" / "radare_extractor.py"
)

# Stub out backend-only dependencies used at import time.
_utils_pkg = types.ModuleType("utils")
_debug_mod = types.ModuleType("utils.debug")
_debug_mod.debug_log = lambda *a, **k: None
_utils_pkg.debug = _debug_mod
sys.modules.setdefault("utils", _utils_pkg)
sys.modules.setdefault("utils.debug", _debug_mod)

# r2pipe is imported at module load time; stub it so import succeeds.
sys.modules.setdefault("r2pipe", types.ModuleType("r2pipe"))

spec = importlib.util.spec_from_file_location("radare_extractor", MODULE_PATH)
radare_extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(radare_extractor)

RadareExtractor = radare_extractor.RadareExtractor


def _make_extractor(functions, cmdj_side_effect=None):
    """
    Build a RadareExtractor with a mocked r2 session, bypassing open()/
    file-existence checks (binary_path need not exist for these tests).
    """
    extractor = RadareExtractor.__new__(RadareExtractor)
    extractor.binary_path = "fake_sample.bin"
    extractor.r2 = MagicMock()

    # get_functions() -> get_calls_from_all_functions() calls this, which
    # in turn calls self.r2.cmdj("aflj") through the hard-timeout wrapper.
    # We short-circuit get_functions() directly to isolate the call-site
    # under test.
    extractor.get_functions = MagicMock(return_value=functions)

    if cmdj_side_effect is not None:
        extractor.r2.cmdj.side_effect = cmdj_side_effect
    else:
        extractor.r2.cmdj.return_value = {"ops": []}

    return extractor


# ---------------------------------------------------------------------------
# 1. SECURITY TEST — malicious symbol name must never reach the command string
# ---------------------------------------------------------------------------
def test_malicious_function_name_never_interpolated_into_command():
    malicious_names = [
        "sym.evil;!bash",
        "sym.evil@0x41414141",
        "sym.evil`whoami`",
        "sym.evil!pwn",
    ]
    functions = [
        {"name": name, "offset": 0x1000 + i}
        for i, name in enumerate(malicious_names)
    ]
    extractor = _make_extractor(functions)

    extractor.get_calls_from_all_functions(max_functions=10)

    for call_args in extractor.r2.cmdj.call_args_list:
        (cmd_str,), _ = call_args
        assert cmd_str.startswith("pdfj @ ")
        arg = cmd_str[len("pdfj @ "):]
        # The interpolated argument must be a plain decimal integer only —
        # none of the malicious name's metacharacters may appear anywhere
        # in the command string passed to cmdj().
        assert arg.lstrip("-").isdigit(), (
            f"Non-numeric/unsafe token reached r2 command: {cmd_str!r}"
        )
        for bad_char in (";", "@", "`", "!"):
            # Only the single expected "@" separator between "pdfj" and the
            # numeric offset should ever appear.
            assert cmd_str.count("@") == 1
            if bad_char != "@":
                assert bad_char not in cmd_str


# ---------------------------------------------------------------------------
# 2. NORMAL FUNCTION TEST — legitimate extraction still works
# ---------------------------------------------------------------------------
def test_normal_function_call_extraction_returns_expected_calls():
    functions = [{"name": "main", "offset": 0x4010}]

    def cmdj_side_effect(cmd):
        assert cmd == "pdfj @ 16400"  # 0x4010 == 16400
        return {
            "ops": [
                {"type": "call", "disasm": "call sym.imp.CreateFileW"},
                {"type": "call", "disasm": "call sym.imp.WriteFile"},
                {"type": "mov", "disasm": "mov eax, ebx"},
            ]
        }

    extractor = _make_extractor(functions, cmdj_side_effect=cmdj_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == sorted(["CreateFileW", "WriteFile"])


# ---------------------------------------------------------------------------
# 3. OFFSET TEST — numeric offset (not name) is used to locate the function
# ---------------------------------------------------------------------------
def test_numeric_offset_used_instead_of_name():
    functions = [{"name": "suspicious_name_here", "offset": 0x2000}]
    extractor = _make_extractor(functions)

    extractor.get_calls_from_all_functions(max_functions=10)

    extractor.r2.cmdj.assert_called_once_with("pdfj @ 8192")  # 0x2000 == 8192


def test_function_with_invalid_offset_is_skipped_safely():
    functions = [{"name": "weird", "offset": "not_a_number"}]
    extractor = _make_extractor(functions)

    calls = extractor.get_calls_from_all_functions(max_functions=10)

    extractor.r2.cmdj.assert_not_called()
    assert calls == []


# ---------------------------------------------------------------------------
# 4. EXISTING LIMIT TEST — max_functions=200 behavior unchanged
# ---------------------------------------------------------------------------
def test_max_functions_limit_still_enforced():
    functions = [
        {"name": f"func_{i}", "offset": 0x1000 + i} for i in range(300)
    ]
    extractor = _make_extractor(functions)

    extractor.get_calls_from_all_functions()  # default max_functions=200

    assert extractor.r2.cmdj.call_count == 200


# ---------------------------------------------------------------------------
# 5. TIMEOUT TEST — per-call hard timeout path remains intact
# ---------------------------------------------------------------------------
def test_per_call_hard_timeout_path_preserved(monkeypatch):
    functions = [
        {"name": "hangs", "offset": 0x3000},
        {"name": "after_timeout", "offset": 0x3100},
    ]
    extractor = _make_extractor(functions)

    call_log = []

    def fake_hard_timeout(fn, timeout_seconds, late_result_cleanup=None):
        call_log.append(timeout_seconds)
        if len(call_log) == 1:
            # Simulate the first call hitting the hard timeout, which the
            # real implementation surfaces as a TimeoutError and (per
            # existing behavior) invalidates self.r2.
            extractor.r2 = None
            raise TimeoutError("simulated hard timeout")
        return fn()

    extractor._run_with_hard_timeout = fake_hard_timeout

    calls = extractor.get_calls_from_all_functions(max_functions=10)

    # Per-call timeout constant still passed through unchanged.
    assert all(t == radare_extractor.R2_PER_CALL_HARD_TIMEOUT for t in call_log)
    # Session invalidated after timeout -> loop stops early, no crash.
    assert call_log == [radare_extractor.R2_PER_CALL_HARD_TIMEOUT]
    assert calls == []


if __name__ == "__main__":
    if pytest is not None:
        sys.exit(pytest.main([__file__, "-v"]))
    else:
        # Minimal fallback runner when pytest is unavailable in this
        # environment (no network access to install it). Executes every
        # top-level test_* function directly.
        _g = globals()
        _tests = [
            (n, f) for n, f in _g.items()
            if n.startswith("test_") and callable(f)
        ]
        _passed, _failed = 0, 0
        for _name, _fn in _tests:
            try:
                if "monkeypatch" in _fn.__code__.co_varnames[: _fn.__code__.co_argcount]:
                    _fn(None)
                else:
                    _fn()
                print(f"PASS: {_name}")
                _passed += 1
            except Exception as _e:
                print(f"FAIL: {_name} -> {_e}")
                _failed += 1
        print(f"\n{_passed} passed, {_failed} failed")
        sys.exit(0 if _failed == 0 else 1)
