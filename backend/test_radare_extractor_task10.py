"""
test_radare_extractor_task10.py

Task 10 focused regression tests: RadareExtractor.get_calls_from_all_functions()
must fall back to text-mode `pdf @ <offset>` when `pdfj @ <offset>` returns no
usable structured evidence ({}, None, or an empty "ops" list), while:
  - never using the function's (untrusted) name in either command,
  - keeping a valid, non-empty pdfj result authoritative (no fallback),
  - routing the fallback through the same _run_with_hard_timeout /
    R2_PER_CALL_HARD_TIMEOUT / R2_CALLS_TOTAL_BUDGET_SECONDS protections,
  - only parsing genuine `call` instruction lines from pdf text output,
    never comments or strings that merely contain the word "call".

Mocks the r2 session — no real radare2 binary is invoked.
"""

import sys
import types
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

MODULE_PATH = (
    Path(__file__).resolve().parent
    / "engines" / "extractor_engine" / "radare_extractor.py"
)

_utils_pkg = types.ModuleType("utils")
_debug_mod = types.ModuleType("utils.debug")
_debug_mod.debug_log = lambda *a, **k: None
_utils_pkg.debug = _debug_mod
sys.modules.setdefault("utils", _utils_pkg)
sys.modules.setdefault("utils.debug", _debug_mod)
sys.modules.setdefault("r2pipe", types.ModuleType("r2pipe"))

spec = importlib.util.spec_from_file_location("radare_extractor_t10", MODULE_PATH)
radare_extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(radare_extractor)

RadareExtractor = radare_extractor.RadareExtractor


def _make_extractor(functions, cmdj_side_effect, cmd_side_effect=None):
    extractor = RadareExtractor.__new__(RadareExtractor)
    extractor.binary_path = "fake_sample.bin"
    extractor.r2 = MagicMock()
    extractor.get_functions = MagicMock(return_value=functions)
    extractor.r2.cmdj.side_effect = cmdj_side_effect
    extractor.r2.cmd.side_effect = cmd_side_effect or (lambda cmd: "")
    return extractor


# ---------------------------------------------------------------------------
# 1. pdfj returns {} -> falls back to pdf text parsing, using the SAME offset
# ---------------------------------------------------------------------------
def test_pdfj_empty_dict_falls_back_to_pdf_text():
    functions = [{"name": "sym.command_exec", "offset": 5368715024}]

    def cmdj_side_effect(cmd):
        assert cmd == "pdfj @ 5368715024"
        return {}

    def cmd_side_effect(cmd):
        assert cmd == "pdf @ 5368715024"
        return "| 0x140001722 e8d91c0000 call sym.system\n"

    extractor = _make_extractor(functions, cmdj_side_effect, cmd_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == ["system"]
    extractor.r2.cmdj.assert_called_once_with("pdfj @ 5368715024")
    extractor.r2.cmd.assert_called_once_with("pdf @ 5368715024")


# ---------------------------------------------------------------------------
# 1b. TASK 10A — real radare2 aflj schema uses "addr", not "offset". Same
#     end-to-end scenario as test 1 above, but using the real key, and using
#     the real sample's own name/address (sym.command_exec / 5368715024).
# ---------------------------------------------------------------------------
def test_aflj_addr_field_is_used_when_offset_field_is_absent():
    functions = [{"name": "sym.command_exec", "addr": 5368715024}]

    def cmdj_side_effect(cmd):
        assert cmd == "pdfj @ 5368715024"
        return {}

    def cmd_side_effect(cmd):
        assert cmd == "pdf @ 5368715024"
        return "| 0x140001722 e8d91c0000 call sym.system\n"

    extractor = _make_extractor(functions, cmdj_side_effect, cmd_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == ["system"]
    extractor.r2.cmdj.assert_called_once_with("pdfj @ 5368715024")
    extractor.r2.cmd.assert_called_once_with("pdf @ 5368715024")


def test_offset_field_takes_precedence_over_addr_when_both_present():
    # "offset" is the pre-existing/possibly-test-only key; when a function
    # dict happens to carry both, the established "offset" path must still
    # win, so nothing relying on "offset" today silently changes behavior.
    functions = [{"name": "sym.foo", "offset": 0x1000, "addr": 0x9999}]

    def cmdj_side_effect(cmd):
        assert cmd == "pdfj @ 4096"  # 0x1000, NOT 0x9999
        return {"ops": [{"type": "call", "disasm": "call sym.system"}]}

    extractor = _make_extractor(functions, cmdj_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == ["system"]
    extractor.r2.cmdj.assert_called_once_with("pdfj @ 4096")


def test_invalid_addr_is_skipped_safely_same_as_invalid_offset():
    functions = [{"name": "sym.weird", "addr": "not_a_number"}]

    extractor = _make_extractor(functions, cmdj_side_effect=lambda cmd: {})
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == []
    extractor.r2.cmdj.assert_not_called()
    extractor.r2.cmd.assert_not_called()


def test_missing_both_offset_and_addr_is_skipped_safely():
    functions = [{"name": "sym.no_address_at_all"}]

    extractor = _make_extractor(functions, cmdj_side_effect=lambda cmd: {})
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == []
    extractor.r2.cmdj.assert_not_called()


# ---------------------------------------------------------------------------
# 2. pdfj returns None -> same fallback
# ---------------------------------------------------------------------------
def test_pdfj_none_falls_back_to_pdf_text():
    functions = [{"name": "sym.foo", "offset": 0x1000}]
    calls_log = []

    def cmdj_side_effect(cmd):
        calls_log.append(cmd)
        return None

    def cmd_side_effect(cmd):
        assert cmd == "pdf @ 4096"
        return "| 0x00001010 e8000000 call sym.imp.CreateFileW\n"

    extractor = _make_extractor(functions, cmdj_side_effect, cmd_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == ["CreateFileW"]


# ---------------------------------------------------------------------------
# 3. pdfj returns {"ops": []} (empty structure) -> same fallback
# ---------------------------------------------------------------------------
def test_pdfj_empty_ops_list_falls_back_to_pdf_text():
    functions = [{"name": "sym.foo", "offset": 0x2000}]

    def cmdj_side_effect(cmd):
        return {"ops": []}

    def cmd_side_effect(cmd):
        return "| 0x00002010 e8000000 call sym.system\n"

    extractor = _make_extractor(functions, cmdj_side_effect, cmd_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == ["system"]


# ---------------------------------------------------------------------------
# 4. pdfj returns a VALID non-empty result -> fallback is never attempted,
#    even if that valid result happens to contain zero call-type ops.
# ---------------------------------------------------------------------------
def test_valid_pdfj_result_with_no_calls_does_not_trigger_fallback():
    functions = [{"name": "sym.leaf", "offset": 0x3000}]

    def cmdj_side_effect(cmd):
        return {"ops": [{"type": "mov", "disasm": "mov eax, ebx"}]}

    extractor = _make_extractor(functions, cmdj_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == []
    extractor.r2.cmd.assert_not_called()  # no `pdf` fallback attempted


def test_valid_pdfj_result_with_calls_is_used_as_is():
    functions = [{"name": "sym.main", "offset": 0x4010}]

    def cmdj_side_effect(cmd):
        assert cmd == "pdfj @ 16400"
        return {"ops": [{"type": "call", "disasm": "call sym.imp.WriteFile"}]}

    extractor = _make_extractor(functions, cmdj_side_effect)
    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == ["WriteFile"]
    extractor.r2.cmd.assert_not_called()


# ---------------------------------------------------------------------------
# 5. Fallback never uses the function's (untrusted) name — same numeric
#    offset in both pdfj and pdf commands, regardless of a malicious name.
# ---------------------------------------------------------------------------
def test_fallback_never_interpolates_function_name():
    malicious_name = "sym.evil;!bash`whoami`"
    functions = [{"name": malicious_name, "offset": 0x5000}]

    def cmdj_side_effect(cmd):
        assert cmd == "pdfj @ 20480"
        return {}

    def cmd_side_effect(cmd):
        assert cmd == "pdf @ 20480"
        for bad in (";", "!", "`"):
            assert bad not in cmd
        return "| 0x00005010 e8000000 call sym.system\n"

    extractor = _make_extractor(functions, cmdj_side_effect, cmd_side_effect)
    extractor.get_calls_from_all_functions(max_functions=10)
    extractor.r2.cmd.assert_called_once_with("pdf @ 20480")


def test_fallback_never_interpolates_function_name_via_addr_field():
    # Same guarantee as above, but for a function dict using the real
    # radare2 "addr" key instead of "offset".
    malicious_name = "sym.evil;!bash`whoami`"
    functions = [{"name": malicious_name, "addr": 0x5000}]

    def cmdj_side_effect(cmd):
        assert cmd == "pdfj @ 20480"
        return {}

    def cmd_side_effect(cmd):
        assert cmd == "pdf @ 20480"
        for bad in (";", "!", "`"):
            assert bad not in cmd
        return "| 0x00005010 e8000000 call sym.system\n"

    extractor = _make_extractor(functions, cmdj_side_effect, cmd_side_effect)
    extractor.get_calls_from_all_functions(max_functions=10)
    extractor.r2.cmd.assert_called_once_with("pdf @ 20480")


# ---------------------------------------------------------------------------
# 6. Comments / strings containing "call" must not be parsed as calls
# ---------------------------------------------------------------------------
def test_pdf_text_parser_ignores_comments_and_similar_words():
    text = (
        "; this function is called from sym.main\n"
        '0x00006000      686a6f00       push str.please_call_this_function\n'
        "0x00006005      e8000000       call sym.system  ; recall later\n"
        "0x0000600a      90             nop  ; callback registered\n"
    )
    targets = radare_extractor._parse_call_targets_from_pdf_text(text)
    assert targets == ["sym.system"]


def test_pdf_text_parser_handles_empty_input():
    assert radare_extractor._parse_call_targets_from_pdf_text("") == []
    assert radare_extractor._parse_call_targets_from_pdf_text(None) == []


# ---------------------------------------------------------------------------
# 7. Fallback pdf call is still bounded by the hard timeout / kills session
# ---------------------------------------------------------------------------
def test_fallback_pdf_call_hard_timeout_stops_loop(monkeypatch):
    functions = [
        {"name": "sym.first", "offset": 0x7000},
        {"name": "sym.second", "offset": 0x7100},
    ]

    def cmdj_side_effect(cmd):
        return {}  # always empty -> always falls back to pdf

    call_log = []

    def fake_hard_timeout(fn, timeout_seconds, late_result_cleanup=None):
        call_log.append(timeout_seconds)
        if len(call_log) == 1:
            extractor.r2 = None
            raise TimeoutError("simulated hard timeout on pdfj")
        return fn()

    extractor = _make_extractor(functions, cmdj_side_effect)
    extractor._run_with_hard_timeout = fake_hard_timeout

    calls = extractor.get_calls_from_all_functions(max_functions=10)

    # Only the FIRST function's pdfj attempt happened before the timeout;
    # the second function must never be attempted (session already dead).
    assert call_log == [radare_extractor.R2_PER_CALL_HARD_TIMEOUT]
    assert calls == []


# ---------------------------------------------------------------------------
# 8. Aggregate budget still stops the loop before any fallback is attempted
# ---------------------------------------------------------------------------
def test_aggregate_budget_exhausted_before_fallback_is_attempted(monkeypatch):
    functions = [{"name": "sym.foo", "offset": 0x8000}]

    def cmdj_side_effect(cmd):
        return {}  # would trigger fallback if budget allowed it

    extractor = _make_extractor(functions, cmdj_side_effect)

    monkeypatch.setattr(radare_extractor, "R2_CALLS_TOTAL_BUDGET_SECONDS", 0)
    monkeypatch.setattr(
        radare_extractor.time, "monotonic", lambda _l=[0.0, 1.0]: _l.pop(0)
    )

    calls = extractor.get_calls_from_all_functions(max_functions=10)

    assert calls == []
    extractor.r2.cmdj.assert_not_called()
    extractor.r2.cmd.assert_not_called()


if __name__ == "__main__":
    _g = globals()
    _tests = [(n, f) for n, f in _g.items() if n.startswith("test_") and callable(f)]
    _passed, _failed = 0, 0
    for _name, _fn in _tests:
        try:
            if "monkeypatch" in _fn.__code__.co_varnames[: _fn.__code__.co_argcount]:
                import pytest as _pytest_shim  # noqa
                class _MP:
                    def setattr(self, obj, name, value):
                        setattr(obj, name, value)
                _fn(_MP())
            else:
                _fn()
            print(f"PASS: {_name}")
            _passed += 1
        except Exception as _e:
            print(f"FAIL: {_name} -> {_e}")
            _failed += 1
    print(f"\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)
