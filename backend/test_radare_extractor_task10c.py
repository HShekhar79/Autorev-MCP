"""
test_radare_extractor_task10c.py

Task 10C focused regression tests: RadareExtractor.get_calls_for_address()
must recognize call-like op types beyond exact "call" (ucall/rcall/icall),
and must restore the richer, but still safe, target-resolution chain
(jump -> disasm text -> refs) that function_analysis_engine.py used to do
inline before centralization — without ever building an r2 command from
anything but a validated numeric address.

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

spec = importlib.util.spec_from_file_location("radare_extractor_t10c", MODULE_PATH)
radare_extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(radare_extractor)

RadareExtractor = radare_extractor.RadareExtractor


def _make_extractor(cmdj_return, cmd_side_effect=None):
    extractor = RadareExtractor.__new__(RadareExtractor)
    extractor.binary_path = "fake_sample.bin"
    extractor.r2 = MagicMock()
    extractor.r2.cmdj.return_value = cmdj_return
    extractor.r2.cmd.side_effect = cmd_side_effect or (lambda cmd: "")
    return extractor


# ---------------------------------------------------------------------------
# 1-4. Each call-like op type resolves (via disasm-text fallback, no jump)
# ---------------------------------------------------------------------------
def test_call_type_resolves():
    extractor = _make_extractor({"ops": [{"type": "call", "disasm": "call sym.system"}]})
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["sym.system"]


def test_ucall_type_resolves():
    extractor = _make_extractor({"ops": [{"type": "ucall", "disasm": "ucall sym.imp.CreateFileW"}]})
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["sym.imp.CreateFileW"]


def test_rcall_type_resolves():
    extractor = _make_extractor({"ops": [{"type": "rcall", "disasm": "rcall rax"}]})
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["rax"]


def test_icall_type_resolves():
    extractor = _make_extractor({"ops": [{"type": "icall", "disasm": "icall [rbp - 0x8]"}]})
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["0x8]"]  # last whitespace-split token, matches prior text-fallback semantics


def test_non_call_type_is_ignored():
    extractor = _make_extractor({"ops": [{"type": "mov", "disasm": "mov eax, ebx"}]})
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == []


# ---------------------------------------------------------------------------
# 5. jump resolution uses only numeric addresses, and wins over disasm text
# ---------------------------------------------------------------------------
def test_numeric_jump_resolved_and_preferred_over_disasm_text():
    def cmd_side_effect(cmd):
        assert cmd == "fd @ 4112"  # 0x1010
        return "sym.imp.WriteFile"

    extractor = _make_extractor(
        {"ops": [{"type": "call", "disasm": "call rax", "jump": 0x1010}]},
        cmd_side_effect=cmd_side_effect,
    )
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["sym.imp.WriteFile"]
    extractor.r2.cmd.assert_called_once_with("fd @ 4112")


def test_non_numeric_jump_is_never_used_falls_back_to_disasm_text():
    extractor = _make_extractor(
        {"ops": [{"type": "call", "disasm": "call sym.system", "jump": "sym.evil;!bash"}]}
    )
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["sym.system"]
    extractor.r2.cmd.assert_not_called()  # non-numeric jump never reaches fd@


def test_jump_resolution_falls_back_to_disasm_text_when_fd_returns_nothing_useful():
    def cmd_side_effect(cmd):
        assert cmd == "fd @ 4112"
        return "4112"  # fd found nothing better than echoing the address back

    extractor = _make_extractor(
        {"ops": [{"type": "call", "disasm": "call sym.system", "jump": 0x1010}]},
        cmd_side_effect=cmd_side_effect,
    )
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["sym.system"]  # falls back to disasm text


# ---------------------------------------------------------------------------
# 6. refs resolution uses only numeric addresses, only when nothing else
#    resolved (no jump, no disasm-text candidate)
# ---------------------------------------------------------------------------
def test_numeric_ref_addr_resolved_when_no_jump_or_disasm_text():
    def cmd_side_effect(cmd):
        assert cmd == "fd @ 8192"  # 0x2000
        return "sym.imp.RegSetValueEx"

    extractor = _make_extractor(
        {"ops": [{"type": "call", "disasm": "call", "refs": [{"addr": 0x2000}]}]},
        cmd_side_effect=cmd_side_effect,
    )
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["sym.imp.RegSetValueEx"]
    extractor.r2.cmd.assert_called_once_with("fd @ 8192")


def test_non_numeric_ref_addr_is_skipped_safely():
    extractor = _make_extractor(
        {"ops": [{"type": "call", "disasm": "call", "refs": [{"addr": "sym.evil;!bash"}]}]}
    )
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == []  # no usable text candidate ("call" alone is 1 token), ref unusable
    extractor.r2.cmd.assert_not_called()


def test_refs_with_malformed_entries_are_skipped_safely():
    extractor = _make_extractor(
        {"ops": [{"type": "call", "disasm": "call", "refs": ["not_a_dict", {"no_addr_key": 1}, None]}]}
    )
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == []
    extractor.r2.cmd.assert_not_called()


# ---------------------------------------------------------------------------
# 7. disasm text fallback still works end-to-end (no jump, no refs at all)
# ---------------------------------------------------------------------------
def test_disasm_text_fallback_used_when_no_jump_or_refs_present():
    extractor = _make_extractor({"ops": [{"type": "call", "disasm": "call sym.imp.CreateFileW"}]})
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == ["sym.imp.CreateFileW"]
    extractor.r2.cmd.assert_not_called()  # no fd@ needed at all


# ---------------------------------------------------------------------------
# 8. malicious function name cannot become an r2 command (pdfj path)
# ---------------------------------------------------------------------------
def test_malicious_name_never_reaches_pdfj_command():
    # get_calls_for_address only ever takes a numeric_offset — a caller
    # could not pass a name even if it wanted to; this asserts the pdfj
    # command built from a validated offset never contains a name.
    extractor = _make_extractor({"ops": [{"type": "call", "disasm": "call sym.system"}]})
    extractor.get_calls_for_address(0x1000)
    extractor.r2.cmdj.assert_called_once_with("pdfj @ 4096")


# ---------------------------------------------------------------------------
# 9. malicious/non-numeric jump AND ref values cannot become r2 commands
#    (combined worst case: both present, both malicious/non-numeric)
# ---------------------------------------------------------------------------
def test_malicious_jump_and_ref_values_never_reach_fd_command():
    extractor = _make_extractor(
        {
            "ops": [
                {
                    "type": "icall",
                    "disasm": "icall",  # single token -> no text candidate either
                    "jump": "sym.evil`whoami`",
                    "refs": [{"addr": "sym.evil;!bash"}, {"addr": None}],
                }
            ]
        }
    )
    calls = extractor.get_calls_for_address(0x1000)
    assert calls == []
    extractor.r2.cmd.assert_not_called()


# ---------------------------------------------------------------------------
# 10. existing per-call hard-timeout behavior remains intact for the
#     primary pdfj call (jump/refs resolution does not bypass it)
# ---------------------------------------------------------------------------
def test_pdfj_hard_timeout_still_propagates_before_any_resolution_attempted():
    extractor = RadareExtractor.__new__(RadareExtractor)
    extractor.binary_path = "fake_sample.bin"
    extractor.r2 = MagicMock()

    def fake_hard_timeout(fn, timeout_seconds, late_result_cleanup=None):
        raise TimeoutError("simulated hard timeout on pdfj")

    extractor._run_with_hard_timeout = fake_hard_timeout

    try:
        extractor.get_calls_for_address(0x1000)
        assert False, "expected TimeoutError to propagate"
    except TimeoutError:
        pass

    extractor.r2.cmd.assert_not_called()  # never reached op resolution at all


if __name__ == "__main__":
    import traceback

    _tests = [
        (n, f) for n, f in globals().items()
        if n.startswith("test_") and callable(f)
    ]
    _passed, _failed = 0, 0
    for _name, _fn in _tests:
        try:
            _fn()
            print(f"PASS: {_name}")
            _passed += 1
        except Exception:
            print(f"FAIL: {_name}")
            traceback.print_exc()
            _failed += 1
    print(f"\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)
