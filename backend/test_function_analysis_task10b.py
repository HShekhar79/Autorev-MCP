"""
test_function_analysis_task10b.py

Task 10B focused regression tests: analyze_functions() must use the
centralized RadareExtractor.get_calls_for_address() (pdfj -> pdf fallback,
"offset"/"addr" compatible, numeric-address-only, hard-timeout-guarded)
instead of its own duplicated, offset-only, fallback-less pdfj path.

Covers:
  A. analyze_functions uses real aflj "addr" when "offset" is absent.
  B. pdfj empty -> pdf text fallback works through the centralized logic.
  C. malicious function name never reaches r2 command construction.
  D. per-function timeout still stops safely and preserves partial results.
  E. existing offset-based fixtures still work (see also the untouched
     test_function_analysis_timeout.py, run alongside this file).
  F. function-level calls are correctly attributed, not globally duplicated
     across every function.
  G. existing normalization/capability/risk behavior is unchanged (calls
     recovered via the fallback still drive behaviour/capability/MITRE/
     risk exactly like calls recovered via the primary pdfj path).

Mocks the r2 session — no real radare2 binary is invoked.
"""

import tempfile
from unittest.mock import patch, MagicMock

from engines.function_analysis_engine.function_analysis_engine import (
    analyze_functions,
)


def make_temp_file():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"TASK10B_FUNCTION_ANALYSIS_INTEGRATION_TEST")
        return f.name


def _install(cmdj_side_effect, cmd_side_effect=None):
    fake_r2 = MagicMock()
    fake_r2.cmd.side_effect = cmd_side_effect or (lambda cmd: "")
    fake_r2.cmdj.side_effect = cmdj_side_effect
    return fake_r2


# ---------------------------------------------------------------------------
# A. real aflj "addr" field (no "offset") is used, not skipped
# ---------------------------------------------------------------------------
def test_analyze_functions_uses_addr_field_when_offset_absent():
    path = make_temp_file()

    # Real radare2 aflj schema: "addr", not "offset". size>=8 so the
    # existing size filter doesn't skip it.
    def cmdj_side_effect(cmd):
        if cmd.startswith("aflj"):
            return [{"name": "sym.command_exec", "addr": 5368715024, "size": 64}]
        if cmd.startswith("izj"):
            return []
        if cmd.startswith("pdfj"):
            assert cmd == "pdfj @ 5368715024"
            return {}  # matches the real reported bug
        return {}

    def cmd_side_effect(cmd):
        if cmd.startswith("pdf @"):
            assert cmd == "pdf @ 5368715024"
            return "| 0x140001722 e8d91c0000 call sym.system\n"
        return ""

    fake_r2 = _install(cmdj_side_effect, cmd_side_effect)

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        return_value=fake_r2,
    ):
        result = analyze_functions(path, strings=[], imports=[])

    assert "error" not in result
    assert len(result["results"]) == 1
    fn = result["results"][0]
    assert fn["function_name"] == "sym.command_exec"
    # B. pdfj -> pdf fallback recovered the call, normalized ("sym." stripped)
    assert fn["calls"] == ["system"]
    # G. recovered call still drives behaviour/capability/risk as usual
    assert fn["risk_score"] > 0
    assert any(b["name"] != "no_external_activity" for b in fn["behaviours"])


# ---------------------------------------------------------------------------
# E. existing "offset"-keyed fixture still works (no fallback needed)
# ---------------------------------------------------------------------------
def test_analyze_functions_offset_field_still_works_without_fallback():
    path = make_temp_file()

    def cmdj_side_effect(cmd):
        if cmd.startswith("aflj"):
            return [{"name": "sym.main", "offset": 0x1000, "size": 32}]
        if cmd.startswith("izj"):
            return []
        if cmd.startswith("pdfj"):
            assert cmd == "pdfj @ 4096"
            return {"ops": [{"type": "call", "disasm": "call sym.imp.WriteFile"}]}
        return {}

    fake_r2 = _install(cmdj_side_effect)

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        return_value=fake_r2,
    ):
        result = analyze_functions(path, strings=[], imports=[])

    assert "error" not in result
    assert result["results"][0]["calls"] == ["WriteFile"]
    # primary pdfj sufficed: no `pdf @ ...` fallback command was issued
    # (only open()'s own "e anal.timeout=..."/"aaa" calls happened)
    pdf_fallback_calls = [
        c for c in fake_r2.cmd.call_args_list if c.args[0].startswith("pdf @")
    ]
    assert pdf_fallback_calls == []


# ---------------------------------------------------------------------------
# C. malicious function name never reaches either r2 command
# ---------------------------------------------------------------------------
def test_malicious_function_name_never_reaches_r2_commands():
    path = make_temp_file()
    malicious_name = "sym.evil;!bash`whoami`"

    seen_cmds = []

    def cmdj_side_effect(cmd):
        seen_cmds.append(cmd)
        if cmd.startswith("aflj"):
            return [{"name": malicious_name, "addr": 0x5000, "size": 16}]
        if cmd.startswith("izj"):
            return []
        if cmd.startswith("pdfj"):
            return {}  # force fallback
        return {}

    def cmd_side_effect(cmd):
        seen_cmds.append(cmd)
        return "| 0x00005010 e8000000 call sym.system\n"

    fake_r2 = _install(cmdj_side_effect, cmd_side_effect)

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        return_value=fake_r2,
    ):
        result = analyze_functions(path, strings=[], imports=[])

    assert "error" not in result
    for cmd in seen_cmds:
        if cmd in ("aflj", "izj"):
            continue
        for bad in (";", "!", "`"):
            assert bad not in cmd, f"unsafe char in r2 command: {cmd!r}"
    pdf_fallback_calls = [
        c.args[0] for c in fake_r2.cmd.call_args_list if c.args[0].startswith("pdf @")
    ]
    assert pdf_fallback_calls == ["pdf @ 20480"]


# ---------------------------------------------------------------------------
# D. per-function timeout stops safely, preserves partial results
# ---------------------------------------------------------------------------
def test_per_function_timeout_stops_loop_and_preserves_partial_results():
    path = make_temp_file()

    def cmdj_side_effect(cmd):
        if cmd.startswith("aflj"):
            return [
                {"name": "sym.first", "addr": 0x1000, "size": 32},
                {"name": "sym.second", "addr": 0x2000, "size": 32},
            ]
        if cmd.startswith("izj"):
            return []
        if cmd.startswith("pdfj @ 4096"):
            return {"ops": [{"type": "call", "disasm": "call sym.system"}]}
        if cmd.startswith("pdfj @ 8192"):
            raise TimeoutError("simulated hard timeout")
        return {}

    fake_r2 = _install(cmdj_side_effect)

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        return_value=fake_r2,
    ), patch(
        "engines.extractor_engine.radare_extractor.RadareExtractor._kill_r2_process",
        lambda self: None,
    ):
        result = analyze_functions(path, strings=[], imports=[])

    assert isinstance(result, dict)
    # First function's result is preserved even though the second timed out.
    assert len(result["results"]) == 1
    assert result["results"][0]["function_name"] == "sym.first"
    assert result["results"][0]["calls"] == ["system"]


# ---------------------------------------------------------------------------
# F. THE CORE BUG — function-level attribution, not global duplication.
#    Each function's "calls" must reflect only ITS OWN recovered calls, not
#    the full set recovered across every function in the binary.
# ---------------------------------------------------------------------------
def test_calls_are_attributed_per_function_not_globally_duplicated():
    path = make_temp_file()

    def cmdj_side_effect(cmd):
        if cmd.startswith("aflj"):
            return [
                {"name": "sym.alpha", "addr": 0x1000, "size": 32},
                {"name": "sym.beta", "addr": 0x2000, "size": 32},
                {"name": "sym.gamma", "addr": 0x3000, "size": 32},
            ]
        if cmd.startswith("izj"):
            return []
        if cmd == "pdfj @ 4096":
            return {"ops": [{"type": "call", "disasm": "call sym.imp.CreateFileW"}]}
        if cmd == "pdfj @ 8192":
            return {}  # falls back to pdf for this one only
        if cmd == "pdfj @ 12288":
            return {"ops": [{"type": "call", "disasm": "call sym.imp.RegSetValueEx"}]}
        return {}

    def cmd_side_effect(cmd):
        if cmd == "pdf @ 8192":
            return "| 0x2010 e8000000 call sym.system\n"
        return ""

    fake_r2 = _install(cmdj_side_effect, cmd_side_effect)

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        return_value=fake_r2,
    ):
        result = analyze_functions(path, strings=[], imports=[])

    assert "error" not in result
    by_name = {r["function_name"]: r for r in result["results"]}
    assert len(result["results"]) == 3

    # Each function has ONLY its own call(s) — never the union of all three.
    assert by_name["sym.alpha"]["calls"] == ["CreateFileW"]
    assert by_name["sym.beta"]["calls"] == ["system"]       # recovered via fallback
    assert by_name["sym.gamma"]["calls"] == ["RegSetValueEx"]

    # sym.beta's call came through the pdfj->pdf fallback specifically.
    pdf_fallback_calls = [
        c.args[0] for c in fake_r2.cmd.call_args_list if c.args[0].startswith("pdf @")
    ]
    assert pdf_fallback_calls == ["pdf @ 8192"]

    # Behaviour/capability detection reflects each function's own calls —
    # e.g. only sym.beta should show command_execution (from "system").
    assert any(
        b["name"] not in ("no_external_activity",)
        for b in by_name["sym.beta"]["behaviours"]
    )


if __name__ == "__main__":
    import sys
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
