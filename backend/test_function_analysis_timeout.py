"""
test_function_analysis_timeout.py

Task 9 focused regression tests for finding #1: function_analysis_engine.py's
r2pipe session must be bounded by the same hard-timeout / process-kill
pattern as radare_extractor.py, and must never hang the job in "processing".

Run with:
    python -m pytest -q test_function_analysis_timeout.py
"""
import time
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from engines.function_analysis_engine.function_analysis_engine import (
    analyze_functions,
)
from engines.extractor_engine.radare_extractor import (
    R2_OPEN_HARD_TIMEOUT,
)


def make_temp_file():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"TASK9_FUNCTION_ANALYSIS_TIMEOUT_TEST")
        return f.name


# ---------------------------------------------------------------------------
# 1. function-analysis r2 timeout is bounded
# ---------------------------------------------------------------------------

def test_analyze_functions_returns_within_bounded_time_on_hanging_open():
    """
    A hanging r2pipe.open() must not hang analyze_functions() past
    RadareExtractor's own hard timeout. We patch r2pipe.open (as used by
    radare_extractor, the module analyze_functions now delegates to) with a
    function that blocks forever, and assert wall-clock time stays bounded.
    """
    path = make_temp_file()

    def _hang(*args, **kwargs):
        # Simulate a hostile binary hanging radare2's handshake forever.
        while True:
            time.sleep(0.05)

    t0 = time.monotonic()
    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        side_effect=_hang,
    ):
        result = analyze_functions(path)
    elapsed = time.monotonic() - t0

    # Must return (not hang forever) and stay near the configured hard
    # timeout, not the old unbounded r2pipe.open() call.
    assert elapsed < R2_OPEN_HARD_TIMEOUT + 15
    assert isinstance(result, dict)
    assert result["results"] == []
    assert "error" in result


# ---------------------------------------------------------------------------
# 2. r2 process/session is cleaned up on timeout
# ---------------------------------------------------------------------------

def test_analyze_functions_kills_r2_process_on_timeout():
    """
    On a hard timeout of the per-function pdfj call, the underlying r2
    process must be forcibly killed (via RadareExtractor._kill_r2_process),
    not merely abandoned.
    """
    path = make_temp_file()

    fake_r2 = MagicMock()
    fake_r2.cmd.return_value = ""
    fake_r2.cmdj.side_effect = [
        [{"name": "sym.main", "size": 32, "offset": 0x1000}],  # aflj
        {"ops": []},  # izj branch not hit since strings passed in
    ]

    kill_calls = []

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        return_value=fake_r2,
    ), patch(
        "engines.extractor_engine.radare_extractor.RadareExtractor._kill_r2_process",
        side_effect=lambda self=None: kill_calls.append(True),
        autospec=False,
    ):
        # Force the per-function pdfj call itself to hang so the hard
        # timeout on that specific call fires.
        def cmdj_side_effect(cmd):
            if cmd.startswith("aflj"):
                return [{"name": "sym.main", "size": 32, "offset": 0x1000}]
            if cmd.startswith("izj"):
                return []
            if cmd.startswith("pdfj"):
                time.sleep(9999)
            return {}

        fake_r2.cmdj.side_effect = cmdj_side_effect

        # Use a very small per-call timeout for a fast test.
        with patch(
            "engines.extractor_engine.radare_extractor.R2_PER_CALL_HARD_TIMEOUT",
            1,
        ), patch(
            "engines.function_analysis_engine.function_analysis_engine.R2_PER_CALL_HARD_TIMEOUT",
            1,
        ):
            result = analyze_functions(path, strings=[], imports=[])

    assert kill_calls, "hard timeout must trigger process kill"
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# 3. successful analysis still completes normally (no regression)
# ---------------------------------------------------------------------------

def test_analyze_functions_success_path_unaffected():
    path = make_temp_file()

    fake_r2 = MagicMock()
    fake_r2.cmd.return_value = ""
    fake_r2.cmdj.side_effect = lambda cmd: (
        [{"name": "sym.main", "size": 32, "offset": 0x1000}]
        if cmd.startswith("aflj")
        else {"ops": []}
    )

    with patch(
        "engines.extractor_engine.radare_extractor.r2pipe.open",
        return_value=fake_r2,
    ):
        result = analyze_functions(path, strings=[], imports=[])

    assert "error" not in result
    assert len(result["results"]) == 1
    assert result["results"][0]["function_name"] == "sym.main"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
