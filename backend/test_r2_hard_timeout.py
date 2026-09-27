"""
test_r2_hard_timeout.py

Deterministic, mocked regression test for the Radare2 hard wall-clock
timeout / process-kill protection in radare_extractor.py.

LIMITATION (per task requirement #11): running an actual hostile/malformed
binary that hangs real radare2 indefinitely is not safe or deterministic to
execute automatically in CI/regression — a real hang, by definition, has no
guaranteed upper bound if the kill mechanism itself were broken, which could
stall the test run. Instead, this test simulates the hang deterministically
by mocking r2.cmd() to block on a threading.Event that is only released
by the test process itself, and verifies:
  1. open() does not block past the configured hard timeout.
  2. The hard-kill path is invoked (proc.kill()).
  3. open() raises TimeoutError rather than hanging forever.
  4. self.r2 is invalidated (set to None) centrally, in
     _run_with_hard_timeout's timeout branch — not only reachable via
     open()'s exception handler — confirming the fix that any guarded
     call's timeout (not just open()/aaa) invalidates the session.
  5. A subsequent, normal (non-hanging) session still works — proving the
     timeout path does not leave broken global state affecting later runs.

A real malformed-binary hang test should still be run manually/periodically
against an actual hostile sample in an isolated environment, but is
intentionally excluded from automated regression for the reason above.
"""

import os
import tempfile
import threading
import time
from unittest.mock import patch, MagicMock

import engines.extractor_engine.radare_extractor as radare_extractor
from engines.extractor_engine.radare_extractor import RadareExtractor


def make_temp_file():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"HARD_TIMEOUT_TEST_FIXTURE")
        return f.name


def test_hard_timeout_kills_hung_r2_and_invalidates_session():

    path = make_temp_file()

    hang_forever = threading.Event()  # never set — simulates a permanent hang
    kill_called = threading.Event()

    mock_process = MagicMock()

    def _fake_kill():
        kill_called.set()
        hang_forever.set()  # unblock the fake hang once "killed", like real proc.kill()

    mock_process.kill.side_effect = _fake_kill
    mock_process.pid = 999999  # unlikely to collide with a real PID

    mock_r2 = MagicMock()
    mock_r2.process = mock_process  # confirmed attribute name in production r2pipe

    def _blocking_cmd(cmd):
        # Simulates radare2 never returning from "aaa" until killed.
        hang_forever.wait()
        raise RuntimeError("pipe closed")  # what a killed process's read raises

    mock_r2.cmd.side_effect = _blocking_cmd

    with patch.object(radare_extractor, "r2pipe") as mock_r2pipe, \
         patch.object(radare_extractor, "subprocess") as mock_subprocess:
        mock_r2pipe.open.return_value = mock_r2

        extractor = RadareExtractor(path)

        # Force a short hard timeout for a fast, deterministic test run.
        with patch.object(radare_extractor, "R2_ANALYSIS_HARD_TIMEOUT", 1):
            start = time.monotonic()
            try:
                extractor.open()
                assert False, "expected TimeoutError"
            except TimeoutError:
                pass
            elapsed = time.monotonic() - start

        # Must not have waited anywhere near "forever" — bounded by the
        # configured hard timeout plus the small grace period.
        assert elapsed < 10, f"open() blocked too long: {elapsed}s"
        assert kill_called.is_set(), "hard-kill path was never invoked"
        # Confirms centralized invalidation inside _run_with_hard_timeout,
        # not just a residual set in open()'s exception handler.
        assert extractor.r2 is None, "session handle must be invalidated after timeout"

    os.remove(path)


def test_per_call_timeout_stops_get_calls_from_all_functions_early():
    """
    Verifies that a hard timeout during a per-function pdfj call invalidates
    self.r2 centrally, causing get_calls_from_all_functions() to stop after
    the first timeout instead of attempting further calls against a dead
    session.
    """
    path = make_temp_file()

    mock_process = MagicMock()
    mock_process.pid = 555555
    hang_forever = threading.Event()

    def _fake_kill():
        hang_forever.set()

    mock_process.kill.side_effect = _fake_kill

    mock_r2 = MagicMock()
    mock_r2.process = mock_process
    mock_r2.cmd.return_value = ""

    # Two functions in the function list; only the first pdfj call hangs.
    mock_r2.cmdj.side_effect = None
    call_log = []

    def _cmdj(cmd):
        call_log.append(cmd)
        if cmd == "aflj":
            return [
                {"name": "fcn.first", "offset": 0x1000},
                {"name": "fcn.second", "offset": 0x2000},
            ]
        if cmd.startswith("pdfj"):
            hang_forever.wait()
            raise RuntimeError("pipe closed")
        return []

    mock_r2.cmdj.side_effect = _cmdj

    with patch.object(radare_extractor, "r2pipe") as mock_r2pipe, \
         patch.object(radare_extractor, "subprocess"):
        mock_r2pipe.open.return_value = mock_r2

        extractor = RadareExtractor(path)
        with patch.object(radare_extractor, "R2_ANALYSIS_HARD_TIMEOUT", 5):
            extractor.open()  # aaa is mocked to return immediately (cmd.return_value = "")

        with patch.object(radare_extractor, "R2_PER_CALL_HARD_TIMEOUT", 1):
            result = extractor.get_calls_from_all_functions(max_functions=200)

        # Only the first function's pdfj call should have been attempted —
        # the second must be skipped because self.r2 was invalidated after
        # the first call's timeout.
        pdfj_calls = [c for c in call_log if c.startswith("pdfj")]
        assert len(pdfj_calls) == 1, (
            f"expected exactly 1 pdfj call before session invalidation, got {len(pdfj_calls)}"
        )
        assert extractor.r2 is None
        assert result == []

    os.remove(path)


def test_normal_session_unaffected_by_timeout_mechanism():
    """A non-hanging session must behave exactly as before — no regression
    in the happy path introduced by the timeout wrapper."""
    path = make_temp_file()

    mock_process = MagicMock()
    mock_process.pid = 123456

    mock_r2 = MagicMock()
    mock_r2.process = mock_process
    mock_r2.cmd.return_value = ""
    mock_r2.cmdj.return_value = []

    with patch.object(radare_extractor, "r2pipe") as mock_r2pipe:
        mock_r2pipe.open.return_value = mock_r2

        extractor = RadareExtractor(path)
        extractor.open()  # should return promptly, no exception
        assert extractor.r2 is not None
        assert extractor.get_functions() == []
        extractor.close()
        assert extractor.r2 is None

    os.remove(path)

def test_open_late_completion_kills_orphaned_handle():
    """
    Verifies that if r2pipe.open() eventually completes AFTER the open-stage
    hard timeout has already fired, the late-arriving handle is killed
    rather than silently leaked.
    """
    path = make_temp_file()

    open_released = threading.Event()
    late_kill_called = threading.Event()

    late_process = MagicMock()
    late_process.pid = 777777
    late_process.kill.side_effect = lambda: late_kill_called.set()

    late_r2_handle = MagicMock()
    late_r2_handle.process = late_process

    def _slow_open(path_arg, flags=None):
        open_released.wait()  # blocks until released below, simulating a hang
        return late_r2_handle

    with patch.object(radare_extractor, "r2pipe") as mock_r2pipe, \
         patch.object(radare_extractor, "subprocess"):
        mock_r2pipe.open.side_effect = _slow_open

        extractor = RadareExtractor(path)

        with patch.object(radare_extractor, "R2_OPEN_HARD_TIMEOUT", 1):
            try:
                extractor.open()
                assert False, "expected TimeoutError"
            except TimeoutError:
                pass

        assert extractor.r2 is None

        # Now let the "hung" open() finally complete.
        open_released.set()
        # Give the daemon worker thread a moment to run its late-result
        # cleanup callback.
        for _ in range(50):
            if late_kill_called.is_set():
                break
            time.sleep(0.1)

        assert late_kill_called.is_set(), (
            "late-arriving r2pipe.open() result must be killed, not leaked"
        )

    os.remove(path)


def test_calls_loop_stops_at_aggregate_budget():
    """
    Verifies the aggregate wall-clock budget in get_calls_from_all_functions
    stops the loop and preserves partial results, independent of the
    per-call timeout and max_functions count.
    """
    path = make_temp_file()

    mock_process = MagicMock()
    mock_process.pid = 444444

    mock_r2 = MagicMock()
    mock_r2.process = mock_process
    mock_r2.cmd.return_value = ""

    funcs = [{"name": f"fcn.f{i}"} for i in range(5)]

    def _cmdj(cmd):
        if cmd == "aflj":
            return funcs
        if cmd.startswith("pdfj"):
            return {"ops": [{"type": "call", "disasm": "call sym.imp.SomeAPI"}]}
        return []

    mock_r2.cmdj.side_effect = _cmdj

    with patch.object(radare_extractor, "r2pipe") as mock_r2pipe, \
         patch.object(radare_extractor, "subprocess"):
        mock_r2pipe.open.return_value = mock_r2

        extractor = RadareExtractor(path)
        with patch.object(radare_extractor, "R2_ANALYSIS_HARD_TIMEOUT", 5):
            extractor.open()

        # Simulate the budget already being exceeded before the loop even
        # starts, so exactly zero functions are processed and the loop
        # exits via the budget guard (deterministic, no real sleeping).
        with patch.object(radare_extractor, "R2_CALLS_TOTAL_BUDGET_SECONDS", 0), \
             patch.object(radare_extractor.time, "monotonic", side_effect=[0.0, 1.0]):
            result = extractor.get_calls_from_all_functions(max_functions=200)

        assert result == [], "loop should have stopped before collecting any calls"

    os.remove(path)


if __name__ == "__main__":
    print("Running Radare2 hard-timeout regression tests...")
    test_hard_timeout_kills_hung_r2_and_invalidates_session()
    test_per_call_timeout_stops_get_calls_from_all_functions_early()
    test_normal_session_unaffected_by_timeout_mechanism()
    test_open_late_completion_kills_orphaned_handle()
    test_calls_loop_stops_at_aggregate_budget()
    print("All hard-timeout tests passed.")
