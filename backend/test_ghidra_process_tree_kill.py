"""
test_ghidra_process_tree_kill.py

Focused regression test for the process-TREE kill added to
ghidra_engine._run_headless() / _kill_process_tree(). Proves specifically
that on timeout, cleanup goes beyond the immediate subprocess and targets
the tree — the exact gap subprocess.run(timeout=...)'s default behavior
does not cover.

Deterministic and mocked, for the same reasons test_r2_hard_timeout.py's
tests are mocked rather than exercising a real hang: a real indefinite
Ghidra hang has no bounded upper time cost to rely on in automated
regression if the kill mechanism itself were broken.
"""

import subprocess
from unittest.mock import patch, MagicMock

import engines.ghidra_engine.ghidra_engine as ghidra_engine


def test_timeout_kills_process_tree_not_just_immediate_process():
    """
    Simulates communicate() timing out, and verifies _kill_process_tree is
    invoked with the correct PID, and that TimeoutExpired is re-raised so
    the existing caller-side handling is unaffected.
    """
    mock_proc = MagicMock()
    mock_proc.pid = 424242
    mock_proc.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd=["fake"], timeout=1),
        ("partial stdout", "partial stderr"),
    ]

    kill_tree_calls = []

    def _fake_kill_tree(pid):
        kill_tree_calls.append(pid)

    with patch.object(ghidra_engine.subprocess, "Popen", return_value=mock_proc), \
         patch.object(ghidra_engine, "_kill_process_tree", side_effect=_fake_kill_tree), \
         patch.object(ghidra_engine, "GHIDRA_TIMEOUT", 1):

        try:
            ghidra_engine._run_headless(["fake_cmd"])
            assert False, "expected subprocess.TimeoutExpired to be raised"
        except subprocess.TimeoutExpired:
            pass

    assert kill_tree_calls == [424242], (
        f"expected process-tree kill for pid 424242, got {kill_tree_calls}"
    )


def test_windows_kill_uses_taskkill_with_tree_flag():
    """
    Verifies the Windows kill path specifically invokes
    `taskkill /F /T /PID <pid>` — the /T flag is what reaches descendant
    processes (e.g. java.exe spawned by analyzeHeadless.bat via cmd.exe),
    which a bare process.kill() on the immediate subprocess does not.
    """
    captured_cmds = []

    def _fake_run(cmd, **kwargs):
        captured_cmds.append(cmd)
        return MagicMock(returncode=0)

    with patch.object(ghidra_engine, "_IS_WINDOWS", True), \
         patch.object(ghidra_engine.subprocess, "run", side_effect=_fake_run):
        ghidra_engine._kill_process_tree(999)

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert cmd[0] == "taskkill"
    assert "/F" in cmd
    assert "/T" in cmd
    assert "/PID" in cmd
    assert "999" in cmd


def test_kill_process_tree_never_raises_on_failure():
    """
    Cleanup must be best-effort — a failure in the kill itself must not
    propagate and prevent the caller from continuing to raise/handle the
    original TimeoutExpired.
    """
    with patch.object(ghidra_engine, "_IS_WINDOWS", True), \
         patch.object(
             ghidra_engine.subprocess, "run",
             side_effect=RuntimeError("taskkill unavailable"),
         ):
        # Must not raise.
        ghidra_engine._kill_process_tree(123)


def test_normal_run_unaffected_by_popen_migration():
    """
    A successful (non-timeout) run must return the same
    CompletedProcess-shaped result as before — proving the migration from
    subprocess.run() to Popen+communicate() introduces no regression in
    the happy path.
    """
    mock_proc = MagicMock()
    mock_proc.pid = 1
    mock_proc.communicate.return_value = ("ok stdout", "")
    mock_proc.returncode = 0

    with patch.object(ghidra_engine.subprocess, "Popen", return_value=mock_proc):
        result = ghidra_engine._run_headless(["fake_cmd"])

    assert result.returncode == 0
    assert result.stdout == "ok stdout"
    assert result.stderr == ""


if __name__ == "__main__":
    print("Running Ghidra process-tree-kill regression tests...")
    test_timeout_kills_process_tree_not_just_immediate_process()
    test_windows_kill_uses_taskkill_with_tree_flag()
    test_kill_process_tree_never_raises_on_failure()
    test_normal_run_unaffected_by_popen_migration()
    print("All Ghidra process-tree-kill tests passed.")