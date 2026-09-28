import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import engines.ghidra_engine.ghidra_engine as ghidra_engine
from engines.ghidra_engine.ghidra_engine import run_ghidra_analysis


def _create_fake_headless(tmp_path):
    """
    Creates a real temporary file so the production code's
    headless-path existence check succeeds.
    """
    fake_headless = tmp_path / "analyzeHeadless.bat"
    fake_headless.write_text(
        "@echo off\n",
        encoding="utf-8",
    )
    return str(fake_headless)


def _create_fake_target(tmp_path):
    """
    Creates a real temporary target file so the production code's
    target-file existence check succeeds.
    """
    fake_target = tmp_path / "dummy_binary.exe"
    fake_target.write_bytes(b"MZ\x00\x00")
    return str(fake_target)


def test_ghidra_timeout_is_handled_without_raising(tmp_path):
    """
    Simulates a Ghidra script timing out.

    run_ghidra_analysis() should handle subprocess.TimeoutExpired
    internally and continue without leaking the exception to the caller.
    """

    fake_headless = _create_fake_headless(tmp_path)
    fake_target = _create_fake_target(tmp_path)

    with (
        patch.object(
            ghidra_engine,
            "_resolve_headless",
            return_value=fake_headless,
        ),
        patch.object(
            ghidra_engine,
            "_run_headless",
            side_effect=subprocess.TimeoutExpired(
                cmd=[fake_headless],
                timeout=1,
            ),
        ),
        patch.object(
            ghidra_engine,
            "_read_json_output",
            return_value=[],
        ),
    ):
        result = run_ghidra_analysis(fake_target)

    assert isinstance(result, dict)
    assert "functions" in result
    assert "calls" in result
    assert "strings" in result


def test_ghidra_timeout_does_not_leave_analysis_directory(tmp_path):
    """
    Verifies that the temporary Ghidra analysis directory is cleaned up
    even when the headless analysis times out.
    """

    created_tmp_dir = None
    real_mkdtemp = tempfile.mkdtemp

    def fake_mkdtemp(prefix):
        nonlocal created_tmp_dir

        created_tmp_dir = Path(real_mkdtemp(prefix=prefix))
        return str(created_tmp_dir)

    fake_headless = _create_fake_headless(tmp_path)
    fake_target = _create_fake_target(tmp_path)

    with (
        patch.object(
            ghidra_engine,
            "_resolve_headless",
            return_value=fake_headless,
        ),
        patch.object(
            ghidra_engine.tempfile,
            "mkdtemp",
            side_effect=fake_mkdtemp,
        ),
        patch.object(
            ghidra_engine,
            "_run_headless",
            side_effect=subprocess.TimeoutExpired(
                cmd=[fake_headless],
                timeout=1,
            ),
        ),
        patch.object(
            ghidra_engine,
            "_read_json_output",
            return_value=[],
        ),
    ):
        result = run_ghidra_analysis(fake_target)

    assert isinstance(result, dict)

    assert created_tmp_dir is not None
    assert not created_tmp_dir.exists()


def test_ghidra_normal_execution_remains_unaffected(tmp_path):
    """
    Verifies that normal Ghidra execution still produces a valid result
    when no timeout occurs.
    """

    fake_headless = _create_fake_headless(tmp_path)
    fake_target = _create_fake_target(tmp_path)

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = ""
    mock_result.stderr = ""

    with (
        patch.object(
            ghidra_engine,
            "_resolve_headless",
            return_value=fake_headless,
        ),
        patch.object(
            ghidra_engine,
            "_run_headless",
            return_value=mock_result,
        ),
        patch.object(
            ghidra_engine,
            "_read_json_output",
            return_value=[],
        ),
    ):
        result = run_ghidra_analysis(fake_target)

    assert isinstance(result, dict)
    assert "functions" in result
    assert "calls" in result
    assert "strings" in result


def test_timeout_kills_process_tree_not_just_immediate_process():
    """
    Simulates communicate() timing out, and verifies _kill_process_tree
    is invoked with the correct PID, and that TimeoutExpired is re-raised
    so the existing caller-side handling is unaffected.
    """

    mock_proc = MagicMock()
    mock_proc.pid = 424242

    mock_proc.communicate.side_effect = [
        subprocess.TimeoutExpired(
            cmd=["fake"],
            timeout=1,
        ),
        ("partial stdout", "partial stderr"),
    ]

    kill_tree_calls = []

    def _fake_kill_tree(pid):
        kill_tree_calls.append(pid)

    with (
        patch.object(
            ghidra_engine.subprocess,
            "Popen",
            return_value=mock_proc,
        ),
        patch.object(
            ghidra_engine,
            "_kill_process_tree",
            side_effect=_fake_kill_tree,
        ),
        patch.object(
            ghidra_engine,
            "GHIDRA_TIMEOUT",
            1,
        ),
    ):
        try:
            ghidra_engine._run_headless(["fake_cmd"])
            assert False, "expected subprocess.TimeoutExpired to be raised"
        except subprocess.TimeoutExpired:
            pass

    assert kill_tree_calls == [424242], (
        f"expected process-tree kill for pid 424242, "
        f"got {kill_tree_calls}"
    )


def test_windows_kill_uses_taskkill_with_tree_flag():
    """
    Verifies the Windows kill path specifically invokes:

        taskkill /F /T /PID <pid>

    The /T flag is what reaches descendant processes such as java.exe
    spawned by analyzeHeadless.bat via cmd.exe.
    """

    captured_cmds = []

    def _fake_run(cmd, **kwargs):
        captured_cmds.append(cmd)
        return MagicMock(returncode=0)

    with (
        patch.object(
            ghidra_engine,
            "_IS_WINDOWS",
            True,
        ),
        patch.object(
            ghidra_engine.subprocess,
            "run",
            side_effect=_fake_run,
        ),
    ):
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
    Cleanup must be best-effort.

    A failure in the kill operation must not propagate and prevent
    the caller from continuing to raise/handle the original
    TimeoutExpired exception.
    """

    with (
        patch.object(
            ghidra_engine,
            "_IS_WINDOWS",
            True,
        ),
        patch.object(
            ghidra_engine.subprocess,
            "run",
            side_effect=RuntimeError("taskkill unavailable"),
        ),
    ):
        # Must not raise.
        ghidra_engine._kill_process_tree(123)


def test_normal_run_unaffected_by_popen_migration():
    """
    A successful non-timeout run must return the same
    CompletedProcess-shaped result as before.

    This verifies that migration from subprocess.run() to
    Popen + communicate() does not regress the happy path.
    """

    mock_proc = MagicMock()
    mock_proc.pid = 1
    mock_proc.communicate.return_value = (
        "ok stdout",
        "",
    )
    mock_proc.returncode = 0

    with patch.object(
        ghidra_engine.subprocess,
        "Popen",
        return_value=mock_proc,
    ):
        result = ghidra_engine._run_headless(["fake_cmd"])

    assert result.returncode == 0
    assert result.stdout == "ok stdout"
    assert result.stderr == ""


if __name__ == "__main__":
    print("Ghidra hard-timeout regression tests")