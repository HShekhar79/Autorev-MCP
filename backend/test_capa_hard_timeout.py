import os
import subprocess
import sys
import time
from unittest.mock import patch

from engines.capa_engine.capa_engine import (
    CAPA_TIMEOUT,
    _kill_process_tree,
    run_capa_analysis,
)


def test_capa_timeout_config_is_available():
    assert isinstance(CAPA_TIMEOUT, int)
    assert CAPA_TIMEOUT > 0


def test_capa_process_tree_helper_is_callable():
    assert callable(_kill_process_tree)


def test_capa_timeout_returns_failed_result():
    """
    Verify that a CAPA timeout is converted into the existing
    capa_timeout result contract without running real CAPA analysis.
    """

    fake_process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )

    try:
        with patch(
            "engines.capa_engine.capa_engine.subprocess.Popen",
            return_value=fake_process,
        ), patch(
            "engines.capa_engine.capa_engine.CAPA_TIMEOUT",
            1,
        ):
            # Use an existing file so execution reaches the CAPA subprocess.
            result = run_capa_analysis(__file__)

        assert result["status"] == "failed"
        assert result["reason"] == "capa_timeout"
        assert ">1s on" in result["detail"]

    finally:
        if fake_process.poll() is None:
            _kill_process_tree(fake_process.pid)

        try:
            fake_process.communicate(timeout=5)
        except Exception:
            pass


def test_kill_process_tree_terminates_process():
    """
    Verify that the CAPA cleanup helper actually terminates
    a running process on the current platform.
    """

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )

    assert process.poll() is None

    _kill_process_tree(process.pid)

    for _ in range(20):
        if process.poll() is not None:
            break
        time.sleep(0.1)

    assert process.poll() is not None


def test_capa_normal_subprocess_path_is_not_changed():
    """
    Verify that normal subprocess execution still works independently
    of the CAPA analysis pipeline.
    """

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "print('CAPA_TEST_OK')",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )

    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0
    assert stdout.strip() == "CAPA_TEST_OK"
    assert stderr.strip() == ""