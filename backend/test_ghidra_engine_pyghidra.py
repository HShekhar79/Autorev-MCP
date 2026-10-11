"""Focused tests for the PyGhidra launcher integration. All subprocess calls are mocked.

The Ghidra launcher runs through subprocess.Popen(...) + communicate(timeout=...)
(so a timeout can kill the whole process tree); pip and the version probe still go
through subprocess.run(...).  make_fake_popen() models the former.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from engines.ghidra_engine import ghidra_engine as ge  # noqa: E402

_REAL_ENSURE = ge._ensure_pyghidra   # captured before the autouse patch below
_REAL_RESOLVE = ge._resolve_ghidra_python
_REAL_VERSION = ge._installed_pyghidra_version

FAKE_PY = str(Path("/fake/.ghidra-venv/python"))   # stands in for the dedicated 3.12 interpreter

PYG_ERR = "ERROR REPORT SCRIPT ERROR: extract_functions.py : Ghidra was not started with PyGhidra. Python is not available"


@pytest.fixture(autouse=True)
def _no_real_provisioning(monkeypatch):
    """Default: PyGhidra is 'ready' so run_ghidra_analysis tests never touch pip."""
    monkeypatch.setattr(ge, "_ensure_pyghidra",
                        lambda python_exe: ge._Setup(True, "ready", "pyghidra 3.0.2"))
    monkeypatch.setattr(ge, "_resolve_ghidra_python", lambda: FAKE_PY)


FAKE_PID = 424242


@pytest.fixture(autouse=True)
def killed(monkeypatch):
    """Record _kill_process_tree calls; a test must never really taskkill/killpg a PID."""
    pids = []
    monkeypatch.setattr(ge, "_kill_process_tree", lambda pid: pids.append(pid))
    return pids


@pytest.fixture
def ghidra_home(tmp_path, monkeypatch):
    home = tmp_path / "ghidra"
    launcher = home / "Ghidra" / "Features" / "PyGhidra" / "support" / "pyghidra_launcher.py"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("# fake")
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(ge, "GHIDRA_HOME", str(home))
    return home, launcher, sample


def _arg_after(cmd, flag):
    return cmd[cmd.index(flag) + 1]


class FakePopen:
    """Minimal subprocess.Popen stand-in: .pid, .returncode, .communicate(timeout=), .kill().

    `kw` is the dict the test inspects (Popen kwargs). The communicate() timeout is
    recorded into it as kw["timeout"] (first call only), so "timeout == GHIDRA_TIMEOUT"
    stays assertable. If `hang` is set, the first communicate() raises TimeoutExpired,
    like a real hung child; the follow-up communicate() (after the engine killed the
    tree) returns the partial output.
    """

    def __init__(self, cmd, kw, rc, stdout, stderr, hang=False):
        self.args = cmd
        self._kw = kw
        self._rc = rc
        self._out = stdout
        self._err = stderr
        self._hang = hang
        self.pid = FAKE_PID
        self.returncode = None

    def communicate(self, timeout=None):
        self._kw.setdefault("timeout", timeout)
        if self._hang:
            self._hang = False
            raise subprocess.TimeoutExpired(self.args, timeout)
        self.returncode = self._rc
        return self._out, self._err

    def kill(self):
        self.returncode = -9


def make_fake_popen(calls, outputs=None, stdout="", stderr="", rc=0, timeout_on=None):
    """outputs: {script_name: json-able or None(no file)}; default valid output for all.

    Returns a drop-in for subprocess.Popen. Calls are recorded as (cmd, kwargs) with
    the communicate() timeout merged into kwargs.
    """
    defaults = {
        "extract_functions.py": [{"name": "main", "address": "00401000", "size": 10}],
        "extract_calls.py": [{"caller": "main", "callee": "CreateFileA", "address": "00401005"}],
        "extract_strings.py": [{"value": "hello world", "address": "00402000", "length": 11}],
    }
    outs = dict(defaults)
    outs.update(outputs or {})

    def fake_popen(cmd, **kw):
        calls.append((cmd, kw))
        script = _arg_after(cmd, "-postScript")
        if timeout_on == script:
            return FakePopen(cmd, kw, rc, stdout, stderr, hang=True)
        out_dir = Path(_arg_after(cmd, "--output-dir"))
        data = outs.get(script)
        if data is not None:
            (out_dir / f"{Path(script).stem}_output.json").write_text(json.dumps(data))
        return FakePopen(cmd, kw, rc, stdout, stderr)
    return fake_popen


# A
def test_launcher_resolution(ghidra_home):
    _, launcher, _ = ghidra_home
    assert ge._resolve_pyghidra_launcher() == str(launcher)


# D
def test_missing_launcher_or_home(ghidra_home, monkeypatch):
    home, launcher, sample = ghidra_home
    launcher.unlink()
    assert ge._resolve_pyghidra_launcher() is None
    ran = []
    monkeypatch.setattr(ge.subprocess, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setattr(ge.subprocess, "Popen", lambda *a, **k: ran.append(1))
    assert ge.run_ghidra_analysis(str(sample)) is None
    assert not ran
    monkeypatch.setattr(ge, "GHIDRA_HOME", None)
    assert ge._resolve_pyghidra_launcher() is None


# B, C
def test_command_construction(ghidra_home, monkeypatch):
    home, launcher, _ = ghidra_home
    monkeypatch.setattr(ge, "GHIDRA_PYGHIDRA_LAUNCHER", str(launcher))
    monkeypatch.setattr(ge, "GHIDRA_SCRIPTS_DIR", "/scripts")
    proj = Path("/tmp/proj")
    cmd = ge._build_cmd(proj, "P", "/bin/a b.exe", "extract_calls.py", ["--output-dir", "/o"], True)
    assert cmd[:4] == [FAKE_PY, str(launcher), "-H", str(home)]
    assert cmd[4:6] == [str(proj), "P"]
    assert "cmd.exe" not in cmd and "analyzeHeadless.bat" not in " ".join(cmd)
    assert _arg_after(cmd, "-import") == "/bin/a b.exe"          # path passed as one list item
    assert "-overwrite" in cmd
    assert _arg_after(cmd, "-scriptPath") == "/scripts"
    assert _arg_after(cmd, "-postScript") == "extract_calls.py"
    assert cmd[cmd.index("-postScript") + 1:cmd.index("-postScript") + 4] == [
        "extract_calls.py", "--output-dir", "/o"]
    assert _arg_after(cmd, "-log") == str(proj / "extract_calls.py.log")
    assert cmd[-1] == "-deleteProject"
    assert "-deleteProject" not in ge._build_cmd(proj, "P", "x", "s.py", [], False)


# H, J + shell=False + timeout kwarg
def test_success_schema_and_subprocess_kwargs(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(calls))
    r = ge.run_ghidra_analysis(str(sample))
    assert set(r) == {"functions", "calls", "strings", "_meta"}
    assert r["functions"] == [{"name": "main", "offset": 0x401000, "size": 10}]
    assert r["calls"] == ["CreateFileA"]
    assert r["strings"] == ["hello world"]
    m = r["_meta"]
    for k in ("engine", "elapsed", "function_count", "call_count", "string_count",
              "scripts_executed", "output_dir_files"):
        assert k in m
    assert m["extraction_ok"] is True
    assert set(m["script_status"].values()) == {"ok"}
    assert len(calls) == 3
    for _, kw in calls:
        assert kw["shell"] is False and kw["timeout"] == ge.GHIDRA_TIMEOUT


# E, I
def test_pyghidra_text_with_rc0_is_failure_and_fails_fast(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        calls, outputs={"extract_functions.py": None}, stdout=PYG_ERR, rc=0))
    r = ge.run_ghidra_analysis(str(sample))
    assert r is not None and r["functions"] == [] and r["calls"] == [] and r["strings"] == []
    assert r["_meta"]["script_status"]["extract_functions.py"] == "pyghidra_unavailable"
    assert r["_meta"]["extraction_ok"] is False
    assert len(calls) == 1                                    # remaining scripts skipped


# F
def test_nonzero_exit_is_process_failure(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        [], outputs={"extract_functions.py": None, "extract_calls.py": None,
                     "extract_strings.py": None}, stderr="boom", rc=1))
    r = ge.run_ghidra_analysis(str(sample))
    assert set(r["_meta"]["script_status"].values()) == {"process_failed"}
    assert r["_meta"]["extraction_ok"] is False


def test_rc0_missing_output_no_marker_is_not_success(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        [], outputs={"extract_calls.py": None}))
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"]["extract_calls.py"] == "no_output"
    assert r["_meta"]["extraction_ok"] is False
    assert r["functions"]                                      # partial results preserved


def test_valid_empty_output_is_success(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        [], outputs={"extract_functions.py": [], "extract_calls.py": [],
                     "extract_strings.py": []}))
    r = ge.run_ghidra_analysis(str(sample))
    assert r["functions"] == [] and r["_meta"]["extraction_ok"] is True


# G + cleanup
def test_timeout_preserved_and_cleanup(ghidra_home, monkeypatch, killed):
    sample = ghidra_home[2]
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(calls, timeout_on="extract_calls.py"))
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"]["extract_calls.py"] == "timeout"
    assert r["_meta"]["script_status"]["extract_functions.py"] == "ok"
    assert r["_meta"]["extraction_ok"] is False
    assert len(calls) == 3                                     # later scripts still attempted
    tmp_root = Path(_arg_after(calls[0][0], "--output-dir")).parent
    assert not tmp_root.exists()
    assert killed == [FAKE_PID]                                # hung child's process tree was killed


def test_corrupt_json_not_ok(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    base = make_fake_popen([], outputs={})

    def popen(cmd, **kw):
        p = base(cmd, **kw)
        if _arg_after(cmd, "-postScript") == "extract_strings.py":
            (Path(_arg_after(cmd, "--output-dir")) / "extract_strings_output.json").write_text("{bad")
        return p
    monkeypatch.setattr(ge.subprocess, "Popen", popen)
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"]["extract_strings.py"] == "corrupt_output"
    assert r["strings"] == []


def test_classifier_log_text_marker():
    assert ge._classify_script_run(0, "", "", False, PYG_ERR) == "pyghidra_unavailable"
    # error text names a failure only when the exit code / artifact already show one
    assert ge._classify_script_run(0, "REPORT SCRIPT ERROR: x", "", False) == "script_failed"
    assert ge._classify_script_run(0, "REPORT SCRIPT ERROR: x", "", True) == "ok"


# ---------------------------------------------------------------------------
# Provisioning / non-interactive behaviour
# ---------------------------------------------------------------------------
@pytest.fixture
def prov(ghidra_home, monkeypatch):
    """Real _ensure_pyghidra with a fake bundled wheel dir and mocked version/pip."""
    home, _, sample = ghidra_home
    dist = home.joinpath(*ge._PYGHIDRA_DIST_PARTS)
    dist.mkdir(parents=True)
    (dist / "pyghidra-3.0.2-py3-none-any.whl").write_bytes(b"")
    monkeypatch.setattr(ge, "_ensure_pyghidra", _REAL_ENSURE)
    monkeypatch.setattr(ge, "GHIDRA_PYGHIDRA_AUTO_UPGRADE", False)
    state = {"version": None, "pip_calls": [], "pip_rc": 0, "install_to": "3.0.2"}
    monkeypatch.setattr(ge, "_installed_pyghidra_version", lambda py: state["version"])

    def fake_pip(cmd, **kw):
        state["pip_calls"].append((cmd, kw))
        if state["pip_rc"] == 0:
            state["version"] = state["install_to"]
        return subprocess.CompletedProcess(cmd, state["pip_rc"], "", "pip err")
    monkeypatch.setattr(ge.subprocess, "run", fake_pip)
    return state, dist, sample


def test_first_run_installs_bundled_wheel_offline_noninteractive(prov):
    state, dist, _ = prov
    s = ge._ensure_pyghidra(FAKE_PY)
    assert s.ok and s.status == "installed"
    (cmd, kw), = state["pip_calls"]
    assert cmd[:4] == [FAKE_PY, "-m", "pip", "install"]   # dedicated interpreter, same as launcher
    assert sys.executable not in cmd
    assert "--no-index" in cmd and _arg_after(cmd, "--find-links") == str(dist)
    assert cmd[-1] == "pyghidra==3.0.2"
    assert kw["stdin"] is subprocess.DEVNULL and kw["shell"] is False
    assert kw["timeout"] == ge.GHIDRA_PIP_TIMEOUT


def test_existing_same_or_newer_version_is_untouched(prov):
    state, _, _ = prov
    for v in ("3.0.2", "3.1.0"):
        state["version"] = v
        s = ge._ensure_pyghidra(FAKE_PY)
        assert s.ok and s.status == "ready"
    assert state["pip_calls"] == []


def test_older_version_default_is_not_mutated_and_fails_fast(prov, monkeypatch):
    state, _, sample = prov
    state["version"] = "2.9.0"
    s = ge._ensure_pyghidra(FAKE_PY)
    assert not s.ok and s.status == "outdated" and state["pip_calls"] == []
    # run_ghidra_analysis: setup failure -> None, launcher never started
    assert ge.run_ghidra_analysis(str(sample)) is None
    assert state["pip_calls"] == []


def test_older_version_with_opt_in_upgrade(prov, monkeypatch):
    state, _, _ = prov
    state["version"] = "2.9.0"
    monkeypatch.setattr(ge, "GHIDRA_PYGHIDRA_AUTO_UPGRADE", True)
    s = ge._ensure_pyghidra(FAKE_PY)
    assert s.ok and s.status == "upgraded" and len(state["pip_calls"]) == 1


def test_missing_and_no_wheel_is_setup_failure(prov):
    state, dist, sample = prov
    for w in dist.glob("*.whl"):
        w.unlink()
    s = ge._ensure_pyghidra(FAKE_PY)
    assert not s.ok and s.status == "not_installed_no_wheel" and state["pip_calls"] == []
    assert ge.run_ghidra_analysis(str(sample)) is None


def test_pip_failure_and_timeout_and_unverified(prov, monkeypatch):
    state, _, sample = prov
    state["pip_rc"] = 1
    s = ge._ensure_pyghidra(FAKE_PY)
    assert not s.ok and s.status == "pip_failed"
    assert ge.run_ghidra_analysis(str(sample)) is None

    def boom(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)
    monkeypatch.setattr(ge.subprocess, "run", boom)
    assert ge._ensure_pyghidra(FAKE_PY).status == "pip_timeout"

    state["pip_rc"] = 0
    state["install_to"] = "1.0.0"      # pip "succeeded" but wrong version
    monkeypatch.setattr(ge.subprocess, "run", lambda cmd, **kw: (
        state.__setitem__("version", "1.0.0"),
        subprocess.CompletedProcess(cmd, 0, "", ""))[1])
    state["version"] = None
    assert ge._ensure_pyghidra(FAKE_PY).status == "verify_failed"


def test_launcher_subprocess_has_no_stdin_and_meta_reports_setup(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(calls))
    r = ge.run_ghidra_analysis(str(sample))
    assert len(calls) == 3
    assert all(kw["stdin"] is subprocess.DEVNULL for _, kw in calls)
    assert r["_meta"]["pyghidra_setup"]["status"] == "ready"


def test_launcher_popen_contract(ghidra_home, monkeypatch):
    """Launcher is spawned with the exact Popen contract _run_headless promises."""
    sample = ghidra_home[2]
    monkeypatch.setenv("PYTHONHOME", "x")
    monkeypatch.setenv("VIRTUAL_ENV", "z")
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(calls))
    ge.run_ghidra_analysis(str(sample))
    assert len(calls) == 3
    for _, kw in calls:
        assert kw["shell"] is False
        assert kw["stdin"] is subprocess.DEVNULL
        assert kw["stdout"] is subprocess.PIPE and kw["stderr"] is subprocess.PIPE
        assert kw["text"] is True
        assert "PYTHONHOME" not in kw["env"] and "VIRTUAL_ENV" not in kw["env"]
        assert kw["timeout"] == ge.GHIDRA_TIMEOUT          # passed to communicate(timeout=...)


def test_launcher_prompt_text_is_classified_and_fails_fast(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        calls, outputs={"extract_functions.py": None},
        stderr="EOFError: EOF when reading a line", rc=1))
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"] == {"extract_functions.py": "pyghidra_prompt_blocked"}
    assert r["_meta"]["extraction_ok"] is False and len(calls) == 1


# ---------------------------------------------------------------------------
# Classification / semantics
# ---------------------------------------------------------------------------
def test_script_error_line_names_failure_only_when_artifact_missing():
    out = "[GHIDRA][extract_functions] ERROR enumerating functions: boom"
    assert ge._classify_script_run(0, out, "", False) == "script_failed"
    assert ge._classify_script_run(1, out, "", False) == "script_failed"
    assert ge._classify_script_run(0, "[GHIDRA][extract_functions] WARN skipping func: x", "", True) == "ok"


def test_zero_byte_and_non_list_output_are_corrupt(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        [], outputs={"extract_functions.py": {"not": "a list"}}))
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"]["extract_functions.py"] == "corrupt_output"
    assert r["_meta"]["extraction_ok"] is False and r["functions"] == []

    d = Path(sample).parent
    (d / "extract_x_output.json").write_text("")
    assert ge._read_json_output(d, "extract_x") is None


def test_argument_order_and_spaces(ghidra_home, monkeypatch, tmp_path):
    home, launcher, _ = ghidra_home
    spaced = tmp_path / "Himanshu Shekhar" / "test mitre.exe"
    spaced.parent.mkdir()
    spaced.write_bytes(b"MZ")
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(calls))
    ge.run_ghidra_analysis(str(spaced))
    cmd = calls[0][0]
    assert cmd[:4] == [FAKE_PY, str(launcher), "-H", str(home)]
    assert _arg_after(cmd, "-import") == str(spaced)


# ---------------------------------------------------------------------------
# Dedicated Ghidra Python runtime
# ---------------------------------------------------------------------------
@pytest.fixture
def real_resolver(monkeypatch, tmp_path):
    """Undo the autouse resolver patch; point the project root at a temp tree."""
    monkeypatch.setattr(ge, "_resolve_ghidra_python", _REAL_RESOLVE)
    monkeypatch.delenv("GHIDRA_PYTHON_EXECUTABLE", raising=False)
    monkeypatch.setattr(ge, "_PROJECT_ROOT", tmp_path)
    return tmp_path


def _make_ghidra_venv(root, windows):
    rel = ("Scripts", "python.exe") if windows else ("bin", "python")
    exe = root.joinpath(".ghidra-venv", *rel)
    exe.parent.mkdir(parents=True)
    exe.write_text("")
    return exe


@pytest.mark.parametrize("windows", [True, False])
def test_resolution_defaults_to_dedicated_ghidra_venv(real_resolver, monkeypatch, windows):
    monkeypatch.setattr(ge, "_IS_WINDOWS", windows)
    exe = _make_ghidra_venv(real_resolver, windows)
    assert ge._resolve_ghidra_python() == str(exe)
    assert ge._resolve_ghidra_python() != sys.executable


def test_explicit_env_overrides_default(real_resolver, monkeypatch, tmp_path):
    monkeypatch.setattr(ge, "_IS_WINDOWS", True)
    _make_ghidra_venv(real_resolver, True)
    other = tmp_path / "custom" / "py312.exe"
    other.parent.mkdir()
    other.write_text("")
    monkeypatch.setenv("GHIDRA_PYTHON_EXECUTABLE", str(other))
    assert ge._resolve_ghidra_python() == str(other)


def test_invalid_explicit_env_fails_without_fallback(real_resolver, monkeypatch):
    monkeypatch.setattr(ge, "_IS_WINDOWS", True)
    _make_ghidra_venv(real_resolver, True)          # default exists, but must NOT be used
    monkeypatch.setenv("GHIDRA_PYTHON_EXECUTABLE", str(real_resolver / "nope.exe"))
    assert ge._resolve_ghidra_python() is None


def test_missing_dedicated_python_fails_clearly_and_runs_nothing(ghidra_home, real_resolver, monkeypatch):
    sample = ghidra_home[2]
    ran = []
    monkeypatch.setattr(ge.subprocess, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setattr(ge.subprocess, "Popen", lambda *a, **k: ran.append(1))
    assert ge._resolve_ghidra_python() is None
    assert ge.run_ghidra_analysis(str(sample)) is None
    assert ran == []                                  # no pip, no launcher, no sys.executable fallback


def test_launcher_and_provisioning_use_dedicated_python_not_sys_executable(ghidra_home, real_resolver, monkeypatch):
    home, launcher, sample = ghidra_home
    monkeypatch.setattr(ge, "_IS_WINDOWS", True)
    exe = _make_ghidra_venv(real_resolver, True)
    dist = home.joinpath(*ge._PYGHIDRA_DIST_PARTS)
    dist.mkdir(parents=True)
    (dist / "pyghidra-3.0.2-py3-none-any.whl").write_bytes(b"")
    monkeypatch.setattr(ge, "_ensure_pyghidra", _REAL_ENSURE)
    monkeypatch.setattr(ge, "GHIDRA_PYGHIDRA_AUTO_UPGRADE", False)

    calls = []
    installed = {"v": None}
    fake_launch = make_fake_popen([])      # writes the JSON outputs; its own call list is unused

    def fake_run(cmd, **kw):
        if cmd[1:3] == ["-c", ge._VERSION_PROBE]:            # version probe
            calls.append(("probe", cmd))
            return subprocess.CompletedProcess(cmd, 0, installed["v"] or "", "")
        if cmd[1:3] == ["-m", "pip"]:                         # provisioning
            calls.append(("pip", cmd))
            installed["v"] = "3.0.2"
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected subprocess.run: {cmd!r}")   # launches must use Popen
    monkeypatch.setattr(ge.subprocess, "run", fake_run)

    def fake_popen(cmd, **kw):
        calls.append(("launch", cmd))
        return fake_launch(cmd, **kw)
    monkeypatch.setattr(ge.subprocess, "Popen", fake_popen)

    r = ge.run_ghidra_analysis(str(sample))
    kinds = [k for k, _ in calls]
    assert kinds[0] == "probe" and "pip" in kinds and kinds.count("launch") == 3
    for _, cmd in calls:
        assert cmd[0] == str(exe)                             # always the dedicated interpreter
        assert sys.executable not in cmd
    assert r["_meta"]["extraction_ok"] is True
    assert r["_meta"]["ghidra_python"] == str(exe)
    assert r["_meta"]["pyghidra_setup"]["status"] == "installed"


def test_child_env_strips_autorev_python_settings(monkeypatch):
    monkeypatch.setenv("PYTHONHOME", "x")
    monkeypatch.setenv("PYTHONPATH", "y")
    monkeypatch.setenv("VIRTUAL_ENV", "z")
    monkeypatch.setenv("GHIDRA_HOME", "keep")
    env = ge._child_env()
    assert "PYTHONHOME" not in env and "PYTHONPATH" not in env and "VIRTUAL_ENV" not in env
    assert env["GHIDRA_HOME"] == "keep"


def test_all_ghidra_subprocesses_get_clean_env_and_no_stdin(prov, monkeypatch):
    state, _, _ = prov
    seen = []
    orig = ge.subprocess.run

    def spy(cmd, **kw):
        seen.append(kw)
        return orig(cmd, **kw)
    monkeypatch.setattr(ge.subprocess, "run", spy)
    ge._ensure_pyghidra(FAKE_PY)
    assert seen and all(kw["stdin"] is subprocess.DEVNULL and "env" in kw for kw in seen)


def test_version_probe_failure_is_python_error(prov, monkeypatch):
    monkeypatch.setattr(ge, "_installed_pyghidra_version", _REAL_VERSION)
    monkeypatch.setattr(ge.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "no such interpreter"))
    s = ge._ensure_pyghidra(FAKE_PY)
    assert not s.ok and s.status == "python_error"


def test_version_probe_snippet_runs_on_a_real_interpreter():
    v = ge._installed_pyghidra_version(sys.executable)   # test-only: any real python works as a probe target
    assert v is None or v[0].isdigit()


# ---------------------------------------------------------------------------
# Status contract: exit code + output artifact decide; stdout/stderr text does not
# ---------------------------------------------------------------------------
LAUNCHER_INFO = (
    'Using Python command: "py -3.14"\n'
    "Using active virtual environment: C:\\x\\.ghidra-venv\n"
    "Name: pyghidra\nVersion: 3.0.2\nSummary: Python library for Ghidra\n"
    "Requires: jpype1, packaging\n"
)


def test_contract_A_rc0_valid_json_is_ok(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen([]))
    r = ge.run_ghidra_analysis(str(sample))
    assert set(r["_meta"]["script_status"].values()) == {"ok"}
    assert r["_meta"]["extraction_ok"] is True


def test_contract_B_rc0_missing_output_is_failure(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        [], outputs={"extract_functions.py": None}))
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"]["extract_functions.py"] in ("no_output", "script_failed")
    assert r["_meta"]["script_status"]["extract_functions.py"] != "ok"
    assert r["_meta"]["extraction_ok"] is False


def test_contract_C_rc0_malformed_json_is_failure(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    base = make_fake_popen([], outputs={})

    def popen(cmd, **kw):
        p = base(cmd, **kw)
        if _arg_after(cmd, "-postScript") == "extract_calls.py":
            (Path(_arg_after(cmd, "--output-dir")) / "extract_calls_output.json").write_text("[{bad")
        return p
    monkeypatch.setattr(ge.subprocess, "Popen", popen)
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"]["extract_calls.py"] in ("corrupt_output", "script_failed")
    assert r["_meta"]["extraction_ok"] is False
    assert r["functions"] and r["strings"]                     # partial results preserved


def test_contract_D_nonzero_exit_is_failure_even_with_output(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen([], stderr="boom", rc=3))
    r = ge.run_ghidra_analysis(str(sample))
    assert set(r["_meta"]["script_status"].values()) == {"process_failed"}
    assert r["_meta"]["extraction_ok"] is False


def test_contract_E_informational_launcher_output_is_not_failure(ghidra_home, monkeypatch):
    sample = ghidra_home[2]
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        [], stdout=LAUNCHER_INFO, stderr="INFO  something harmless\n"))
    r = ge.run_ghidra_analysis(str(sample))
    assert set(r["_meta"]["script_status"].values()) == {"ok"}
    assert r["_meta"]["extraction_ok"] is True
    assert ge._classify_script_run(0, LAUNCHER_INFO, "", True) == "ok"


def test_contract_E2_valid_output_beats_error_text_in_stdout_stderr_and_log(ghidra_home, monkeypatch):
    # e.g. a script prints an error line (such as a console-encoding failure on a
    # progress message) AFTER it already wrote its JSON artifact.
    sample = ghidra_home[2]
    noisy = "[GHIDRA][extract_functions] ERROR writing output: 'charmap' codec can't encode"
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        [], stdout=noisy, stderr="REPORT SCRIPT ERROR: x"))
    r = ge.run_ghidra_analysis(str(sample))
    assert set(r["_meta"]["script_status"].values()) == {"ok"}
    assert r["_meta"]["extraction_ok"] is True
    assert r["functions"] and r["calls"] and r["strings"]


def test_contract_F_timeout_still_intact(ghidra_home, monkeypatch, killed):
    sample = ghidra_home[2]
    calls = []
    monkeypatch.setattr(ge.subprocess, "Popen", make_fake_popen(
        calls, stdout=LAUNCHER_INFO, timeout_on="extract_functions.py"))
    r = ge.run_ghidra_analysis(str(sample))
    assert r["_meta"]["script_status"]["extract_functions.py"] == "timeout"
    assert r["_meta"]["script_status"]["extract_calls.py"] == "ok"
    assert r["_meta"]["extraction_ok"] is False and len(calls) == 3
    assert not Path(_arg_after(calls[0][0], "--output-dir")).parent.exists()
    assert killed == [FAKE_PID]
