"""
tests/test_capa_ruleset_integrity.py

Focused CAPA tests. No real capa.exe is required.
Plain unittest: runs with `python -m unittest` and is collected by pytest.

1. Ruleset integrity - guards against capa's "duplicate rule name" failure,
   which occurs when backend/capa-rules contains the same rules twice (for
   example a stale copy nested in a rules/ sub-folder). capa walks the whole
   directory passed to -r and aborts on the first repeated rule name.
2. Engine failure modes - every capa failure must come back as a structured
   result and never raise, so the pipeline continues with Radare2 / Ghidra.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

from engines.capa_engine import capa_engine  # noqa: E402


# =============================================================================
# Helper: mirrors capa's own rule collection (walk dir, skip .git*, reject a
# repeated rule.meta.name).
# =============================================================================

def scan_ruleset(root):
    """Return (rule_count, {name: [paths]} for duplicated names, [malformed paths])."""
    names, malformed, count = {}, [], 0
    for dirpath, dirnames, filenames in os.walk(str(root)):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".github")]
        for fn in filenames:
            if not fn.endswith(".yml"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8") as fh:
                    name = yaml.safe_load(fh)["rule"]["meta"]["name"]
            except Exception:
                malformed.append(path)
                continue
            count += 1
            names.setdefault(name, []).append(path)
    return count, {n: p for n, p in names.items() if len(p) > 1}, malformed


def write_rule(directory, filename, name):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(
        "rule:\n  meta:\n    name: %s\n    scope: function\n  features:\n    - api: CreateFileA\n" % name,
        encoding="utf-8",
    )


# =============================================================================
# 1. Ruleset integrity
# =============================================================================

@unittest.skipIf(yaml is None, "PyYAML not installed")
class RulesetIntegrityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def test_valid_ruleset_has_no_duplicates(self):
        write_rule(self.root / "host-interaction", "a.yml", "create file")
        write_rule(self.root / "communication", "b.yml", "reference dns server")
        self.assertEqual(scan_ruleset(self.root), (2, {}, []))

    def test_nested_copy_of_ruleset_is_detected_as_duplicates(self):
        """The real-world failure: the same rules present twice in one tree."""
        write_rule(self.root / "host-interaction", "a.yml", "create file")
        write_rule(self.root / "communication", "b.yml", "reference dns server")
        shutil.copytree(self.root / "host-interaction", self.root / "rules" / "host-interaction")
        shutil.copytree(self.root / "communication", self.root / "rules" / "communication")
        _, dups, _ = scan_ruleset(self.root)
        self.assertEqual(set(dups), {"create file", "reference dns server"})

    def test_malformed_rule_is_reported_not_raised(self):
        write_rule(self.root, "ok.yml", "good rule")
        (self.root / "broken.yml").write_text("rule: [unclosed", encoding="utf-8")
        count, dups, bad = scan_ruleset(self.root)
        self.assertEqual((count, dups, len(bad)), (1, {}, 1))

    def test_git_metadata_is_not_scanned_as_rules(self):
        write_rule(self.root, "a.yml", "rule a")
        write_rule(self.root / ".git" / "x", "a.yml", "rule a")
        write_rule(self.root / ".github" / "x", "a.yml", "rule a")
        self.assertEqual(scan_ruleset(self.root)[1], {})

    @unittest.skipUnless((BACKEND_DIR / "capa-rules").is_dir(), "backend/capa-rules not present")
    def test_vendored_capa_rules_have_no_duplicate_names(self):
        """Regression guard for the vendored ruleset ARISE passes to capa -r."""
        count, dups, bad = scan_ruleset(BACKEND_DIR / "capa-rules")
        self.assertGreater(count, 0, "no rules found under backend/capa-rules")
        self.assertFalse(
            dups,
            "duplicate rule names (e.g. a nested copy such as capa-rules/rules/): %s" % sorted(dups)[:5],
        )
        self.assertFalse(bad, "unparseable rule files: %s" % bad[:5])


# =============================================================================
# 2. Engine failure modes (subprocess mocked)
# =============================================================================

class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


SAMPLE_OK = {
    "rules": {
        "persist via Run registry key": {
            "meta": {
                "name": "persist via Run registry key",
                "att&ck": [{"id": "T1547.001", "tactic": "Persistence",
                            "technique": "Boot or Logon Autostart Execution"}],
            },
            "matches": {},
        }
    }
}


class EngineFailureModeTests(unittest.TestCase):
    def setUp(self):
        # capa "exists"; each test decides what subprocess.run does.
        p = mock.patch.object(capa_engine.os.path, "exists", return_value=True)
        p.start()
        self.addCleanup(p.stop)

    def _run(self, **run_kwargs):
        with mock.patch.object(capa_engine.subprocess, "run", **run_kwargs) as m:
            res = capa_engine.run_capa_analysis("sample.bin")
        return res, m

    def test_invalid_ruleset_returns_structured_failure_not_exception(self):
        """Exact production failure: capa exits non-zero on a duplicate rule name."""
        stderr = "ERROR capa: invalid rule: duplicate rule name: reference AES constants"
        res, _ = self._run(return_value=_Proc(returncode=1, stderr=stderr))

        self.assertEqual((res["status"], res["reason"]), ("failed", "capa_nonzero_exit"))
        self.assertIn("duplicate rule name", res["detail"])
        # keys analysis.py relies on are always present and empty
        self.assertEqual(res["capabilities"], [])
        self.assertEqual(res["normalized_capabilities"], [])
        self.assertEqual(res["function_capabilities"], {})
        summary = capa_engine.get_capa_status_summary(res)
        self.assertIs(summary["enabled"], False)
        self.assertEqual(summary["capabilities_found"], 0)

    def test_valid_ruleset_reports_success(self):
        res, _ = self._run(return_value=_Proc(0, stdout=json.dumps(SAMPLE_OK)))
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["capabilities_detected"], 1)
        self.assertEqual(res["capabilities"], ["registry_persistence"])
        self.assertEqual(res["mitre_techniques"], ["T1547.001"])
        self.assertIs(capa_engine.get_capa_status_summary(res)["enabled"], True)

    def test_timeout_degrades_gracefully(self):
        res, _ = self._run(side_effect=subprocess.TimeoutExpired("capa", 180))
        self.assertEqual((res["status"], res["reason"]), ("failed", "capa_timeout"))
        self.assertEqual(res["capabilities"], [])

    def test_non_json_output_degrades_gracefully(self):
        res, _ = self._run(return_value=_Proc(0, stdout="not json"))
        self.assertEqual((res["status"], res["reason"]), ("failed", "capa_json_parse_error"))

    def test_unexpected_exception_degrades_gracefully(self):
        res, _ = self._run(side_effect=OSError("cannot execute"))
        self.assertEqual((res["status"], res["reason"]), ("failed", "capa_exception"))

    def test_missing_executable_degrades_gracefully(self):
        with mock.patch.object(capa_engine.os.path, "exists", return_value=False):
            res = capa_engine.run_capa_analysis("sample.bin")
        self.assertEqual((res["status"], res["reason"]), ("failed", "capa_exe_not_found"))

        def test_command_is_list_no_shell_with_timeout_and_repo_rules(self):
            _, m = self._run(return_value=_Proc(0, stdout=json.dumps(SAMPLE_OK)))
            cmd, kwargs = m.call_args[0][0], m.call_args[1]
            self.assertIsInstance(cmd, list)
            self.assertFalse(kwargs.get("shell"))
            self.assertEqual(kwargs.get("timeout"), 180)

            rules_arg = cmd[cmd.index("-r") + 1].replace("\\", "/")
            self.assertTrue(rules_arg.endswith("backend/capa-rules"))

            self.assertIn("-s", cmd)
            signatures_arg = cmd[cmd.index("-s") + 1].replace("\\", "/")
            self.assertTrue(signatures_arg.endswith("backend/capa-signatures"))


if __name__ == "__main__":
    unittest.main()
