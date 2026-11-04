#!/usr/bin/env python3
"""Guards on the release pipeline's Python invocation.

Both workflows run on self-hosted runners that do not agree about which
interpreter is first on PATH. One Windows runner resolved ``C:\\Python314``
even though setup-python had installed 3.11, which made ``pip install`` write
into the wrong environment and failed the build at the dependency step.

Bare ``pip`` and ``pyinstaller`` are therefore not allowed: every invocation
goes through ``python -m`` so the selected interpreter is always the one used.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RELEASE = ROOT / ".github" / "workflows" / "release-binaries.yml"
TESTS = ROOT / ".github" / "workflows" / "run-tests.yml"
WORKFLOWS = (RELEASE, TESTS)

# ``pip`` / ``pyinstaller`` invoked as a command, not via ``python -m`` and not
# as part of a longer word.
BARE_PIP = re.compile(
    r"^\s*(?:&&\s*|;\s*)?pip3?\s+(?:install|download|wheel|freeze)",
    re.MULTILINE,
)
# A bare command starts the line (optionally after "&&" / ";"), so
# "python -m PyInstaller" never matches.
BARE_PYINSTALLER = re.compile(
    r"^\s*(?:&&\s*|;\s*)?pyinstaller\s", re.IGNORECASE | re.MULTILINE
)


def _run_blocks(path: Path) -> str:
    """Every shell body in the workflow, parsed from YAML when available.

    Parsing the real structure keeps comments and prose from satisfying a
    check, and stops one ``run:`` block from swallowing the rest of the file.
    """
    text = path.read_text(encoding="utf-8")
    try:
        import yaml
    except ModuleNotFoundError:
        return text
    bodies: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "run" and isinstance(value, str):
                    bodies.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(yaml.safe_load(text) or {})
    return "\n".join(bodies)


class TestNoBareInterpreterCommands(unittest.TestCase):
    def test_release_has_no_bare_pip(self):
        offenders = BARE_PIP.findall(_run_blocks(RELEASE))
        self.assertEqual(offenders, [], msg="use 'python -m pip' in workflows")

    def test_release_has_no_bare_pyinstaller(self):
        offenders = BARE_PYINSTALLER.findall(_run_blocks(RELEASE))
        self.assertEqual(offenders, [], msg="use 'python -m PyInstaller'")

    def test_tests_workflow_has_no_bare_pip(self):
        offenders = BARE_PIP.findall(_run_blocks(TESTS))
        self.assertEqual(offenders, [], msg="use 'python -m pip' in workflows")


class TestReleaseBuildPinsInterpreter(unittest.TestCase):
    def setUp(self):
        self.text = RELEASE.read_text(encoding="utf-8")

    def test_build_installs_through_python_m(self):
        self.assertIn("python -m pip install -r requirements-build.txt", self.text)

    def test_both_platforms_build_through_python_m(self):
        blocks = _run_blocks(RELEASE)
        # Two build commands (Linux, Windows) plus one version probe.
        build_lines = [
            line for line in blocks.splitlines()
            if line.strip().startswith("python -m PyInstaller")
        ]
        self.assertEqual(len(build_lines), 3, msg=build_lines)

    def test_interpreter_is_logged_before_installing(self):
        log = self.text.index("Show interpreter")
        install = self.text.index("Install build dependencies")
        self.assertLess(log, install)
        block = self.text[log:install]
        self.assertIn("sys.executable", block)

    def test_pyinstaller_version_is_recorded(self):
        self.assertIn("python -m PyInstaller --version", self.text)


class TestReleaseSmokeStillWired(unittest.TestCase):
    def test_task_smoke_still_present(self):
        text = RELEASE.read_text(encoding="utf-8")
        self.assertIn("Smoke: binary runs a task list", text)
        self.assertIn("tasks/core.tasks", text)

    def test_workflows_are_valid_yaml(self):
        try:
            import yaml
        except ModuleNotFoundError:
            self.skipTest("pyyaml not installed")
        for path in WORKFLOWS:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertIn("jobs", doc, msg=str(path))

    def test_release_build_still_depends_on_tests(self):
        try:
            import yaml
        except ModuleNotFoundError:
            self.skipTest("pyyaml not installed")
        doc = yaml.safe_load(RELEASE.read_text(encoding="utf-8"))
        self.assertEqual(doc["jobs"]["build"]["needs"], "test")
        self.assertEqual(doc["jobs"]["release"]["needs"], "build")


if __name__ == "__main__":
    unittest.main()
