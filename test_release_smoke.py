#!/usr/bin/env python3
"""Guards on the release pipeline.

A published binary must be able to run a task list. The release workflow builds
one-file binaries, so this suite checks that the workflow exercises ``--tasks``
against a sample collection before the Release step runs.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github" / "workflows" / "release-binaries.yml"


def _text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


class TestReleaseSmoke(unittest.TestCase):
    def test_task_smoke_step_exists(self):
        self.assertIn("Smoke: binary runs a task list", _text())

    def test_task_smoke_runs_after_the_build_step(self):
        text = _text()
        build = text.index("Build binary (Linux)")
        smoke = text.index("Smoke: binary runs a task list")
        release = text.index("name: Create GitHub Release")
        self.assertLess(build, smoke)
        self.assertLess(smoke, release)

    def test_task_smoke_uses_a_shipped_fixture(self):
        text = _text()
        smoke = text.index("Smoke: binary runs a task list")
        block = text[smoke:smoke + 1600]
        self.assertIn("tasks/core.tasks", block)

    def test_task_smoke_asserts_output_files(self):
        text = _text()
        smoke = text.index("Smoke: binary runs a task list")
        block = text[smoke:smoke + 1600]
        self.assertIn("Domains.csv", block)
        self.assertIn("index.csv", block)

    def test_task_smoke_validates_the_fixture(self):
        text = _text()
        smoke = text.index("Smoke: binary runs a task list")
        block = text[smoke:smoke + 1600]
        self.assertIn("--tasks-validate", block)

    def test_release_notes_mention_task_lists(self):
        text = _text()
        self.assertIn("task list", text.lower())

    def test_workflow_is_still_valid_yaml(self):
        try:
            import yaml
        except ModuleNotFoundError:
            self.skipTest("pyyaml not installed")
        doc = yaml.safe_load(_text())
        self.assertIn("jobs", doc)
        for job in ("test", "build", "release"):
            self.assertIn(job, doc["jobs"])

    def test_build_job_still_needs_test(self):
        try:
            import yaml
        except ModuleNotFoundError:
            self.skipTest("pyyaml not installed")
        doc = yaml.safe_load(_text())
        self.assertEqual(doc["jobs"]["build"]["needs"], "test")
        self.assertEqual(doc["jobs"]["release"]["needs"], "build")


class TestReadmeReleaseDocs(unittest.TestCase):
    def test_readme_documents_task_lists_in_flags(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("`--tasks FILE…`", text)

    def test_readme_documents_supported_subset(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Supported query subset", text)

    def test_cookbook_documents_task_lists(self):
        text = (ROOT / "docs" / "cookbook.md").read_text(encoding="utf-8")
        self.assertIn("--tasks", text)
        self.assertIn("task-reports", text)


if __name__ == "__main__":
    unittest.main()
