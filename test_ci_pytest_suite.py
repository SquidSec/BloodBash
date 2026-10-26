#!/usr/bin/env python3
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIRED = (
    "test_bloodbash.py",
    "test_members_ingest.py",
    "test_detection_variations.py",
    "test_compromise_dossier.py",
    "test_synthetic_corpus.py",
    "test_ludus_collections.py",
    "test_real_data_reliability.py",
    "test_graph_cache.py",
    "test_owned_file.py",
    "test_golden_path.py",
    "test_deep_paths.py",
    "test_repo_hygiene.py",
    "test_ingest_edge_cases.py",
    "test_detector_fixes.py",
    "test_reporting_features.py",
    "test_coverage_additions.py",
    "test_version_consistency.py",
    "test_ci_pytest_suite.py",
)


def _pytest_invocation(text: str) -> str:
    blocks = re.findall(
        r"python(?:3)?\s+-m\s+pytest\s+((?:.|\n)*?)(?:\n\s*(?:#|- name:|timeout-minutes:)|$)",
        text,
    )
    return " ".join(blocks)


class TestCiPytestSuite(unittest.TestCase):
    def test_run_tests_lists_all_required_modules(self):
        text = (ROOT / ".github/workflows/run-tests.yml").read_text(encoding="utf-8")
        inv = _pytest_invocation(text)
        for name in REQUIRED:
            self.assertIn(name, inv, msg=f"run-tests.yml missing {name}")

    def test_release_lists_all_required_modules(self):
        text = (ROOT / ".github/workflows/release-binaries.yml").read_text(
            encoding="utf-8"
        )
        inv = _pytest_invocation(text)
        for name in REQUIRED:
            self.assertIn(name, inv, msg=f"release-binaries.yml missing {name}")

    def test_run_tests_covers_supported_python_versions(self):
        text = (ROOT / ".github/workflows/run-tests.yml").read_text(encoding="utf-8")
        self.assertIn("3.9", text)
        self.assertIn("3.11", text)
        self.assertRegex(text, r"python-version:\s*\$\{\{\s*matrix\.python-version")

    def test_release_test_job_uses_311(self):
        text = (ROOT / ".github/workflows/release-binaries.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('python-version: "3.11"', text)

    def test_release_can_be_rerun_without_a_push(self):
        # A failed release on main used to require an empty commit to retry.
        text = (ROOT / ".github/workflows/release-binaries.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_dispatch:", text)

    def test_release_uploads_both_assets_with_retries(self):
        text = (ROOT / ".github/workflows/release-binaries.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("release-final/bloodbash-linux-x64", text)
        self.assertIn("release-final/bloodbash-windows-x64.exe", text)
        # The artifact service and Releases API both failed transiently in Oct 2026.
        self.assertIn("Create GitHub Release (retry)", text)

    def test_release_retries_artifact_upload_and_download(self):
        text = (ROOT / ".github/workflows/release-binaries.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Upload build artifact (retry)", text)
        self.assertIn("Download Windows binary (retry)", text)


if __name__ == "__main__":
    unittest.main()
