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


if __name__ == "__main__":
    unittest.main()
