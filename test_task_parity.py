#!/usr/bin/env python3
"""Parity tests for the shipped task lists.

Every fixture is run over its corpus and compared against a committed baseline
snapshot. The point is regression protection: a change to the projection, the
evaluator or a fixture that alters row counts, columns or sample rows fails
here instead of shipping quietly.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import BloodBash as bb  # noqa: E402
import task_parity  # noqa: E402

TASKS_DIR = ROOT / "tasks"
BASELINE = TASKS_DIR / task_parity.BASELINE_NAME


def _corpus_for(name: str) -> Path:
    manifest = task_parity.load_manifest(TASKS_DIR)
    corpus = manifest.get(name) or manifest.get("*") or "testData/synthetic-corp-lab"
    path = Path(corpus)
    return path if path.is_absolute() else ROOT / path


class TestParityBaseline(unittest.TestCase):
    def test_baseline_exists(self):
        self.assertTrue(BASELINE.is_file(), msg="run tools/task_parity.py --write")

    def test_current_output_matches_baseline(self):
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        current = task_parity.collect(TASKS_DIR, ROOT / "testData" / "synthetic-corp-lab")
        problems = task_parity.compare(baseline, current)
        self.assertEqual(problems, [], msg="\n".join(problems))

    def test_second_run_is_identical(self):
        first = task_parity.collect(TASKS_DIR, ROOT / "testData" / "synthetic-corp-lab")
        second = task_parity.collect(TASKS_DIR, ROOT / "testData" / "synthetic-corp-lab")
        self.assertEqual(task_parity.compare(first, second), [])

    def test_compare_detects_row_count_drift(self):
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        current = json.loads(BASELINE.read_text(encoding="utf-8"))
        current["fixtures"][0]["tasks"][0]["rows"] += 1
        self.assertTrue(task_parity.compare(baseline, current))

    def test_compare_detects_column_drift(self):
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        current = json.loads(BASELINE.read_text(encoding="utf-8"))
        current["fixtures"][0]["tasks"][0].setdefault("columns", []).append("Extra")
        self.assertTrue(task_parity.compare(baseline, current))

    def test_compare_detects_sample_drift(self):
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        current = json.loads(BASELINE.read_text(encoding="utf-8"))
        current["fixtures"][0]["tasks"][0]["sample"] = [["changed"]]
        self.assertTrue(task_parity.compare(baseline, current))

    def test_compare_detects_status_drift(self):
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        current = json.loads(BASELINE.read_text(encoding="utf-8"))
        current["fixtures"][0]["tasks"][0]["status"] = "query-error"
        self.assertTrue(task_parity.compare(baseline, current))

    def test_compare_detects_removed_fixture(self):
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        current = json.loads(BASELINE.read_text(encoding="utf-8"))
        current["fixtures"] = current["fixtures"][1:]
        self.assertTrue(task_parity.compare(baseline, current))


class TestEveryFixtureRuns(unittest.TestCase):
    def test_no_parse_or_query_errors(self):
        for path in sorted(TASKS_DIR.glob("*.tasks")):
            specs = bb.parse_task_file(str(path))
            self.assertTrue(specs, msg=path.name)
            for spec in specs:
                self.assertTrue(spec.ok, msg=f"{path.name}:{spec.line_no}: {spec.error}")

    def test_every_fixture_produces_rows(self):
        for path in sorted(TASKS_DIR.glob("*.tasks")):
            corpus = _corpus_for(path.name)
            nodes = bb.load_json_dirs([str(corpus)])
            G, _ = bb.build_graph(nodes)
            projection = bb.build_bloodhound_projection(G)
            total_rows = 0
            for spec in bb.parse_task_file(str(path)):
                if not spec.ok or spec.is_sentinel:
                    continue
                total_rows += bb.execute_task_query(spec.query, projection).row_count
            self.assertGreater(total_rows, 0, msg=f"{path.name} returned no rows")


class TestParityCli(unittest.TestCase):
    def test_check_mode_passes(self):
        code = task_parity.main([
            "--corpus", str(ROOT / "testData" / "synthetic-corp-lab"), "--check",
        ])
        self.assertEqual(code, 0)

    def test_missing_task_dir_returns_2(self):
        code = task_parity.main(["--tasks", "/nonexistent/tasks", "--check"])
        self.assertEqual(code, 2)

    def test_missing_corpus_returns_2(self):
        code = task_parity.main(["--corpus", "/nonexistent/corpus", "--check"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
