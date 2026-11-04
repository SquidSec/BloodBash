#!/usr/bin/env python3
"""End-to-end tests for the ``--tasks`` CLI surface."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

import BloodBash as bb

ROOT = Path(__file__).resolve().parent
SAMPLE = str(ROOT / "SampleSharphoundADData")


def _tasks_file(contents: str) -> str:
    path = os.path.join(tempfile.mkdtemp(), "list.tasks")
    Path(path).write_text(contents, encoding="utf-8")
    return path


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _capture(fn, *args, **kwargs) -> str:
    buf = StringIO()
    con = Console(file=buf, width=140, force_terminal=False, legacy_windows=False)
    with patch.object(bb.console, "print", side_effect=con.print):
        fn(*args, **kwargs)
    return buf.getvalue()


class TestTaskFlags(unittest.TestCase):
    def setUp(self):
        self.parser = bb.build_arg_parser()

    def test_tasks_flag_is_repeatable(self):
        args = self.parser.parse_args(["./data", "--tasks", "a.tasks", "--tasks", "b.tasks"])
        # action="append" with nargs="+" keeps one group per flag
        self.assertEqual(args.tasks, [["a.tasks"], ["b.tasks"]])

    def test_tasks_out_dir(self):
        args = self.parser.parse_args(["./data", "--tasks", "a.tasks", "--tasks-out", "/tmp/out"])
        self.assertEqual(args.tasks_out, "/tmp/out")

    def test_tasks_strict_flag(self):
        args = self.parser.parse_args(["./data", "--tasks", "a.tasks", "--tasks-strict"])
        self.assertTrue(args.tasks_strict)

    def test_tasks_list_flag(self):
        args = self.parser.parse_args(["--tasks-list"])
        self.assertTrue(args.tasks_list)

    def test_defaults_are_off(self):
        args = self.parser.parse_args(["./data"])
        self.assertIsNone(args.tasks)
        self.assertIsNone(args.tasks_out)
        self.assertFalse(args.tasks_strict)

    def test_tasks_alone_counts_as_explicit_intent(self):
        args = self.parser.parse_args(["./data", "--tasks", "a.tasks"])
        self.assertTrue(bb.cli_has_explicit_analysis_intent(args))

    def test_tasks_and_all_together(self):
        args = self.parser.parse_args(["./data", "--tasks", "a.tasks", "--all"])
        self.assertTrue(args.all)
        self.assertEqual(args.tasks, [["a.tasks"]])

    def test_tasks_format_override(self):
        args = self.parser.parse_args(["./data", "--tasks", "a.tasks", "--tasks-format", "CSV"])
        self.assertEqual(args.tasks_format, "CSV")

    def test_bad_format_override_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.parser.parse_args(["./data", "--tasks", "a.tasks", "--tasks-format", "PDF"])


class TestHelpListsTaskFlags(unittest.TestCase):
    def test_advanced_help_mentions_tasks(self):
        out = _capture(bb.print_structured_help, prog="bloodbash", advanced=True)
        for flag in ("--tasks", "--tasks-out", "--tasks-strict", "--tasks-validate"):
            self.assertIn(flag, out)

    def test_examples_include_a_task_run(self):
        out = _capture(bb.print_structured_help, prog="bloodbash", advanced=True)
        self.assertIn("--tasks", out)
        self.assertIn(".tasks", out)


class TestRunTasksForCli(unittest.TestCase):
    def test_returns_written_files(self):
        path = _tasks_file('["Domains", "CSV", "Domains", "MATCH (n:Domain) RETURN n.name AS Domain"]\n')
        out = tempfile.mkdtemp()
        written = bb.run_tasks_for_cli([path], None, out, strict=False)
        self.assertTrue(any(p.endswith("Domains.csv") for p in written))

    def test_strict_raises_on_task_error(self):
        path = _tasks_file('["Bad", "CSV", "Bad", "SELECT nonsense"]\n')
        with self.assertRaises(bb.TaskQueryError):
            bb.run_tasks_for_cli([path], None, tempfile.mkdtemp(), strict=True)

    def test_non_strict_continues_after_error(self):
        path = _tasks_file(
            '["Bad", "CSV", "Bad", "SELECT nonsense"]\n'
            '["Good", "CSV", "Good", "MATCH (n:Domain) RETURN n.name"]\n'
        )
        written = bb.run_tasks_for_cli([path], None, tempfile.mkdtemp(), strict=False)
        self.assertTrue(any(p.endswith("Good.csv") for p in written))

    def test_strict_raises_on_parse_error(self):
        path = _tasks_file("this is not a task\n")
        with self.assertRaises(bb.TaskListError):
            bb.run_tasks_for_cli([path], None, tempfile.mkdtemp(), strict=True)

    def test_multiple_files_share_one_output_dir(self):
        a = _tasks_file('["A", "CSV", "A", "MATCH (n:Domain) RETURN n.name"]\n')
        b = _tasks_file('["B", "CSV", "B", "MATCH (n:Group) RETURN n.name"]\n')
        out = tempfile.mkdtemp()
        bb.run_tasks_for_cli([a, b], None, out, strict=False)
        self.assertTrue(os.path.isfile(os.path.join(out, "A.csv")))
        self.assertTrue(os.path.isfile(os.path.join(out, "B.csv")))

    def test_format_override_applies_to_every_task(self):
        path = _tasks_file('["Domains", "HTML", "Domains", "MATCH (n:Domain) RETURN n.name"]\n')
        out = tempfile.mkdtemp()
        bb.run_tasks_for_cli([path], None, out, strict=False, fmt_override="CSV")
        self.assertTrue(os.path.isfile(os.path.join(out, "Domains.csv")))


class TestBundledTaskLists(unittest.TestCase):
    def test_shipped_example_lists_parse(self):
        directory = ROOT / "tasks"
        self.assertTrue(directory.is_dir(), msg="tasks/ example lists are missing")
        paths = sorted(directory.glob("*.tasks"))
        self.assertTrue(paths)
        for path in paths:
            specs = bb.parse_task_file(str(path))
            self.assertTrue(specs, msg=str(path))
            broken = [s.error for s in specs if not s.ok]
            self.assertFalse(broken, msg=f"{path}: {broken}")

    def test_catalog_lists_examples(self):
        rows = bb.list_bundled_task_lists()
        self.assertTrue(rows)
        self.assertTrue(all(os.path.isfile(r["path"]) for r in rows))

    def test_catalog_prints_table(self):
        out = _capture(bb.print_bundled_task_lists)
        self.assertIn(".tasks", out)


class TestCliEndToEnd(unittest.TestCase):
    def test_cli_runs_a_task_list_against_sample_data(self):
        path = _tasks_file(
            '["Domains", "CSV", "Domains", "MATCH (n:Domain) RETURN n.name AS Domain"]\n'
        )
        out = tempfile.mkdtemp()
        proc = subprocess.run(
            [sys.executable, str(ROOT / "BloodBash.py"), SAMPLE,
             "--tasks", path, "--tasks-out", out, "--no-cache"],
            capture_output=True, text=True, env=_env(), timeout=600,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout[-3000:] + proc.stderr[-3000:])
        self.assertTrue(os.path.isfile(os.path.join(out, "Domains.csv")))
        self.assertTrue(os.path.isfile(os.path.join(out, "index.csv")))

    def test_cli_validate_exit_code(self):
        path = _tasks_file("nonsense\n")
        proc = subprocess.run(
            [sys.executable, str(ROOT / "BloodBash.py"), "--tasks-validate", path],
            capture_output=True, text=True, env=_env(), timeout=180,
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
