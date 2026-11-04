#!/usr/bin/env python3
"""Tests for task result writers.

Writers turn a query result (columns + rows) into the same deliverables the
CSV pack already produces: one CSV or HTML file per task, an index, and a zip.
"""
from __future__ import annotations

import csv
import os
import tempfile
import unittest
import zipfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

import BloodBash as bb


def _capture(fn, *args, **kwargs) -> str:
    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=False, legacy_windows=False)
    with patch.object(bb.console, "print", side_effect=con.print):
        fn(*args, **kwargs)
    return buf.getvalue()


def _result(rows=None, columns=None):
    return bb.TaskResult(
        title="Domains",
        columns=columns or ["Domain", "DNS"],
        rows=rows if rows is not None else [["CORP.LOCAL", "corp.local"]],
        query="MATCH (n:Domain) RETURN n.name AS Domain, n.domain AS DNS",
    )


class TestTaskResult(unittest.TestCase):
    def test_row_count(self):
        self.assertEqual(_result().row_count, 1)

    def test_empty_result_has_zero_rows(self):
        self.assertEqual(_result(rows=[]).row_count, 0)

    def test_status_defaults_to_ok(self):
        self.assertEqual(_result().status, "ok")

    def test_failed_result_carries_error(self):
        res = bb.TaskResult(title="T", columns=[], rows=[], query="Q", status="error", error="boom")
        self.assertEqual(res.status, "error")
        self.assertEqual(res.error, "boom")


class TestCsvWriter(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_writes_header_and_rows(self):
        path = bb.write_task_csv(_result(), self.dir, "Domains.csv")
        rows = list(csv.reader(Path(path).read_text(encoding="utf-8").splitlines()))
        self.assertEqual(rows[0], ["Domain", "DNS"])
        self.assertEqual(rows[1], ["CORP.LOCAL", "corp.local"])

    def test_empty_result_writes_header_only(self):
        path = bb.write_task_csv(_result(rows=[]), self.dir, "Empty.csv")
        rows = list(csv.reader(Path(path).read_text(encoding="utf-8").splitlines()))
        self.assertEqual(rows, [["Domain", "DNS"]])

    def test_formula_injection_is_neutralized(self):
        res = _result(rows=[["=cmd|calc", "x"]])
        path = bb.write_task_csv(res, self.dir, "Inj.csv")
        text = Path(path).read_text(encoding="utf-8")
        # write_csv_file prefixes dangerous cells with an apostrophe
        self.assertIn("'=cmd", text)
        self.assertNotIn(",=cmd", text)

    def test_creates_missing_directory(self):
        nested = os.path.join(self.dir, "a", "b")
        bb.write_task_csv(_result(), nested, "x.csv")
        self.assertTrue(os.path.isfile(os.path.join(nested, "x.csv")))


class TestHtmlWriter(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_writes_table_with_columns(self):
        path = bb.write_task_html(_result(), self.dir, "Domains.html")
        html = Path(path).read_text(encoding="utf-8")
        self.assertIn("Domains", html)
        self.assertIn("<table", html)
        self.assertIn("CORP.LOCAL", html)

    def test_escapes_html_in_cells(self):
        res = _result(rows=[["<script>alert(1)</script>", "x"]])
        path = bb.write_task_html(res, self.dir, "X.html")
        html = Path(path).read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_includes_the_query_for_traceability(self):
        path = bb.write_task_html(_result(), self.dir, "Q.html")
        html = Path(path).read_text(encoding="utf-8")
        self.assertIn("MATCH (n:Domain)", html)

    def test_empty_result_still_renders(self):
        path = bb.write_task_html(_result(rows=[]), self.dir, "E.html")
        self.assertIn("<table", Path(path).read_text(encoding="utf-8"))


class TestStdoutWriter(unittest.TestCase):
    def test_prints_rows(self):
        out = _capture(bb.write_task_stdout, _result())
        self.assertIn("CORP.LOCAL", out)

    def test_prints_title(self):
        out = _capture(bb.write_task_stdout, _result())
        self.assertIn("Domains", out)

    def test_empty_result_prints_no_rows_message(self):
        out = _capture(bb.write_task_stdout, _result(rows=[]))
        self.assertIn("no rows", out.lower())


class TestWriteTaskResult(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_csv_format_writes_csv(self):
        written = bb.write_task_result(_result(), bb.TaskSpec("Domains", "CSV", "Domains", "Q"), self.dir)
        self.assertEqual(len(written), 1)
        self.assertTrue(written[0].endswith("Domains.csv"))

    def test_html_format_writes_html(self):
        written = bb.write_task_result(_result(), bb.TaskSpec("Domains", "HTML", "Domains", "Q"), self.dir)
        self.assertTrue(written[0].endswith("Domains.html"))

    def test_htmlcsv_writes_both(self):
        written = bb.write_task_result(_result(), bb.TaskSpec("Domains", "HTMLCSV", "Domains", "Q"), self.dir)
        suffixes = sorted(Path(p).suffix for p in written)
        self.assertEqual(suffixes, [".csv", ".html"])

    def test_stdout_writes_nothing(self):
        written = bb.write_task_result(_result(), bb.TaskSpec("Domains", "STDOUT", "", "Q"), self.dir)
        self.assertEqual(written, [])

    def test_default_filename_derived_from_title(self):
        written = bb.write_task_result(_result(), bb.TaskSpec("Domain Trusts", "CSV", "", "Q"), self.dir)
        self.assertTrue(written[0].endswith("Domain_Trusts.csv"))

    def test_traversal_in_outfile_is_neutralized(self):
        written = bb.write_task_result(
            _result(), bb.TaskSpec("X", "CSV", "../../etc/passwd", "Q"), self.dir
        )
        self.assertTrue(written[0].startswith(os.path.abspath(self.dir)))

    def test_failed_result_writes_no_files(self):
        res = bb.TaskResult(title="T", columns=[], rows=[], query="Q", status="error", error="boom")
        self.assertEqual(bb.write_task_result(res, bb.TaskSpec("T", "CSV", "T", "Q"), self.dir), [])


class TestIndexWriter(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_index_lists_every_task_with_row_counts(self):
        results = [
            (_result(), bb.TaskSpec("Domains", "CSV", "Domains", "Q"), ["/x/Domains.csv"]),
            (_result(rows=[]), bb.TaskSpec("Empty", "CSV", "Empty", "Q"), ["/x/Empty.csv"]),
        ]
        path = bb.write_task_index(results, self.dir)
        rows = list(csv.reader(Path(path).read_text(encoding="utf-8").splitlines()))
        self.assertEqual(rows[0][:3], ["Title", "Format", "Rows"])
        self.assertEqual(rows[1][0], "Domains")
        self.assertEqual(rows[1][2], "1")
        self.assertEqual(rows[2][2], "0")

    def test_index_html_links_each_output(self):
        results = [(_result(), bb.TaskSpec("Domains", "CSV", "Domains", "Q"), ["/x/Domains.csv"])]
        bb.write_task_index(results, self.dir)
        html = Path(os.path.join(self.dir, "index.html")).read_text(encoding="utf-8")
        self.assertIn("Domains.csv", html)

    def test_index_includes_failed_tasks(self):
        failed = bb.TaskResult(title="Bad", columns=[], rows=[], query="Q", status="error", error="boom")
        results = [(failed, bb.TaskSpec("Bad", "CSV", "Bad", "Q"), [])]
        path = bb.write_task_index(results, self.dir)
        text = Path(path).read_text(encoding="utf-8")
        self.assertIn("Bad", text)
        self.assertIn("error", text.lower())


class TestZipWriter(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_zips_generated_files(self):
        bb.write_task_csv(_result(), self.dir, "Domains.csv")
        zip_path = bb.zip_task_outputs(self.dir, os.path.join(tempfile.mkdtemp(), "pack.zip"))
        with zipfile.ZipFile(zip_path) as zf:
            self.assertIn("Domains.csv", zf.namelist())

    def test_zip_skips_the_archive_itself(self):
        bb.write_task_csv(_result(), self.dir, "A.csv")
        zip_path = os.path.join(self.dir, "self.zip")
        bb.zip_task_outputs(self.dir, zip_path)
        with zipfile.ZipFile(zip_path) as zf:
            self.assertNotIn("self.zip", zf.namelist())


class TestRunTaskSpecs(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_sentinels_are_handled_without_writing_rows(self):
        specs = [
            bb.TaskSpec("Domains", "CSV", "Domains", "Q"),
            bb.TaskSpec("Index", "HTML", "index", "REPORT-INDEX"),
        ]
        calls = []

        def fake_execute(query, projection):
            calls.append(query)
            return _result()

        written = bb.run_task_specs(specs, None, self.dir, execute=fake_execute)
        self.assertEqual(calls, ["Q"])
        names = sorted(Path(p).name for p in written)
        self.assertIn("Domains.csv", names)
        self.assertIn("index.csv", names)

    def test_failing_task_does_not_stop_the_run(self):
        specs = [
            bb.TaskSpec("Bad", "CSV", "Bad", "BAD QUERY"),
            bb.TaskSpec("Good", "CSV", "Good", "Q"),
        ]

        def fake_execute(query, projection):
            if query == "BAD QUERY":
                raise ValueError("nope")
            return _result()

        written = bb.run_task_specs(specs, None, self.dir, execute=fake_execute)
        self.assertTrue(any(p.endswith("Good.csv") for p in written))

    def test_parsed_error_specs_are_reported_not_written(self):
        specs = [
            bb.TaskSpec("", "", "", "", error="broken line"),
            bb.TaskSpec("Good", "CSV", "Good", "Q"),
        ]
        written = bb.run_task_specs(specs, None, self.dir, execute=lambda q, p: _result())
        self.assertTrue(all(not p.endswith(".html") or "index" in p for p in written))

    def test_zip_sentinel_creates_archive(self):
        specs = [
            bb.TaskSpec("Domains", "CSV", "Domains", "Q"),
            bb.TaskSpec("Zip", "ZIP", "pack", "ZIP-TASKS"),
        ]
        bb.run_task_specs(specs, None, self.dir, execute=lambda q, p: _result())
        self.assertTrue(os.path.isfile(os.path.join(self.dir, "pack.zip")))


if __name__ == "__main__":
    unittest.main()
