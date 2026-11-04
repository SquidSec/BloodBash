#!/usr/bin/env python3
"""Parser tests for PlumHound-style ``.tasks`` files.

A task line is a four-element Python list literal:
    ["Title", "FORMAT", "OutFile", "CYPHER"]
The parser reports per-line errors instead of aborting the file, so one bad
line cannot hide the rest of an engagement task list.
"""
from __future__ import annotations

import os
import tempfile
import unittest
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


def _write(contents: str) -> str:
    path = os.path.join(tempfile.mkdtemp(), "list.tasks")
    Path(path).write_text(contents, encoding="utf-8")
    return path


class TestTaskSpec(unittest.TestCase):
    def test_task_spec_holds_four_fields(self):
        spec = bb.TaskSpec(title="T", fmt="CSV", outfile="Out", query="MATCH (n) RETURN n")
        self.assertEqual(spec.title, "T")
        self.assertEqual(spec.fmt, "CSV")
        self.assertEqual(spec.outfile, "Out")
        self.assertEqual(spec.query, "MATCH (n) RETURN n")
        self.assertIsNone(spec.error)
        self.assertTrue(spec.ok)

    def test_spec_records_line_number(self):
        spec = bb.TaskSpec(title="T", fmt="CSV", outfile="Out", query="Q", line_no=7)
        self.assertEqual(spec.line_no, 7)

    def test_spec_with_error_is_not_ok(self):
        spec = bb.TaskSpec(title="", fmt="", outfile="", query="", error="bad line")
        self.assertFalse(spec.ok)

    def test_effective_outfile_appends_extension(self):
        spec = bb.TaskSpec(title="T", fmt="CSV", outfile="Domains", query="Q")
        self.assertEqual(spec.effective_outfile(), "Domains.csv")

    def test_effective_outfile_keeps_existing_extension(self):
        spec = bb.TaskSpec(title="T", fmt="HTML", outfile="Domains.html", query="Q")
        self.assertEqual(spec.effective_outfile(), "Domains.html")

    def test_stdout_has_no_output_file(self):
        spec = bb.TaskSpec(title="T", fmt="STDOUT", outfile="", query="Q")
        self.assertEqual(spec.effective_outfile(), "")


class TestParseTaskLine(unittest.TestCase):
    def test_parses_valid_line(self):
        spec = bb.parse_task_line('["Domains", "CSV", "Domains", "MATCH (n:Domain) RETURN n.name"]')
        self.assertTrue(spec.ok)
        self.assertEqual(spec.title, "Domains")
        self.assertEqual(spec.fmt, "CSV")
        self.assertEqual(spec.outfile, "Domains")
        self.assertIn("MATCH", spec.query)

    def test_normalizes_format_case(self):
        spec = bb.parse_task_line('["T", "csv", "Out", "Q"]')
        self.assertEqual(spec.fmt, "CSV")

    def test_accepts_known_plumhound_format_typo(self):
        spec = bb.parse_task_line('["T", "HTLMCSV", "Out", "Q"]')
        self.assertTrue(spec.ok)
        self.assertEqual(spec.fmt, "HTMLCSV")

    def test_unknown_format_is_an_error(self):
        spec = bb.parse_task_line('["T", "PDF", "Out", "Q"]')
        self.assertFalse(spec.ok)
        self.assertIn("PDF", spec.error)

    def test_rejects_three_elements(self):
        spec = bb.parse_task_line('["T", "CSV", "Out"]')
        self.assertFalse(spec.ok)
        self.assertIn("4", spec.error)

    def test_rejects_non_list(self):
        spec = bb.parse_task_line('"just a string"')
        self.assertFalse(spec.ok)

    def test_rejects_invalid_python_literal(self):
        spec = bb.parse_task_line('["T", "CSV", "Out", "unterminated')
        self.assertFalse(spec.ok)

    def test_rejects_empty_query(self):
        spec = bb.parse_task_line('["T", "CSV", "Out", ""]')
        self.assertFalse(spec.ok)
        self.assertIn("query", spec.error.lower())

    def test_report_index_sentinel_is_accepted(self):
        spec = bb.parse_task_line('["Index", "HTML", "index", "REPORT-INDEX"]')
        self.assertTrue(spec.ok)
        self.assertTrue(spec.is_sentinel)
        self.assertEqual(spec.fmt, "HTML")

    def test_zip_tasks_sentinel_is_accepted(self):
        spec = bb.parse_task_line('["Zip", "ZIP", "reports", "ZIP-TASKS"]')
        self.assertTrue(spec.ok)
        self.assertTrue(spec.is_sentinel)

    def test_sentinel_accepts_zero_element_output(self):
        spec = bb.parse_task_line('["Zip", "ZIP", "", "ZIP-TASKS"]')
        self.assertTrue(spec.ok)

    def test_single_quoted_cypher_is_accepted(self):
        spec = bb.parse_task_line("""["T", "CSV", "Out", "MATCH (n) WHERE n.name = 'ADMIN' RETURN n"]""")
        self.assertTrue(spec.ok)

    def test_line_number_is_recorded(self):
        spec = bb.parse_task_line('["T", "CSV", "Out", "Q"]', line_no=12)
        self.assertEqual(spec.line_no, 12)


class TestParseTaskFile(unittest.TestCase):
    def test_parses_multiple_tasks(self):
        path = _write(
            '["A", "CSV", "a", "MATCH (n:User) RETURN n.name"]\n'
            '["B", "HTML", "b", "MATCH (n:Group) RETURN n.name"]\n'
        )
        specs = bb.parse_task_file(path)
        self.assertEqual([s.title for s in specs], ["A", "B"])

    def test_skips_blank_lines_without_numbering_them(self):
        path = _write('\n\n["A", "CSV", "a", "Q"]\n\n')
        specs = bb.parse_task_file(path)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].line_no, 3)

    def test_skips_hash_comments(self):
        path = _write('# a comment\n["A", "CSV", "a", "Q"]\n')
        specs = bb.parse_task_file(path)
        self.assertEqual(len(specs), 1)

    def test_skips_double_slash_comments(self):
        path = _write('// a comment\n["A", "CSV", "a", "Q"]\n')
        specs = bb.parse_task_file(path)
        self.assertEqual(len(specs), 1)

    def test_bad_line_does_not_stop_later_lines(self):
        path = _write(
            '["A", "CSV", "a", "Q"]\n'
            'this is not a task\n'
            '["C", "CSV", "c", "Q"]\n'
        )
        specs = bb.parse_task_file(path)
        self.assertEqual(len(specs), 3)
        self.assertTrue(specs[0].ok)
        self.assertFalse(specs[1].ok)
        self.assertEqual(specs[1].line_no, 2)
        self.assertTrue(specs[2].ok)

    def test_utf8_bom_is_tolerated(self):
        path = _write('\ufeff["A", "CSV", "a", "Q"]\n')
        specs = bb.parse_task_file(path)
        self.assertTrue(specs[0].ok)

    def test_windows_line_endings_are_tolerated(self):
        path = _write('["A", "CSV", "a", "Q"]\r\n["B", "CSV", "b", "Q"]\r\n')
        self.assertEqual(len(bb.parse_task_file(path)), 2)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            bb.parse_task_file("/nonexistent/list.tasks")

    def test_empty_file_returns_no_tasks(self):
        self.assertEqual(bb.parse_task_file(_write("")), [])

    def test_summarize_counts_errors(self):
        path = _write('["A", "CSV", "a", "Q"]\nbroken\n')
        summary = bb.summarize_task_list(bb.parse_task_file(path))
        self.assertEqual(summary["tasks"], 2)
        self.assertEqual(summary["valid"], 1)
        self.assertEqual(summary["errors"], 1)


class TestTaskListValidateCli(unittest.TestCase):
    def test_valid_list_exits_zero(self):
        path = _write('["A", "CSV", "a", "Q"]\n')
        code = bb.validate_task_list_cli([path], prog="bloodbash")
        self.assertEqual(code, 0)

    def test_invalid_list_exits_two(self):
        path = _write('broken line\n')
        code = bb.validate_task_list_cli([path], prog="bloodbash")
        self.assertEqual(code, 2)

    def test_prints_task_table(self):
        path = _write('["Domains", "CSV", "Domains", "MATCH (n:Domain) RETURN n.name"]\n')
        out = _capture(bb.validate_task_list_cli, [path], prog="bloodbash")
        self.assertIn("Domains", out)
        self.assertIn("CSV", out)

    def test_prints_line_number_for_error(self):
        path = _write('["A", "CSV", "a", "Q"]\nbroken\n')
        out = _capture(bb.validate_task_list_cli, [path], prog="bloodbash")
        self.assertIn("2", out)

    def test_multiple_files_are_summarized_together(self):
        a = _write('["A", "CSV", "a", "Q"]\n')
        b = _write('["B", "CSV", "b", "Q"]\n')
        out = _capture(bb.validate_task_list_cli, [a, b], prog="bloodbash")
        self.assertIn("2", out)


class TestParserContractOnRealShape(unittest.TestCase):
    """Lines taken from the documented PlumHound format, authored independently."""

    SAMPLE = (
        '["Domains", "HTMLCSV", "Domains", "MATCH (n:Domain) return n.name as Domain"]\n'
        '["Domain Controllers", "HTMLCSV", "DomainControllers", '
        '"MATCH (c:Computer)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH \'-516\' '
        'RETURN c.name as Hostname"]\n'
        '["Admin Groups", "CSV", "AdminGroups", '
        '"Match (n:Group) WHERE n.name CONTAINS \'ADMIN\' return n.name as Name"]\n'
        '["Index", "HTML", "index.html", "REPORT-INDEX"]\n'
    )

    def test_shape_matches_documented_format(self):
        specs = bb.parse_task_file(_write(self.SAMPLE))
        self.assertEqual(len(specs), 4)
        self.assertTrue(all(s.ok for s in specs), msg=[s.error for s in specs])
        self.assertEqual(specs[0].effective_outfile(), "Domains.html")
        self.assertEqual(specs[-1].query, "REPORT-INDEX")

    def test_queries_survive_unchanged(self):
        specs = bb.parse_task_file(_write(self.SAMPLE))
        self.assertIn("ENDS WITH '-516'", specs[1].query)
        self.assertIn("CONTAINS 'ADMIN'", specs[2].query)


if __name__ == "__main__":
    unittest.main()
