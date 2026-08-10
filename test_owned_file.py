#!/usr/bin/env python3
"""Tests for --owned-file / --from-user-file line-delimited principal lists."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

bloodbash_globals = {}
with open("BloodBash.py", "r", encoding="utf-8") as f:
    exec(f.read(), bloodbash_globals)


class TestOwnedFile(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bb-owned-")
        self._saved = bloodbash_globals["global_findings"]
        bloodbash_globals["global_findings"] = []

    def tearDown(self):
        bloodbash_globals["global_findings"] = self._saved
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write(self, name: str, text: str) -> str:
        path = os.path.join(self.temp_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_parse_principal_list_file_basic(self):
        path = self._write(
            "owned.txt",
            "# footholds\n"
            "alice\n"
            "\n"
            "bob@corp.local  # helpdesk\n"
            "  svc_backup  \n"
            "# trailing\n",
        )
        names = bloodbash_globals["parse_principal_list_file"](path)
        self.assertEqual(names, ["alice", "bob@corp.local", "svc_backup"])

    def test_parse_empty_file_raises(self):
        path = self._write("empty.txt", "# only comments\n\n")
        with self.assertRaises(ValueError):
            bloodbash_globals["parse_principal_list_file"](path)

    def test_parse_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            bloodbash_globals["parse_principal_list_file"](
                os.path.join(self.temp_dir, "nope.txt")
            )

    def test_merge_csv_and_file_dedupes(self):
        path = self._write("more.txt", "bob\ncharlie\n")
        merged = bloodbash_globals["merge_principal_csv_and_file"](
            "alice,bob", path
        )
        self.assertEqual(merged, "alice,bob,charlie")

    def test_merge_file_only(self):
        path = self._write("only.txt", "alice\nbob\n")
        merged = bloodbash_globals["merge_principal_csv_and_file"](None, path)
        self.assertEqual(merged, "alice,bob")

    def test_apply_to_args_owned_and_from_user(self):
        owned_path = self._write("owned.txt", "alice\nbob\n")
        fu_path = self._write("fu.txt", "charlie\n")

        class A:
            owned = "dave"
            owned_file = owned_path
            from_user = None
            from_user_file = fu_path

        args = A()
        string_io = StringIO()
        test_console = Console(file=string_io, width=100, legacy_windows=False)
        with patch.object(
            bloodbash_globals["console"], "print", side_effect=test_console.print
        ):
            bloodbash_globals["apply_principal_list_files_to_args"](args)
        self.assertEqual(args.owned, "dave,alice,bob")
        self.assertEqual(args.from_user, "charlie")
        out = re.sub(r"\x1b\[[0-9;]*m", "", string_io.getvalue())
        self.assertIn("owned principal", out.lower())
        self.assertIn("compromise principal", out.lower())

    def test_cli_owned_file_loads_and_runs(self):
        """CLI accepts --owned-file and finds principals in sample data."""
        # SCOTT exists in SampleSharphoundADData
        owned_path = self._write("owned.txt", "# sample\nSCOTT\n")
        env = os.environ.copy()
        env["BLOODBASH_NO_CACHE"] = "1"
        r = subprocess.run(
            [
                sys.executable,
                "BloodBash.py",
                "SampleSharphoundADData",
                "--owned-file",
                owned_path,
                "--owned-inventory",
                "--no-cache",
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=os.getcwd(),
        )
        self.assertEqual(r.returncode, 0, msg=r.stderr + r.stdout)
        out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
        self.assertIn("Loaded 1 owned principal", out)
        # Inventory or paths section should mention SCOTT somehow
        self.assertTrue(
            "SCOTT" in out.upper() or "Owned" in out,
            msg=out[-2000:],
        )

    def test_cli_missing_file_exits_nonzero(self):
        env = os.environ.copy()
        env["BLOODBASH_NO_CACHE"] = "1"
        missing = os.path.join(self.temp_dir, "missing-owned.txt")
        r = subprocess.run(
            [
                sys.executable,
                "BloodBash.py",
                "SampleSharphoundADData",
                "--owned-file",
                missing,
                "--no-cache",
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=os.getcwd(),
        )
        self.assertNotEqual(r.returncode, 0)
        out = (r.stdout + r.stderr).lower()
        self.assertIn("owned-file", out)


if __name__ == "__main__":
    unittest.main()
