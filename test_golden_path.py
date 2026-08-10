#!/usr/bin/env python3
"""Tests for --golden-path (single path to Domain Admins)."""
import os
import re
import subprocess
import sys
import tempfile
import unittest

import networkx as nx

bloodbash_globals = {}
with open("BloodBash.py", "r", encoding="utf-8") as f:
    exec(f.read(), bloodbash_globals)


class TestGoldenPath(unittest.TestCase):
    def setUp(self):
        G = nx.MultiDiGraph()
        for oid, name, typ in [
            ("u_low", "LOW@LAB.LOCAL", "User"),
            ("u_mid", "MID@LAB.LOCAL", "User"),
            ("c_box", "BOX.LAB.LOCAL", "Computer"),
            ("u_da", "ADMIN@LAB.LOCAL", "User"),
            ("g_da", "DOMAIN ADMINS@LAB.LOCAL", "Group"),
        ]:
            G.add_node(oid, name=name, type=typ, props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_edge("u_low", "g_da", label="MemberOf")
        G.add_edge("u_low", "u_mid", label="ForceChangePassword")
        G.add_edge("u_mid", "c_box", label="AdminTo")
        G.add_edge("c_box", "u_da", label="HasSession")
        G.add_edge("u_da", "g_da", label="MemberOf")
        self.G = G

    def test_resolve_domain_admins(self):
        targets = bloodbash_globals["resolve_domain_admin_targets"](self.G)
        self.assertEqual(len(targets), 1)
        self.assertIn("DOMAIN ADMINS", targets[0][1].upper())

    def test_find_golden_path_returns_path(self):
        result = bloodbash_globals["find_golden_path"](self.G)
        self.assertIsNotNone(result)
        self.assertEqual(result["path"][-1], "g_da")
        self.assertIn("DOMAIN ADMINS", result["path_plain"].upper())
        self.assertIn("--[", result["path_plain"])

    def test_find_golden_path_from_seed(self):
        result = bloodbash_globals["find_golden_path"](
            self.G, from_principals="MID@LAB.LOCAL"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["path"][0], "u_mid")

    def test_run_golden_path_jackpot_output(self):
        from io import StringIO
        from unittest.mock import patch
        from rich.console import Console

        string_io = StringIO()
        test_console = Console(file=string_io, width=100, legacy_windows=False, force_terminal=False)
        with patch.object(bloodbash_globals["console"], "print", side_effect=test_console.print):
            code = bloodbash_globals["run_golden_path"](self.G, animate=False)
        self.assertEqual(code, 0)
        text = re.sub(r"\x1b\[[0-9;]*m", "", string_io.getvalue())
        self.assertIn("JACKPOT", text.upper())
        self.assertIn("DOMAIN ADMINS", text.upper())
        self.assertIn("GOLDEN PATH", text.upper())
        self.assertIn("WINNER", text.upper())
        self.assertIn("--[", text)

    def test_cli_golden_path_sample(self):
        env = os.environ.copy()
        env["BLOODBASH_NO_CACHE"] = "1"
        env["TQDM_DISABLE"] = "1"
        r = subprocess.run(
            [
                sys.executable,
                "BloodBash.py",
                "SampleSharphoundADData",
                "--golden-path",
                "--no-cache",
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=os.getcwd(),
        )
        # Sample data may or may not have a path; exit 0 or 1 both ok if clean
        out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
        if r.returncode == 0:
            self.assertIn("JACKPOT", out.upper())
            self.assertNotIn("Collection health", out)
            self.assertNotIn("Prioritized Findings", out)
            self.assertIn("--[", out)
        else:
            self.assertTrue(
                "HOUSE WINS" in out.upper() or "NO PATH" in out.upper(),
                msg=out[-1500:],
            )


if __name__ == "__main__":
    unittest.main()
