#!/usr/bin/env python3
"""Unit tests for --writable-file (bloodyAD-style effective write import)."""
import json
import os
import re
import shutil
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import networkx as nx
from rich.console import Console

bloodbash_globals = {}
with open("BloodBash.py", "r", encoding="utf-8") as f:
    exec(f.read(), bloodbash_globals)


class TestWritableFile(unittest.TestCase):
    def setUp(self):
        self._saved = bloodbash_globals["global_findings"]
        bloodbash_globals["global_findings"] = []
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        bloodbash_globals["global_findings"] = self._saved
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _capture(self, func, *args, **kwargs):
        sio = StringIO()
        tc = Console(file=sio, width=120, legacy_windows=False)
        with patch.object(bloodbash_globals["console"], "print", side_effect=tc.print):
            result = func(*args, **kwargs)
        return sio.getvalue(), result

    def _strip(self, text):
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def _write(self, name, payload):
        path = os.path.join(self.temp_dir, name)
        if isinstance(payload, str):
            with open(path, "w", encoding="utf-8") as f:
                f.write(payload)
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f)
        return path

    def _graph(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "U",
            name="ALICE@LAB.LOCAL",
            type="User",
            props={"domain": "LAB.LOCAL", "enabled": True},
            is_azure=False,
        )
        G.add_node(
            "BOB",
            name="BOB@LAB.LOCAL",
            type="User",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "PC",
            name="WS01.LAB.LOCAL",
            type="Computer",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_edge("U", "PC", label="AdminTo")
        return G

    def test_parse_list_of_objects(self):
        path = self._write(
            "w.json",
            [
                {
                    "target": "BOB@LAB.LOCAL",
                    "rights": ["writeProperty:msDS-KeyCredentialLink"],
                },
                {"dn": "CN=WS01,CN=Computers,DC=lab,DC=local", "writable": ["GenericWrite"]},
            ],
        )
        rows = bloodbash_globals["parse_writable_file"](path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["target"], "BOB@LAB.LOCAL")
        self.assertIn("writeProperty:msDS-KeyCredentialLink", rows[0]["rights"])
        self.assertTrue(any("GenericWrite" in r["rights"] for r in rows))

    def test_parse_wrapped_principal(self):
        path = self._write(
            "w2.json",
            {
                "principal": "alice",
                "writable": [
                    {"object": "BOB@LAB.LOCAL", "permission": "GenericWrite"},
                ],
            },
        )
        rows = bloodbash_globals["parse_writable_file"](path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["principal"], "alice")
        self.assertEqual(rows[0]["target"], "BOB@LAB.LOCAL")

    def test_parse_jsonl_and_tsv(self):
        path = self._write(
            "w.jsonl",
            '{"target": "X", "rights": ["WriteDacl"]}\n{"target": "Y", "rights": ["Owns"]}\n',
        )
        rows = bloodbash_globals["parse_writable_file"](path)
        self.assertEqual({r["target"] for r in rows}, {"X", "Y"})
        tsv = self._write("w.tsv", "TARGET\tRIGHT\nBOB@LAB\twriteProperty:unicodePwd\n")
        rows2 = bloodbash_globals["parse_writable_file"](tsv)
        self.assertEqual(rows2[0]["target"], "BOB@LAB")
        self.assertIn("writeProperty:unicodePwd", rows2[0]["rights"])

    def test_filter_by_principal(self):
        rows = [
            {"principal": "alice", "target": "A", "rights": ["GenericWrite"]},
            {"principal": "bob", "target": "B", "rights": ["GenericAll"]},
            {"principal": "", "target": "C", "rights": ["WriteDacl"]},
        ]
        filt = bloodbash_globals["filter_writable_rows"](rows, "ALICE@LAB.LOCAL")
        targets = {r["target"] for r in filt}
        self.assertEqual(targets, {"A", "C"})

    def test_annotate_not_in_sharphound(self):
        G = self._graph()
        rows = [
            {"target": "WS01.LAB.LOCAL", "rights": ["AdminTo"]},
            {
                "target": "BOB@LAB.LOCAL",
                "rights": ["writeProperty:msDS-KeyCredentialLink"],
            },
        ]
        annotated = bloodbash_globals["annotate_writable_vs_graph"](G, rows, "U")
        bob = [r for r in annotated if "BOB" in r["target"]][0]
        ws = [r for r in annotated if "WS01" in r["target"]][0]
        self.assertTrue(bob["not_in_collector"])
        self.assertFalse(ws["not_in_collector"])

    def test_dossier_merges_writable(self):
        G = self._graph()
        path = self._write(
            "live.json",
            [{"target": "BOB@LAB.LOCAL", "rights": ["writeProperty:servicePrincipalName"]}],
        )
        rows = bloodbash_globals["parse_writable_file"](path)
        dossier = bloodbash_globals["build_compromise_dossier"](
            G, "alice", writable_rows=rows
        )
        self.assertEqual(dossier["counts"]["effective_writable"], 1)
        self.assertEqual(len(dossier["effective_writable"]), 1)
        self.assertTrue(dossier["effective_writable"][0]["not_in_collector"])

    def test_print_and_export_include_writable(self):
        G = self._graph()
        rows = [
            {
                "target": "BOB@LAB.LOCAL",
                "rights": ["writeProperty:msDS-KeyCredentialLink"],
                "not_in_collector": True,
            }
        ]
        dossier = bloodbash_globals["build_compromise_dossier"](
            G, "alice", writable_rows=rows
        )
        out, _ = self._capture(bloodbash_globals["print_compromise_dossier"], dossier)
        text = self._strip(out)
        self.assertIn("Effective writable", text)
        self.assertIn("BOB@LAB.LOCAL", text)
        self.assertIn("not in sharphound", text.lower())
        written = bloodbash_globals["export_compromise_dossier"](dossier, self.temp_dir)
        names = {os.path.basename(p) for p in written}
        self.assertIn("effective_writable.txt", names)
        self.assertIn("effective_writable.csv", names)

    def test_cli_help_mentions_writable_file(self):
        import subprocess
        import sys

        r = subprocess.run(
            [sys.executable, "BloodBash.py", "--help-advanced"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn("--writable-file", r.stdout)

    def test_parse_missing_file_raises(self):
        with self.assertRaises(OSError):
            bloodbash_globals["parse_writable_file"](
                os.path.join(self.temp_dir, "nope.json")
            )


if __name__ == "__main__":
    unittest.main()
