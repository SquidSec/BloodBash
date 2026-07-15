#!/usr/bin/env python3
"""Integration tests against the synthetic SharpHound CE corpus.

Corpus: testData/synthetic-corp-lab/ (regenerate via tools/generate_synthetic_sharphound.py)
Ground truth: testData/synthetic-corp-lab/ground_truth.json
"""
from __future__ import annotations

import json
import os
import re
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import networkx as nx
from rich.console import Console

CORPUS = Path(__file__).resolve().parent / "testData" / "synthetic-corp-lab"
GT_PATH = CORPUS / "ground_truth.json"

bloodbash_globals = {}
with open(Path(__file__).resolve().parent / "BloodBash.py", encoding="utf-8") as f:
    exec(f.read(), bloodbash_globals)


class TestSyntheticCorpLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CORPUS.is_dir() or not GT_PATH.is_file():
            raise unittest.SkipTest(
                f"Synthetic corpus missing at {CORPUS}. Run: "
                "python3 tools/generate_synthetic_sharphound.py"
            )
        cls.gt = json.loads(GT_PATH.read_text(encoding="utf-8"))
        cls.nodes = bloodbash_globals["load_json_dir"](str(CORPUS))
        cls.G, _ = bloodbash_globals["build_graph"](cls.nodes)
        cls.domain = cls.gt["domain"]

    def setUp(self):
        bloodbash_globals["global_findings"] = []

    def _capture(self, fn, *args, **kwargs):
        sio = StringIO()
        tc = Console(file=sio, width=160, force_terminal=False, legacy_windows=False)
        with patch.object(bloodbash_globals["console"], "print", side_effect=tc.print):
            fn(*args, **kwargs)
        return re.sub(r"\x1b\[[0-9;]*m", "", sio.getvalue())

    def test_corpus_stats_floor(self):
        s = self.gt["stats"]
        self.assertGreaterEqual(s["users"], 8)
        self.assertGreaterEqual(s["computers"], 40)
        self.assertGreaterEqual(s["groups"], 10)

    def test_well_known_memberof_synthesized(self):
        du = None
        au = None
        for n, d in self.G.nodes(data=True):
            name = (d.get("name") or "").upper()
            if name.startswith("DOMAIN USERS@"):
                du = n
            if "AUTHENTICATED USERS" in name:
                au = n
        self.assertIsNotNone(du)
        self.assertIsNotNone(au)
        self.assertTrue(
            any(
                u == du and v == au and (ed.get("label") or "").lower() == "memberof"
                for u, v, ed in self.G.edges(data=True)
            )
        )

    def test_unexpected_dcsync_msol(self):
        out = self._capture(bloodbash_globals["print_dcsync_rights"], self.G)
        self.assertIn("MSOL_SYNC", out)
        self.assertIn("Unexpected", out)
        critical = [
            f
            for f in bloodbash_globals["global_findings"]
            if f[1] == "DCSync" and "MSOL_SYNC" in f[2] and "can DCSync" in f[2]
        ]
        self.assertTrue(critical, msg=str(bloodbash_globals["global_findings"]))

    def test_system_administrators_not_default_priv(self):
        name = f"SYSTEM ADMINISTRATORS@{self.domain}"
        self.assertFalse(bloodbash_globals["_is_default_high_priv_name"](name))
        # Helpdesk nested only into System Administrators is not expected admin
        hd = None
        for n, d in self.G.nodes(data=True):
            if (d.get("name") or "").upper().startswith("CORP HELPDESK@"):
                hd = n
                break
        self.assertIsNotNone(hd)
        self.assertFalse(bloodbash_globals["is_expected_admin_principal"](self.G, hd))

    def test_can_configure_rbcd_bulk_principals(self):
        rows = bloodbash_globals["collect_can_configure_rbcd"](self.G)
        summary = bloodbash_globals["summarize_can_configure_rbcd"](rows)
        by_p = {s["principal"].upper(): s for s in summary}
        helpdesk = [k for k in by_p if "HELPDESK" in k]
        aws = [k for k in by_p if "AWS AD CONNECTORS" in k]
        self.assertTrue(helpdesk, msg=list(by_p)[:20])
        self.assertTrue(aws, msg=list(by_p)[:20])
        self.assertGreaterEqual(by_p[helpdesk[0]]["count"], 40)
        self.assertGreaterEqual(by_p[aws[0]]["count"], 40)
        # Best-right dedupe: one row per host, not Owns+WAR+AER triple
        alice = [r for r in rows if "ALICE.LOW" in r["principal"].upper()]
        pentest = [r for r in alice if "PENTESTPC" in r["target"].upper()]
        self.assertEqual(len(pentest), 1)

    def test_rbcd_configured(self):
        out = self._capture(bloodbash_globals["print_rbcd"], self.G)
        self.assertIn("PENTESTPC", out)
        self.assertIn("RBCD configured", out)

    def test_gpo_auth_users_and_link(self):
        out = self._capture(bloodbash_globals["print_gpo_abuse"], self.G)
        up = out.upper()
        self.assertIn("PAMAGENTINSTALL", up)
        self.assertIn("AUTHENTICATED USERS", up)
        self.assertNotIn("NO LINKS DETECTED", up)
        # DA-only default policy should not appear as weak (filtered)
        self.assertNotIn("WEAK GPO: DEFAULT DOMAIN POLICY", up)

    def test_broad_principal_acls(self):
        rows = bloodbash_globals["collect_broad_principal_acls"](self.G)
        self.assertTrue(
            any(
                "EVERYONE" in r["principal"].upper() and "MRIOS" in r["target"].upper()
                for r in rows
            ),
            msg=rows[:10],
        )
        self.assertTrue(
            any(
                "AUTHENTICATED USERS" in r["principal"].upper()
                and "PAMAGENTINSTALL" in r["target"].upper()
                for r in rows
            )
        )

    def test_laps_summary(self):
        bloodbash_globals["global_findings"] = []
        out = self._capture(bloodbash_globals["print_laps_status"], self.G)
        self.assertIn("LAPS enabled", out)
        self.assertIn("not enabled", out.lower())
        laps = [f for f in bloodbash_globals["global_findings"] if f[1] == "LAPS"]
        self.assertEqual(len(laps), 1)
        self.assertRegex(laps[0][2], r"\d+/\d+ computers")

    def test_sessions_localadmin_excludes_object_genericall(self):
        out = self._capture(bloodbash_globals["print_sessions_localadmin"], self.G)
        self.assertIn("LocalAdmin", out)
        self.assertIn("DAVE.HELP", out.upper())
        # Domain Admins GenericAll on every computer must not flood LocalAdmin table
        # (may still appear via LocalAdmin edge on DC only)
        self.assertNotIn("GenericAll", out)

    def test_roast_and_password_flags(self):
        out_k = self._capture(bloodbash_globals["print_kerberoastable"], self.G)
        self.assertIn("SVC_SQL", out_k.upper())
        out_a = self._capture(bloodbash_globals["print_as_rep_roastable"], self.G)
        self.assertIn("BOB.ASREP", out_a.upper())
        out_p = self._capture(bloodbash_globals["print_password_never_expires"], self.G)
        self.assertIn("EVE.PNE", out_p.upper())
        out_n = self._capture(bloodbash_globals["print_password_not_required"], self.G)
        self.assertIn("FRANK.PNR", out_n.upper())

    def test_adcs_esc1_present(self):
        out = self._capture(bloodbash_globals["print_adcs_vulnerabilities"], self.G)
        self.assertNotIn("No ADCS objects in this collection", out)
        self.assertIn("ESC1", out)
        self.assertIn("ESC1-USERAUTH", out.upper())

    def test_shadow_credentials(self):
        out = self._capture(bloodbash_globals["print_shadow_credentials"], self.G)
        self.assertTrue(
            "DAVE.HELP" in out.upper() or "GRACE.SHADOW" in out.upper(),
            msg=out[:500],
        )

    def test_dossier_alice_has_impact_edges(self):
        dossier = bloodbash_globals["build_compromise_dossier"](
            self.G, f"ALICE.LOW@{self.domain}"
        )
        self.assertIsNotNone(dossier)
        self.assertGreaterEqual(dossier["counts"].get("impact_edges", 0), 1)
        out = self._capture(bloodbash_globals["print_compromise_dossier"], dossier)
        self.assertIn("Direct impact edges", out)
        self.assertIn("PENTESTPC", out.upper())


if __name__ == "__main__":
    unittest.main()
