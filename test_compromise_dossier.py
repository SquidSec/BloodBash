#!/usr/bin/env python3
"""Unit tests for compromise dossier mode (--from-user / --compromise)."""
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


class TestCompromiseDossier(unittest.TestCase):
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

    def _foothold_graph(self):
        """alice -> IT (MemberOf) -> DA; alice AdminTo PC1; IT CanRDP PC2; nested Helpdesk."""
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL", "highvalue": True}, is_azure=False)
        G.add_node("IT", name="IT@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("HD", name="HELPDESK@LAB.LOCAL", type="Group",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("U", name="ALICE@LAB.LOCAL", type="User",
                   props={"domain": "LAB.LOCAL", "enabled": True}, is_azure=False)
        G.add_node("PC1", name="WS01.LAB.LOCAL", type="Computer",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("PC2", name="WS02.LAB.LOCAL", type="Computer",
                   props={"domain": "LAB.LOCAL"}, is_azure=False)
        # membership: alice -> helpdesk -> IT -> DA
        G.add_edge("U", "HD", label="MemberOf")
        G.add_edge("HD", "IT", label="MemberOf")
        G.add_edge("IT", "DA", label="MemberOf")
        # direct rights
        G.add_edge("U", "PC1", label="AdminTo")
        G.add_edge("U", "PC1", label="LocalAdmin")
        # via group
        G.add_edge("IT", "PC2", label="CanRDP")
        G.add_edge("HD", "PC2", label="ForceChangePassword")
        return G

    def test_resolve_principal(self):
        G = self._foothold_graph()
        oid = bloodbash_globals["resolve_principal_oid"](G, "alice")
        self.assertEqual(oid, "U")
        oid2 = bloodbash_globals["resolve_principal_oid"](G, "ALICE@LAB.LOCAL")
        self.assertEqual(oid2, "U")
        self.assertIsNone(bloodbash_globals["resolve_principal_oid"](G, "nosuchuser"))

    def test_nested_groups(self):
        G = self._foothold_graph()
        mem = bloodbash_globals["collect_nested_groups"](G, "U")
        self.assertEqual(mem["direct_count"], 1)
        self.assertEqual(mem["direct"][0]["name"], "HELPDESK@LAB.LOCAL")
        names = {g["name"] for g in mem["effective"]}
        self.assertIn("HELPDESK@LAB.LOCAL", names)
        self.assertIn("IT@LAB.LOCAL", names)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", names)
        self.assertGreaterEqual(mem["effective_count"], 3)

    def test_nested_groups_case_insensitive_memberof_label(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="ALICE@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("G", name="STAFF@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_edge("U", "G", label="memberof")  # lowercase edge label
        mem = bloodbash_globals["collect_nested_groups"](G, "U")
        self.assertEqual(mem["direct_count"], 1)
        self.assertEqual(mem["direct"][0]["name"], "STAFF@LAB.LOCAL")

    def test_compromise_right_labels_include_rbcd_configure_rights(self):
        labels = set(bloodbash_globals["COMPROMISE_RIGHT_LABELS"])
        summary = set(bloodbash_globals["COMPROMISE_SUMMARY_RIGHTS"])
        self.assertIn("WriteAccountRestrictions", labels)
        self.assertIn("AddAllowedToAct", labels)
        self.assertIn("AllExtendedRights", labels)
        self.assertIn("WriteAccountRestrictions", summary)
        self.assertIn("AddAllowedToAct", summary)

    def test_outbound_rights_include_via_group(self):
        G = self._foothold_graph()
        mem = bloodbash_globals["collect_nested_groups"](G, "U")
        oids = ["U"] + [g["id"] for g in mem["effective"]]
        rights = bloodbash_globals["collect_outbound_rights_for_principals"](G, oids)
        self.assertIn("AdminTo", rights)
        self.assertIn("CanRDP", rights)
        self.assertTrue(any(r["target"] == "WS01.LAB.LOCAL" for r in rights["AdminTo"]))
        self.assertTrue(any(r["target"] == "WS02.LAB.LOCAL" for r in rights["CanRDP"]))
        # CanRDP via IT group
        self.assertTrue(any(r["via"] == "IT@LAB.LOCAL" for r in rights["CanRDP"]))

    def test_paths_from_principal_to_hv(self):
        G = self._foothold_graph()
        paths = bloodbash_globals["collect_paths_from_principal"](G, "U", fast=True)
        self.assertTrue(paths)
        self.assertTrue(any("DOMAIN ADMINS" in p["target"] for p in paths))
        self.assertGreaterEqual(paths[0]["length"], 1)

    def test_build_and_print_dossier(self):
        G = self._foothold_graph()
        dossier = bloodbash_globals["build_compromise_dossier"](G, "alice")
        self.assertIsNotNone(dossier)
        self.assertEqual(dossier["name"], "ALICE@LAB.LOCAL")
        self.assertGreaterEqual(dossier["counts"]["effective_groups"], 3)
        self.assertGreaterEqual(dossier["counts"].get("AdminTo", 0), 1)
        self.assertGreaterEqual(dossier["counts"].get("CanRDP", 0), 1)
        self.assertGreaterEqual(dossier["counts"]["paths_to_high_value"], 1)
        out, _ = self._capture(bloodbash_globals["print_compromise_dossier"], dossier)
        clean = self._strip(out)
        self.assertIn("Compromise Dossier", clean)
        self.assertIn("Capability summary", clean)
        self.assertIn("Direct group membership", clean)
        self.assertIn("Outbound rights", clean)
        self.assertIn("Attack paths to high-value", clean)
        self.assertTrue(
            any(f[1] == "Compromise Dossier" for f in bloodbash_globals["global_findings"])
        )

    def test_export_dossier_lists(self):
        G = self._foothold_graph()
        dossier = bloodbash_globals["build_compromise_dossier"](G, "alice")
        out_dir = os.path.join(self.temp_dir, "alice-pack")
        written = bloodbash_globals["export_compromise_dossier"](dossier, out_dir)
        self.assertTrue(written)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "summary.md")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "counts.csv")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "membership_direct.txt")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "membership_effective.txt")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "paths_to_high_value.txt")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "paths_to_high_value.csv")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "dossier.json")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "rights", "AdminTo.txt")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "rights", "CanRDP.txt")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "adminto_hosts.txt")))
        self.assertTrue(os.path.exists(os.path.join(out_dir, "adminto_hosts.csv")))
        with open(os.path.join(out_dir, "membership_effective.txt"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", text)
        with open(os.path.join(out_dir, "rights", "CanRDP.txt"), encoding="utf-8") as f:
            rdp = f.read()
        self.assertIn("WS02.LAB.LOCAL", rdp)
        with open(os.path.join(out_dir, "adminto_hosts.txt"), encoding="utf-8") as f:
            hosts = f.read()
        self.assertIn("WS01.LAB.LOCAL", hosts)

    def test_run_compromise_dossiers_missing(self):
        G = self._foothold_graph()
        out, docs = self._capture(
            bloodbash_globals["run_compromise_dossiers"], G, "nobodyhere"
        )
        self.assertEqual(docs, [])
        self.assertIn("not found", self._strip(out).lower())

    def test_well_known_membership_exposes_auth_users_rights(self):
        """Domain Users → Auth Users (synthetic) inherits GenericWrite on GPOs."""
        G = nx.MultiDiGraph()
        G.add_node(
            "U",
            name="ALICE@LAB.LOCAL",
            type="User",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "DU",
            name="DOMAIN USERS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "AU",
            name="AUTHENTICATED USERS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "EV",
            name="EVERYONE@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "GPO",
            name="SOFTWARE-DEPLOY@LAB.LOCAL",
            type="GPO",
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
        # Primary group + direct ACL (SharpHound omits Domain Users → Auth Users)
        G.add_edge("U", "DU", label="MemberOf")
        G.add_edge("U", "PC", label="AllExtendedRights")
        G.add_edge("U", "PC", label="WriteAccountRestrictions")
        G.add_edge("AU", "GPO", label="GenericWrite")
        G.add_edge("AU", "GPO", label="WriteDacl")
        G.add_edge("AU", "GPO", label="WriteOwner")
        added = bloodbash_globals["add_well_known_group_memberships"](G)
        self.assertGreaterEqual(added, 1)
        self.assertTrue(
            any(
                u == "DU" and v == "AU" and d.get("label") == "MemberOf"
                for u, v, d in G.edges(data=True)
            )
        )
        dossier = bloodbash_globals["build_compromise_dossier"](G, "ALICE")
        self.assertIsNotNone(dossier)
        eff = {g["name"] for g in dossier["membership"]["effective"]}
        self.assertIn("AUTHENTICATED USERS@LAB.LOCAL", eff)
        self.assertIn("EVERYONE@LAB.LOCAL", eff)
        rights = dossier["rights"]
        self.assertIn("GenericWrite", rights)
        self.assertTrue(
            any("SOFTWARE-DEPLOY" in r["target"] for r in rights["GenericWrite"])
        )
        self.assertIn("WriteAccountRestrictions", rights)
        self.assertTrue(
            any("WS01" in r["target"] for r in rights["WriteAccountRestrictions"])
        )

    def test_cli_help_mentions_from_user(self):
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "BloodBash.py", "--help"],
            capture_output=True, text=True, cwd=os.path.dirname(os.path.abspath(__file__)) or ".",
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--from-user", result.stdout)
        self.assertIn("Compromise dossier", result.stdout)
        self.assertIn("--from-user-export", result.stdout)
        self.assertIn("Examples — compromise dossier", result.stdout)
        self.assertIn("--from-user alice", result.stdout)


if __name__ == "__main__":
    unittest.main()
