#!/usr/bin/env python3
import unittest
import sys
import os
import re
import subprocess
import tempfile
import shutil
import zipfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch
import json
import networkx as nx
from rich.console import Console

# Load the BloodBash script by executing it in a controlled namespace
bloodbash_globals = {}
with open("BloodBash.py", "r") as f:
    exec(f.read(), bloodbash_globals)

AZURE_TEST_DIR = "azure-ad-tests"

class TestBloodBash(unittest.TestCase):
    def setUp(self):
        self.test_data_dir = "testData"
        self.temp_dir = tempfile.mkdtemp()
        self._saved_findings = bloodbash_globals['global_findings']
        bloodbash_globals['global_findings'] = []

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        bloodbash_globals['global_findings'] = self._saved_findings

    @staticmethod
    def _strip_ansi(text):
        return re.sub(r'\x1b\[[0-9;]*m', '', text)

    def _assert_output_contains(self, output, *needles):
        clean = self._strip_ansi(output)
        for needle in needles:
            self.assertIn(needle, clean, msg=f"Expected '{needle}' in output:\n{clean}")
    def _load_and_build_graph(self, test_subdir):
        """Helper to load JSON files from a test subdirectory and build the graph."""
        test_dir = os.path.join(self.test_data_dir, test_subdir)
        if not os.path.exists(test_dir):
            raise FileNotFoundError(f"Test data directory '{test_dir}' does not exist. Skipping test.")
        nodes = bloodbash_globals['load_json_dir'](test_dir)
        G, _ = bloodbash_globals['build_graph'](nodes)
        return G
    def _capture_output(self, func, *args, **kwargs):
        """Helper to capture console output using Rich's Console with StringIO."""
        string_io = StringIO()
        test_console = Console(file=string_io, width=80, legacy_windows=False)
        with patch.object(bloodbash_globals['console'], 'print', side_effect=test_console.print):
            func(*args, **kwargs)
        output = string_io.getvalue()
        return output
    # ────────────────────────────────────────────────
    # Existing tests (kept 100% unchanged)
    # ────────────────────────────────────────────────
    def test_broad_principal_acls_detects_everyone_genericwrite(self):
        G = nx.MultiDiGraph()
        G.add_node("EV", name="EVERYONE@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("U", name="MRIOS@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("GPO", name="SOFT@LAB.LOCAL", type="GPO", props={}, is_azure=False)
        G.add_node("AU", name="AUTHENTICATED USERS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_edge("EV", "U", label="GenericWrite")
        G.add_edge("AU", "GPO", label="WriteDacl")
        rows = bloodbash_globals["collect_broad_principal_acls"](G)
        self.assertTrue(any(r["target"].startswith("MRIOS") for r in rows))
        self.assertTrue(any(r["target"].startswith("SOFT") for r in rows))
        bloodbash_globals["global_findings"] = []
        out = self._capture_output(bloodbash_globals["print_broad_principal_acls"], G)
        self.assertIn("EVERYONE", self._strip_ansi(out))
        self.assertTrue(
            any(f[1] == "Broad Principal ACL" for f in bloodbash_globals["global_findings"])
        )

    def test_sessions_localadmin_excludes_genericall_object_acl(self):
        """GenericAll on computer object is not a LocalAdmin edge."""
        G = nx.MultiDiGraph()
        G.add_node("PC", name="PC01.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("U", name="HELP@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("DA", "PC", label="GenericAll")
        G.add_edge("U", "PC", label="LocalAdmin")
        output = self._capture_output(bloodbash_globals["print_sessions_localadmin"], G)
        clean = self._strip_ansi(output)
        self.assertIn("HELP@LAB.LOCAL", clean)
        self.assertIn("LocalAdmin", clean)
        self.assertNotIn("GenericAll", clean)
        self.assertNotIn("DOMAIN ADMINS@LAB.LOCAL", clean)

    def test_gpo_abuse(self):
        try:
            G = self._load_and_build_graph("gpo-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_gpo_abuse'], G)
        self.assertIn("Weak GPO", output)
        self.assertIn("High-risk", output)
        self.assertIn("Vulnerable-GPO", output)

    def test_gpo_abuse_ignores_default_priv_only_writers(self):
        G = nx.MultiDiGraph()
        G.add_node("GPO", name="DEFAULT-POLICY@LAB.LOCAL", type="GPO", props={}, is_azure=False)
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_edge("DA", "GPO", label="GenericWrite")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_gpo_abuse"], G)
        clean = self._strip_ansi(output)
        self.assertNotIn("Weak GPO", clean)
        self.assertEqual(
            [f for f in bloodbash_globals["global_findings"] if f[1] == "GPO Abuse"],
            [],
        )

    def test_gpo_abuse_flags_authenticated_users_writer(self):
        G = nx.MultiDiGraph()
        G.add_node("GPO", name="SOFTWARE@LAB.LOCAL", type="GPO", props={}, is_azure=False)
        G.add_node("OU", name="WORKSTATIONS@LAB.LOCAL", type="OU", props={}, is_azure=False)
        G.add_node("AU", name="AUTHENTICATED USERS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_edge("OU", "GPO", label="GPLink")
        G.add_edge("DA", "GPO", label="GenericWrite")
        G.add_edge("AU", "GPO", label="GenericWrite")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_gpo_abuse"], G)
        clean = self._strip_ansi(output)
        self.assertIn("Weak GPO", clean)
        self.assertIn("AUTHENTICATED USERS", clean)
        self.assertNotIn("DOMAIN ADMINS@LAB.LOCAL", clean)
        self.assertTrue(any(f[0] == 9 for f in bloodbash_globals["global_findings"] if f[1] == "GPO Abuse"))

    def test_gpo_abuse_detects_link_via_container_in_edge(self):
        """BloodHound GPLink is container → GPO; must not report 'No links'."""
        G = nx.MultiDiGraph()
        G.add_node(
            "GPO",
            name="SOFTWARE-DEPLOY@LAB.LOCAL",
            type="GPO",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "OU",
            name="WORKSTATIONS@LAB.LOCAL",
            type="OU",
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
        G.add_edge("OU", "GPO", label="GPLink")  # correct direction
        G.add_edge("AU", "GPO", label="GenericWrite")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_gpo_abuse"], G)
        clean = self._strip_ansi(output)
        self.assertIn("SOFTWARE-DEPLOY", clean)
        self.assertIn("WORKSTATIONS", clean)
        self.assertNotIn("No links detected", clean)
        self.assertTrue(
            any("SOFTWARE-DEPLOY" in f[2] for f in bloodbash_globals["global_findings"] if f[1] == "GPO Abuse")
        )
    def test_dcsync_rights(self):
        try:
            G = self._load_and_build_graph("dcsync-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        bloodbash_globals['global_findings'] = []
        output = self._capture_output(bloodbash_globals['print_dcsync_rights'], G)
        clean = self._strip_ansi(output)
        self.assertIn("DCSync possible", clean)
        self.assertIn("LOWPRIV@LAB.LOCAL", clean)
        # Built-in DA still shown as expected, not as critical non-default finding text only
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", clean)
        self.assertIn("Expected DCSync", clean)
        # Partial GetChangesAll-only is not full DCSync
        self.assertIn("PARTIAL@LAB.LOCAL", clean)
        self.assertIn("Partial replication rights", clean)
        # Findings: unexpected full DCSync only for LOWPRIV, not DOMAIN ADMINS
        dcsync_details = [f[2] for f in bloodbash_globals['global_findings'] if f[1] == "DCSync"]
        self.assertTrue(any("LOWPRIV" in d for d in dcsync_details))
        self.assertFalse(any("DOMAIN ADMINS" in d and "can DCSync" in d for d in dcsync_details))

    def test_dcsync_nested_da_member_is_expected(self):
        """User nested into Domain Admins with DCSync rights is expected, not critical."""
        G = nx.MultiDiGraph()
        G.add_node("DOM", name="LAB.LOCAL", type="Domain", props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "U",
            name="NESTEDDA@LAB.LOCAL",
            type="User",
            props={"domain": "LAB.LOCAL", "enabled": True},
            is_azure=False,
        )
        G.add_edge("U", "DA", label="MemberOf")
        G.add_edge("U", "DOM", label="GetChanges")
        G.add_edge("U", "DOM", label="GetChangesAll")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_dcsync_rights"], G)
        clean = self._strip_ansi(output)
        self.assertIn("NESTEDDA@LAB.LOCAL", clean)
        self.assertIn("Expected DCSync", clean)
        critical = [
            f for f in bloodbash_globals["global_findings"]
            if f[1] == "DCSync" and "can DCSync" in f[2] and "NESTEDDA" in f[2]
        ]
        self.assertEqual(critical, [])

    def test_is_expected_dcsync_principal(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("U", name="NESTED@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("X", name="LOWPRIV@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("U", "DA", label="MemberOf")
        self.assertTrue(bloodbash_globals["is_expected_dcsync_principal"](G, "DA"))
        self.assertTrue(bloodbash_globals["is_expected_dcsync_principal"](G, "U"))
        self.assertFalse(bloodbash_globals["is_expected_dcsync_principal"](G, "X"))

    def test_system_administrators_not_expected_dcsync_or_default_priv(self):
        """'SYSTEM ADMINISTRATORS@…' must not match Builtin Administrators needles."""
        self.assertFalse(
            bloodbash_globals["_is_default_high_priv_name"](
                "SYSTEM ADMINISTRATORS@LAB.LOCAL"
            )
        )
        self.assertTrue(
            bloodbash_globals["_is_default_high_priv_name"]("ADMINISTRATORS@LAB.LOCAL")
        )
        self.assertTrue(
            bloodbash_globals["_is_default_high_priv_name"]("DOMAIN ADMINS@LAB.LOCAL")
        )
        G = nx.MultiDiGraph()
        G.add_node(
            "SA",
            name="SYSTEM ADMINISTRATORS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_node(
            "HD",
            name="HELPDESK@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_node(
            "BA",
            name="ADMINISTRATORS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_edge("HD", "SA", label="MemberOf")
        self.assertFalse(bloodbash_globals["is_expected_dcsync_principal"](G, "SA"))
        self.assertFalse(bloodbash_globals["is_expected_dcsync_principal"](G, "HD"))
        self.assertTrue(bloodbash_globals["is_expected_dcsync_principal"](G, "BA"))

    def test_is_domain_controller_via_group(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "DCG",
            name="DOMAIN CONTROLLERS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_node(
            "C",
            name="FILE01.LAB.LOCAL",
            type="Computer",
            props={"unconstraineddelegation": True},
            is_azure=False,
        )
        G.add_node(
            "DC",
            name="DC01.LAB.LOCAL",
            type="Computer",
            props={"unconstraineddelegation": True},
            is_azure=False,
        )
        G.add_edge("DC", "DCG", label="MemberOf")
        self.assertTrue(bloodbash_globals["is_domain_controller"](G, "DC"))
        self.assertFalse(bloodbash_globals["is_domain_controller"](G, "C"))

    def test_unconstrained_delegation_dc_vs_non_dc_sections(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "DCG",
            name="DOMAIN CONTROLLERS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_node(
            "DC",
            name="DC01.LAB.LOCAL",
            type="Computer",
            props={"unconstraineddelegation": True, "operatingsystem": "Windows Server 2019"},
            is_azure=False,
        )
        G.add_node(
            "BAD",
            name="APP01.LAB.LOCAL",
            type="Computer",
            props={"unconstraineddelegation": True},
            is_azure=False,
        )
        G.add_edge("DC", "DCG", label="MemberOf")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(
            bloodbash_globals["print_unconstrained_delegation"], G
        )
        clean = self._strip_ansi(output)
        self.assertIn("Domain Controllers", clean)
        self.assertIn("Non-DC", clean)
        self.assertIn("DC01.LAB.LOCAL", clean)
        self.assertIn("APP01.LAB.LOCAL", clean)
        findings = [f[2] for f in bloodbash_globals["global_findings"] if f[1] == "Unconstrained Delegation"]
        self.assertTrue(any("APP01" in d for d in findings))
        self.assertFalse(any("DC01" in d for d in findings))

    def test_dcsync_domain_type_case_insensitive(self):
        """Domain nodes with type 'domain' (lowercase) must still be scanned."""
        G = nx.MultiDiGraph()
        G.add_node(
            "D1",
            name="TEST.LOCAL",
            type="domain",
            props={"domain": "test.local"},
            is_azure=False,
        )
        G.add_node("U1", name="attacker@test.local", type="User", props={}, is_azure=False)
        G.add_edge("U1", "D1", label="GetChanges")
        G.add_edge("U1", "D1", label="GetChangesAll")
        bloodbash_globals['global_findings'] = []
        output = self._capture_output(bloodbash_globals['print_dcsync_rights'], G)
        clean = self._strip_ansi(output)
        self.assertNotIn("No domain objects found", clean)
        self.assertIn("DCSync possible", clean)
        self.assertIn("attacker@test.local", clean)

    def test_rbcd(self):
        try:
            G = self._load_and_build_graph("rdbc-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_rbcd'], G)
        self.assertIn("RBCD configured", output)
        self.assertIn("TARGET-COMPUTER$", output)
        # Principal who can act on the resource (AllowedToAct edge direction)
        self.assertIn("ATTACKER-COMPUTER$", output)
        # Constrained-delegation property alone must not be reported as RBCD
        self.assertNotIn("SAFE-COMPUTER$", output)

    def test_rbcd_not_constrained_delegation_property(self):
        """msds-allowedtodelegateto is KCD, not RBCD."""
        try:
            G = self._load_and_build_graph("rdbc-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        # SAFE-COMPUTER has KCD property but empty AllowedToAct
        safe = None
        for n, d in G.nodes(data=True):
            if d.get("name") == "SAFE-COMPUTER$":
                safe = n
                break
        self.assertIsNotNone(safe)
        ata_in = [
            u for u, _, ed in G.in_edges(safe, data=True)
            if ed.get("label") == "AllowedToAct"
        ]
        self.assertEqual(ata_in, [])
        output = self._capture_output(bloodbash_globals["print_rbcd"], G)
        self.assertNotIn("SAFE-COMPUTER$", output)

    def test_collect_can_configure_rbcd(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "T",
            name="TARGET$.LAB.LOCAL",
            type="Computer",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "U",
            name="HELPDESK@LAB.LOCAL",
            type="User",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_edge("U", "T", label="GenericAll")
        G.add_edge("DA", "T", label="WriteDacl")
        G.add_edge("U", "T", label="WriteAccountRestrictions")
        rows = bloodbash_globals["collect_can_configure_rbcd"](G)
        # DA excluded as expected high priv
        self.assertTrue(any(r["principal"] == "HELPDESK@LAB.LOCAL" for r in rows))
        self.assertFalse(any(r["principal"] == "DOMAIN ADMINS@LAB.LOCAL" for r in rows))
        # Best single right per (principal, target) — WAR ranks above GenericAll
        helpdesk = [r for r in rows if r["principal"] == "HELPDESK@LAB.LOCAL"]
        self.assertEqual(len(helpdesk), 1)
        self.assertEqual(helpdesk[0]["right"], "WriteAccountRestrictions")

    def test_print_can_configure_rbcd(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="SRV01$.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("U", name="LOWPRIV@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("U", "T", label="GenericWrite")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_can_configure_rbcd"], G)
        clean = self._strip_ansi(output)
        self.assertIn("LOWPRIV@LAB.LOCAL", clean)
        self.assertIn("SRV01$", clean)
        self.assertIn("GenericWrite", clean)
        self.assertTrue(
            any(
                f[1] == "Can Configure RBCD" and "LOWPRIV" in f[2]
                for f in bloodbash_globals["global_findings"]
            )
        )

    def test_summarize_can_configure_rbcd_by_principal(self):
        rows = [
            {"principal": "A@LAB.LOCAL", "target": "H1$", "right": "GenericWrite"},
            {"principal": "A@LAB.LOCAL", "target": "H2$", "right": "GenericAll"},
            {"principal": "B@LAB.LOCAL", "target": "H3$", "right": "Owns"},
        ]
        summary = bloodbash_globals["summarize_can_configure_rbcd"](rows)
        self.assertEqual(summary[0]["principal"], "A@LAB.LOCAL")
        self.assertEqual(summary[0]["count"], 2)
        self.assertEqual(summary[1]["principal"], "B@LAB.LOCAL")
        self.assertEqual(summary[1]["count"], 1)

    def test_print_can_configure_rbcd_aggregates_findings(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="LOWPRIV@LAB.LOCAL", type="User", props={}, is_azure=False)
        for i in range(5):
            tid = f"T{i}"
            G.add_node(tid, name=f"HOST{i}$.LAB.LOCAL", type="Computer", props={}, is_azure=False)
            G.add_edge("U", tid, label="GenericWrite")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_can_configure_rbcd"], G)
        clean = self._strip_ansi(output)
        self.assertIn("×5", clean)
        rbcd = [f for f in bloodbash_globals["global_findings"] if f[1] == "Can Configure RBCD"]
        self.assertEqual(len(rbcd), 1)
        self.assertIn("5 computer", rbcd[0][2])

    def test_can_configure_rbcd_keeps_best_right_per_pair(self):
        """Owns + WAR + AllExtendedRights on same host → one row (strongest)."""
        G = nx.MultiDiGraph()
        G.add_node("T", name="HOST$.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("U", name="HELPDESK@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("U", "T", label="Owns")
        G.add_edge("U", "T", label="AllExtendedRights")
        G.add_edge("U", "T", label="WriteAccountRestrictions")
        rows = bloodbash_globals["collect_can_configure_rbcd"](G)
        host_rows = [r for r in rows if r["principal"] == "HELPDESK@LAB.LOCAL"]
        self.assertEqual(len(host_rows), 1)
        self.assertEqual(host_rows[0]["right"], "WriteAccountRestrictions")

    def test_rbcd_configure_rights_exclude_bare_writeproperty(self):
        rights = bloodbash_globals["RBCD_CONFIGURE_RIGHTS"]
        self.assertNotIn("writeproperty", rights)
        self.assertIn("writeaccountrestrictions", rights)
        self.assertIn("addallowedtoact", rights)
        self.assertIn("genericall", rights)

    def test_can_configure_rbcd_ignores_user_targets_and_writeproperty(self):
        """Only computer resources count; bare WriteProperty is not RBCD-configure."""
        G = nx.MultiDiGraph()
        G.add_node("PC", name="PC01$.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("USR", name="BOB@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("U", name="LOWPRIV@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("U", "USR", label="GenericAll")
        G.add_edge("U", "PC", label="WriteProperty")
        G.add_edge("U", "PC", label="AddAllowedToAct")
        rows = bloodbash_globals["collect_can_configure_rbcd"](G)
        self.assertTrue(any(r["target"].startswith("PC01") for r in rows))
        self.assertFalse(any("BOB@" in r["target"] for r in rows))
        self.assertFalse(any(r["right"].lower() == "writeproperty" for r in rows))
        self.assertTrue(any(r["right"] == "AddAllowedToAct" for r in rows))

    def test_print_can_configure_rbcd_caps_principal_findings(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="HOST$.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        for i in range(60):
            uid = f"U{i}"
            G.add_node(uid, name=f"USER{i}@LAB.LOCAL", type="User", props={}, is_azure=False)
            G.add_edge(uid, "T", label="GenericWrite")
        bloodbash_globals["global_findings"] = []
        self._capture_output(bloodbash_globals["print_can_configure_rbcd"], G)
        rbcd_findings = [f for f in bloodbash_globals["global_findings"] if f[1] == "Can Configure RBCD"]
        # 50 principal findings + 1 overflow
        self.assertEqual(len(rbcd_findings), 51)
        self.assertTrue(any("additional principals" in f[2].lower() for f in rbcd_findings))

    def test_add_well_known_group_memberships_links_domain_users(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "S-1-5-21-1-2-3-513",
            name="DOMAIN USERS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "S-1-5-21-1-2-3-515",
            name="DOMAIN COMPUTERS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "LAB.LOCAL-S-1-5-11",
            name="AUTHENTICATED USERS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "LAB.LOCAL-S-1-1-0",
            name="EVERYONE@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "LAB.LOCAL-S-1-5-32-545",
            name="USERS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        added = bloodbash_globals["add_well_known_group_memberships"](G)
        self.assertGreaterEqual(added, 3)
        edges = {(u, v) for u, v, d in G.edges(data=True) if d.get("label") == "MemberOf"}
        self.assertIn(("S-1-5-21-1-2-3-513", "LAB.LOCAL-S-1-5-11"), edges)
        self.assertIn(("S-1-5-21-1-2-3-515", "LAB.LOCAL-S-1-5-11"), edges)
        self.assertIn(("LAB.LOCAL-S-1-5-11", "LAB.LOCAL-S-1-1-0"), edges)
        # Idempotent
        self.assertEqual(bloodbash_globals["add_well_known_group_memberships"](G), 0)

    def test_build_graph_synthesizes_well_known_memberof(self):
        nodes = {
            "S-1-5-21-1-2-3-513": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-513",
                "ObjectType": "Group",
                "Properties": {"name": "DOMAIN USERS@LAB.LOCAL", "domain": "LAB.LOCAL"},
            },
            "LAB.LOCAL-S-1-5-11": {
                "ObjectIdentifier": "LAB.LOCAL-S-1-5-11",
                "ObjectType": "Group",
                "Properties": {
                    "name": "AUTHENTICATED USERS@LAB.LOCAL",
                    "domain": "LAB.LOCAL",
                },
            },
            "LAB.LOCAL-S-1-1-0": {
                "ObjectIdentifier": "LAB.LOCAL-S-1-1-0",
                "ObjectType": "Group",
                "Properties": {"name": "EVERYONE@LAB.LOCAL", "domain": "LAB.LOCAL"},
            },
        }
        G, _ = bloodbash_globals["build_graph"](nodes)
        self.assertTrue(
            any(
                u == "S-1-5-21-1-2-3-513"
                and v == "LAB.LOCAL-S-1-5-11"
                and d.get("label") == "MemberOf"
                for u, v, d in G.edges(data=True)
            )
        )

    def test_sharphound_ce_property_aliases(self):
        """SharpHound CE field names must be recognized by detectors."""
        try:
            G = self._load_and_build_graph("sharphound-ce-aliases-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        pne = self._capture_output(bloodbash_globals["print_password_never_expires"], G)
        self.assertIn("CE-PNE@LAB.LOCAL", pne)
        self.assertNotIn("CE-NORMAL@LAB.LOCAL", pne)
        pnr = self._capture_output(bloodbash_globals["print_password_not_required"], G)
        self.assertIn("CE-PNR@LAB.LOCAL", pnr)
        self.assertNotIn("CE-NORMAL@LAB.LOCAL", pnr)
        unc = self._capture_output(bloodbash_globals["print_unconstrained_delegation"], G)
        self.assertIn("CE-UNCONSTR$", unc)
        self.assertNotIn("CE-SAFE$", unc)
        kcd = self._capture_output(bloodbash_globals["print_constrained_delegation"], G)
        self.assertIn("CE-CONSTR$", kcd)
        self.assertNotIn("CE-SAFE$", kcd)
    def test_shortest_paths(self):
        try:
            G = self._load_and_build_graph("shortest-paths-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        # High-value targets are privileged groups (not bare "DC1$" hostnames)
        self.assertIn("Domain Admins", output)
        self.assertIn("LOWPRIV@LAB.LOCAL", output)
    def test_dangerous_permissions(self):
        try:
            G = self._load_and_build_graph("dangerous-permissions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G)
        self.assertIn("Domain Admins", output)
        self.assertIn("GenericAll", output)
        self.assertIn("LOWPRIV@LAB.LOCAL", output)
    def test_kerberoastable(self):
        try:
            G = self._load_and_build_graph("kerberoastable-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        self.assertIn("KERBUSER@LAB.LOCAL", output)
    def test_as_rep_roastable(self):
        try:
            G = self._load_and_build_graph("as-rep-roastable-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_as_rep_roastable'], G)
        self.assertIn("ASREPUSER@LAB.LOCAL", output)
    def test_sessions_localadmin(self):
        try:
            G = self._load_and_build_graph("local-admin-sessions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_sessions_localadmin'], G)
        self.assertIn("ADMINUSER@LAB.LOCAL", output)
        self.assertIn("Total computers", output)
    def test_get_high_value_targets(self):
        try:
            G = self._load_and_build_graph("high-value-targets-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        targets = bloodbash_globals['get_high_value_targets'](G)
        target_names = [name for _, name, _ in targets]
        self.assertTrue(any("domain admins" in name.lower() for name in target_names))
        self.assertTrue(any("krbtgt" in name.lower() for name in target_names))
    def test_format_path(self):
        G = nx.MultiDiGraph()
        G.add_node("A", name="UserA")
        G.add_node("B", name="TargetB")
        G.add_edge("A", "B", label="AdminTo")
        path = ["A", "B"]
        formatted = bloodbash_globals['format_path'](G, path)
        self.assertIn("UserA", formatted)
        self.assertIn("AdminTo", formatted)
        self.assertIn("TargetB", formatted)
    def test_domain_filtering(self):
        try:
            G = self._load_and_build_graph("domain-filter-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output_filtered = self._capture_output(bloodbash_globals['print_verbose_summary'], G, domain_filter="lab.local")
        self.assertIn("lab.local", output_filtered.lower())
        output_all = self._capture_output(bloodbash_globals['print_verbose_summary'], G, domain_filter=None)
        self.assertGreater(len(output_all), len(output_filtered))
    def test_indirect_paths(self):
        try:
            G = self._load_and_build_graph("indirect-paths-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, indirect=True)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output)
        self.assertIn("Indirect paths", output)
    def test_indirect_dangerous_permissions(self):
        try:
            G = self._load_and_build_graph("indirect-permissions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G, indirect=True)
        self.assertIn("Indirect via group", output)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output)
    def test_sid_history_abuse(self):
        try:
            G = self._load_and_build_graph("sid-history-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_sid_history_abuse'], G)
        self.assertIn("SID History potential", output)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output.replace("\n", ""))

    def test_sharphound_members_become_memberof_edges(self):
        """SharpHound CE group Members lists must become member → MemberOf → group edges."""
        try:
            G = self._load_and_build_graph("members-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        memberof = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "MemberOf"
        ]
        self.assertEqual(len(memberof), 4, msg=f"Expected 4 MemberOf edges, got {memberof}")
        # Direct memberships
        self.assertIn(
            ("S-1-5-21-1-2-3-1100", "S-1-5-21-1-2-3-512"),
            memberof,
        )
        self.assertIn(
            ("S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-512"),
            memberof,
        )
        # Nested group membership: HELP DESK is member of DOMAIN ADMINS
        self.assertIn(
            ("S-1-5-21-1-2-3-1102", "S-1-5-21-1-2-3-512"),
            memberof,
        )
        self.assertIn(
            ("S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-1102"),
            memberof,
        )
        # Pathfinding relies on MemberOf direction: user → group
        self.assertTrue(nx.has_path(G, "S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-512"))
        path = nx.shortest_path(G, "S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-512")
        self.assertEqual(
            path,
            ["S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-1102", "S-1-5-21-1-2-3-512"],
        )
        # Orphan user with no membership should have no MemberOf edges
        orphan_edges = [
            (u, v)
            for u, v in memberof
            if u == "S-1-5-21-1-2-3-1199" or v == "S-1-5-21-1-2-3-1199"
        ]
        self.assertEqual(orphan_edges, [])

    def test_sample_sharphound_memberof_edges_from_members(self):
        """Real SharpHound sample data must yield MemberOf edges after Members ingest."""
        sample_dir = "SampleSharphoundADData"
        if not os.path.isdir(sample_dir):
            self.skipTest(f"Sample directory '{sample_dir}' not present")
        nodes = bloodbash_globals["load_json_dir"](sample_dir)
        G, _ = bloodbash_globals["build_graph"](nodes)
        memberof_count = sum(
            1 for _, _, d in G.edges(data=True) if d.get("label") == "MemberOf"
        )
        self.assertGreater(
            memberof_count,
            0,
            msg="SampleSharphoundADData should produce MemberOf edges from group Members",
        )

    def test_allowedtoact_edge_direction(self):
        """AllowedToAct must be principal → resource (not resource → principal)."""
        try:
            G = self._load_and_build_graph("allowedtoact-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        principal = "S-1-5-21-1-2-3-1002"
        resource = "S-1-5-21-1-2-3-1001"
        edges = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "AllowedToAct"
        ]
        self.assertEqual(len(edges), 1, msg=f"Expected one AllowedToAct edge, got {edges}")
        self.assertEqual(edges[0], (principal, resource))
        # Attack path direction: attacker computer can reach target resource
        self.assertTrue(nx.has_path(G, principal, resource))
        self.assertFalse(nx.has_path(G, resource, principal))

    def test_sample_allowedtoact_edge_direction(self):
        """Sample SharpHound AllowedToAct edges must point principal → resource."""
        sample_dir = "SampleSharphoundADData"
        if not os.path.isdir(sample_dir):
            self.skipTest(f"Sample directory '{sample_dir}' not present")
        nodes = bloodbash_globals["load_json_dir"](sample_dir)
        G, _ = bloodbash_globals["build_graph"](nodes)
        # Known sample: EXTCA01.WRAITH.CORP lists EXTCA02 in AllowedToAct
        resource_oids = [
            n for n, d in G.nodes(data=True)
            if d.get("name", "").upper().startswith("EXTCA01.")
            and d.get("type", "").lower() == "computer"
        ]
        if not resource_oids:
            self.skipTest("EXTCA01 computer not in sample data")
        resource = resource_oids[0]
        ata = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "AllowedToAct" and v == resource
        ]
        self.assertGreater(len(ata), 0, msg="Expected AllowedToAct into EXTCA01")
        for principal, res in ata:
            self.assertEqual(res, resource)
            self.assertNotEqual(principal, resource)
            # Principal is the actor; resource is the target (RBCD resource)
            self.assertTrue(
                G.nodes[principal]["name"].upper().startswith("EXTCA02."),
                msg=f"Expected EXTCA02 as principal, got {G.nodes[principal]['name']}",
            )
    def test_database_persistence(self):
        try:
            G = self._load_and_build_graph("adcs-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        db_path = os.path.join(self.temp_dir, "test.db")
        bloodbash_globals['save_graph_to_db'](G, db_path)
        self.assertTrue(os.path.exists(db_path))
        G_loaded, _ = bloodbash_globals['load_graph_from_db'](db_path)
        self.assertEqual(G.number_of_nodes(), G_loaded.number_of_nodes())
        self.assertEqual(G.number_of_edges(), G_loaded.number_of_edges())

    def test_database_resave_does_not_duplicate_edges(self):
        """Re-saving into an existing SQLite DB must not accumulate edges."""
        G = nx.MultiDiGraph()
        G.add_node("A", name="UserA", type="User", props={}, is_azure=False)
        G.add_node("B", name="GroupB", type="Group", props={}, is_azure=False)
        G.add_edge("A", "B", label="MemberOf")
        db_path = os.path.join(self.temp_dir, "resave.db")
        bloodbash_globals["save_graph_to_db"](G, db_path)
        bloodbash_globals["save_graph_to_db"](G, db_path)
        bloodbash_globals["save_graph_to_db"](G, db_path)
        G_loaded, _ = bloodbash_globals["load_graph_from_db"](db_path)
        self.assertEqual(G_loaded.number_of_nodes(), 2)
        self.assertEqual(G_loaded.number_of_edges(), 1)
        # Explicit row count in edges table
        import sqlite3
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_severity_scoring_and_prioritization(self):
        bloodbash_globals['global_findings'] = []
        bloodbash_globals['add_finding']("ESC1-ESC8", "Test ESC issue")
        bloodbash_globals['add_finding']("Kerberoastable", "Test kerb issue")
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Prioritized Findings", output)
        self.assertIn("ESC1-ESC8", output)
        self.assertIn("Test ESC issue", output)
    def test_export_html(self):
        try:
            G = self._load_and_build_graph("adcs-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="html")
        html_file = f"{export_path}.html"
        self.assertTrue(os.path.exists(html_file))
        with open(html_file, 'r') as f:
            content = f.read()
            self.assertIn("<html", content)
            self.assertIn("BloodBash Report", content)
    def test_export_csv(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="Target", type="User")
        bloodbash_globals['add_finding']("DCSync", "User has GetChanges+GetChangesAll")
        bloodbash_globals['add_finding']("Kerberoastable", "svc_sql has SPN")
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="csv")
        csv_file = f"{export_path}.csv"
        self.assertTrue(os.path.exists(csv_file))
        with open(csv_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            self.assertGreaterEqual(len(lines), 3)  # header + 2 findings
            self.assertIn("Severity", lines[0])
            self.assertIn("Category", lines[0])
            self.assertIn("Details", lines[0])
            body = "".join(lines[1:])
            self.assertIn("DCSync", body)
            self.assertIn("Kerberoastable", body)
    def test_get_indirect_paths(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User")
        G.add_node("G", name="Group", type="Group")
        G.add_node("T", name="Target")
        G.add_edge("U", "G", label="MemberOf")
        G.add_edge("G", "T", label="AdminTo")
        paths = bloodbash_globals['get_indirect_paths'](G, "U", "T")
        self.assertGreater(len(paths), 0)
        self.assertIn("G", paths[0])
    def test_error_handling_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid_json_path = os.path.join(temp_dir, "invalid.json")
            with open(invalid_json_path, 'w') as f:
                f.write("{ invalid json }")
            with patch.object(bloodbash_globals['console'], 'print') as mock_print:
                nodes = bloodbash_globals['load_json_dir'](temp_dir)
                self.assertTrue(any("Warning" in str(call) and "invalid.json" in str(call) for call in mock_print.call_args_list))
                self.assertEqual(len(nodes), 0)
    def test_case_sensitivity_types_and_labels(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="USER")
        G.add_node("C", name="DC1$", type="computer", props={"highvalue": True})
        G.add_node("G", name="Group", type="GROUP")
        G.add_edge("U", "C", label="ADMinto")
        targets = bloodbash_globals['get_high_value_targets'](G)
        self.assertTrue(any("computer" in t[2].lower() for t in targets))
        path = ["U", "C"]
        formatted = bloodbash_globals['format_path'](G, path)
        self.assertIn("ADMinto", formatted)

    def test_high_value_no_bare_dc_substring(self):
        """Bare 'dc' must not match hostnames like CDC-FILESERVER or DC1$."""
        G = nx.MultiDiGraph()
        G.add_node("1", name="CDC-FILESERVER", type="Computer", props={}, is_azure=False)
        G.add_node("2", name="DC1$", type="Computer", props={}, is_azure=False)
        G.add_node("3", name="DOMAIN ADMINS", type="Group", props={}, is_azure=False)
        G.add_node("4", name="WS01", type="Computer", props={"highvalue": True}, is_azure=False)
        names = {t[1] for t in bloodbash_globals['get_high_value_targets'](G)}
        self.assertIn("DOMAIN ADMINS", names)
        self.assertIn("WS01", names)
        self.assertNotIn("CDC-FILESERVER", names)
        self.assertNotIn("DC1$", names)
    def test_performance_fast_mode_and_limits(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="DOMAIN ADMINS", type="Group")
        for i in range(100):
            G.add_node(f"N{i}", name=f"Node{i}", type="User" if i % 2 == 0 else "Computer")
            if i > 0:
                G.add_edge(f"N{i-1}", f"N{i}", label="MemberOf")
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, fast=True, max_paths=5)
        self.assertIn("Fast mode", output)
        self.assertNotIn("Length:", output)
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, max_paths=5)
        path_count = output.count("Length:")
        self.assertLessEqual(path_count, 5)
    def test_code_duplication_roastable_checks(self):
        G = nx.MultiDiGraph()
        G.add_node("K", name="KerbUser", type="User", props={"hasspn": True, "sensitive": False, "enabled": True})
        G.add_node("A", name="AsRepUser", type="User", props={"dontreqpreauth": True, "sensitive": False, "enabled": True})
        kerb_output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        asrep_output = self._capture_output(bloodbash_globals['print_as_rep_roastable'], G)
        self.assertIn("KerbUser", kerb_output)
        self.assertIn("AsRepUser", asrep_output)
        self.assertNotIn("AsRepUser", kerb_output)
    def test_orphan_ace_principal_creates_placeholder(self):
        """ACEs whose PrincipalSID is not in collector objects still become edges."""
        nodes = {
            "S-1-5-21-1-1000": {
                "ObjectIdentifier": "S-1-5-21-1-1000",
                "ObjectType": "User",
                "Properties": {"name": "admin", "domain": "x.local"},
                "Aces": [
                    {"PrincipalSID": "S-1-5-32-544", "RightName": "GenericAll"},
                ],
            }
        }
        G, _ = bloodbash_globals["build_graph"](nodes)
        self.assertIn("S-1-5-32-544", G.nodes)
        edges = list(G.edges(data=True))
        self.assertTrue(
            any(u == "S-1-5-32-544" and v == "S-1-5-21-1-1000" and d.get("label") == "GenericAll"
                for u, v, d in edges),
            f"expected GenericAll edge from orphan SID, got {edges}",
        )

    def test_bugs_placeholder_nodes_and_missing_data(self):
        nodes = {
            "rel1": {"start": "UserA", "end": "GroupB", "label": "MemberOf"},
            "UserA": {"ObjectIdentifier": "UserA", "Properties": {"name": "UserA"}, "ObjectType": "User"},
            "T": {"ObjectIdentifier": "T", "Properties": {"name": "DC1$"}, "ObjectType": "Computer"}
        }
        G, _ = bloodbash_globals['build_graph'](nodes)
        self.assertIn("UserA", G.nodes)
        groupb_node = next((n for n in G.nodes if G.nodes[n].get('name') == "GroupB"), None)
        self.assertIsNotNone(groupb_node)
        self.assertTrue(G.has_edge("UserA", groupb_node))
    def test_security_input_validation_and_escaping(self):
        with patch.object(bloodbash_globals['console'], 'print') as mock_print:
            nodes = bloodbash_globals['load_json_dir']("/nonexistent")
            mock_print.assert_called_with("[yellow]Warning: Directory '/nonexistent' not found. Skipping.[/yellow]")
            self.assertEqual(len(nodes), 0)
        G = nx.MultiDiGraph()
        G.add_node("T", name="<script>alert('xss')</script>", type="User")
        bloodbash_globals['add_finding']("Test", "Injected<script>")
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="html")
        with open(f"{export_path}.html", 'r') as f:
            content = f.read()
            # User-controlled payload must be escaped (table-sort JS may still include <script>)
            self.assertNotIn("Injected<script>", content)
            self.assertNotIn("<script>alert('xss')</script>", content)
            self.assertIn("&lt;script&gt;", content)
    def test_new_features_unconstrained_delegation(self):
        G = nx.MultiDiGraph()
        G.add_node("C1", name="Comp1", type="Computer", props={"TrustedForDelegation": True})
        G.add_node("C2", name="Comp2", type="Computer", props={"TrustedForDelegation": False})
        output = self._capture_output(bloodbash_globals['print_unconstrained_delegation'], G)
        clean = self._strip_ansi(output)
        self.assertIn("Non-DC unconstrained", clean)
        self.assertIn("Comp1", clean)
        self.assertNotIn("Comp2", clean)
    def test_new_features_password_in_description(self):
        G = nx.MultiDiGraph()
        G.add_node("U1", name="User1", type="User", props={"description": "Password: P@ssw0rd123"})
        G.add_node("U2", name="User2", type="User", props={"description": "Normal description"})
        G.add_node("U3", name="User3", type="User", props={"description": None})
        output = self._capture_output(bloodbash_globals['print_password_in_descriptions'], G)
        self.assertIn("Potential password in description", output)
        self.assertIn("User1", output)
        self.assertNotIn("User2", output)
        self.assertNotIn("User3", output)
    def test_export_md_and_json(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="Domain Admins", type="Group")
        G.add_node("U", name="RegularUser", type="User")
        bloodbash_globals['add_finding']("Test", "Sample finding")
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="md")
        self.assertTrue(os.path.exists(f"{export_path}.md"))
        with open(f"{export_path}.md", 'r', encoding='utf-8') as f:
            md = f.read()
            self.assertIn("Prioritized Findings", md)
            self.assertIn("Sample finding", md)
            self.assertIn("High-Value Targets", md)
            self.assertIn("Domain Admins", md)
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="json")
        self.assertTrue(os.path.exists(f"{export_path}.json"))
        with open(f"{export_path}.json", 'r', encoding='utf-8') as f:
            data = json.load(f)
            self.assertIn("nodes", data)
            self.assertIn("findings", data)
            self.assertIn("high_value", data)
            self.assertEqual(data["nodes"], 2)
            self.assertTrue(any(f.get("details") == "Sample finding" for f in data["findings"]))
            self.assertTrue(any(h.get("name") == "Domain Admins" for h in data["high_value"]))
    def test_prioritization_custom_scores(self):
        bloodbash_globals['add_finding']("Custom", "Low priority", score=1)
        bloodbash_globals['add_finding']("Custom2", "High priority", score=10)
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        clean = self._strip_ansi(output)
        self.assertLess(clean.index("High priority"), clean.index("Low priority"))
    def test_no_results_adcs_vulnerabilities(self):
        G = nx.MultiDiGraph()
        G.add_node("Dummy", name="Dummy", type="User")
        output = self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        self.assertIn("No obvious ESC1–ESC14 misconfigurations detected", output)
    def test_no_results_shortest_paths(self):
        G = nx.MultiDiGraph()
        G.add_node("User", name="User", type="User")
        G.add_node("Target", name="DOMAIN ADMINS", type="Group")
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        self.assertIn("No paths found", output)
    def test_no_results_dangerous_permissions(self):
        G = nx.MultiDiGraph()
        G.add_node("User", name="User", type="User")
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G)
        self.assertIn("No high-value targets found", output)
    def test_no_results_get_high_value_targets(self):
        G = nx.MultiDiGraph()
        G.add_node("N1", name="RegularUser", type="User")
        targets = bloodbash_globals['get_high_value_targets'](G)
        self.assertEqual(len(targets), 0)
    def test_no_results_export_empty_graph(self):
        G = nx.MultiDiGraph()
        export_path = os.path.join(self.temp_dir, "empty")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="json")
        self.assertTrue(os.path.exists(f"{export_path}.json"))
        with open(f"{export_path}.json", 'r') as f:
            data = json.load(f)
            self.assertEqual(data.get("nodes"), 0)
    def test_full_analysis_integration_fixed(self):
        # Ensure findings are added and prioritized output is generated
        G = nx.MultiDiGraph()
        # Add a vulnerable setup that triggers findings
        G.add_node("Domain1", name="TESTDOMAIN.LOCAL", type="Domain")
        G.add_node("User1", name="DCSyncUser", type="User")
        G.add_edge("User1", "Domain1", label="GetChangesAll")
        bloodbash_globals['global_findings'] = []  # Reset findings
        self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        self._capture_output(bloodbash_globals['print_dcsync_rights'], G)
        self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Prioritized Findings", output)
        self.assertGreater(len(bloodbash_globals['global_findings']), 0)  # Ensure findings exist
    def test_indirect_permissions_complex_groups(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User")
        G.add_node("G", name="Group", type="Group")
        G.add_node("T", name="DOMAIN ADMINS", type="Group")
        G.add_edge("U", "G", label="MemberOf")
        G.add_edge("G", "T", label="GenericAll")
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G, indirect=True)
        self.assertIn("Indirect via group", output)
        self.assertIn("User", output)
    def test_export_html_with_findings(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="Target", type="User")
        bloodbash_globals['add_finding']("Test", "<script>alert('xss')</script>")
        export_path = os.path.join(self.temp_dir, "with_findings")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="html")
        with open(f"{export_path}.html", 'r') as f:
            content = f.read()
            self.assertIn("Prioritized Findings", content)
            # Finding payload escaped; branding may include a table-sort <script> block
            self.assertNotIn("<script>alert('xss')</script>", content)
            self.assertIn("&lt;script&gt;", content)
    def test_state_isolation_multiple_runs(self):
        bloodbash_globals['global_findings'] = []
        bloodbash_globals['add_finding']("Run1", "Test1")
        output1 = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Test1", output1)
        bloodbash_globals['global_findings'] = []
        bloodbash_globals['add_finding']("Run2", "Test2")
        output2 = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Test2", output2)
        self.assertNotIn("Test1", output2)
    def test_case_insensitive_properties(self):
        G = nx.MultiDiGraph()
        G.add_node("K1", name="Kerb1", type="User", props={"HASSPN": True, "sensitive": False, "enabled": True})
        G.add_node("K2", name="Kerb2", type="User", props={"hasSPN": True, "Sensitive": False, "Enabled": True})
        output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        self.assertIn("Kerb1", output)
        self.assertIn("Kerb2", output)
    def test_prioritization_multiple_findings_and_sorting(self):
        bloodbash_globals['global_findings'] = []
        bloodbash_globals['add_finding']("Kerberoastable", "Low-risk kerb account", score=5)
        bloodbash_globals['add_finding']("DCSync", "High-risk DCSync", score=10)
        bloodbash_globals['add_finding']("GPO Abuse", "Medium-risk GPO", score=7)
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        lines = output.split('\n')
        finding_lines = [line for line in lines if "DCSync" in line or "GPO" in line or "Kerberoastable" in line]
        dcsync_idx = next(i for i, line in enumerate(finding_lines) if "DCSync" in line)
        gpo_idx = next(i for i, line in enumerate(finding_lines) if "GPO" in line)
        kerb_idx = next(i for i, line in enumerate(finding_lines) if "Kerberoastable" in line)
        self.assertLess(dcsync_idx, gpo_idx)
        self.assertLess(gpo_idx, kerb_idx)
    def test_large_graph_performance(self):
        G = nx.MultiDiGraph()
        for i in range(1000):
            G.add_node(f"N{i}", name=f"Node{i}", type="User" if i % 2 == 0 else "Computer")
            if i > 0:
                G.add_edge(f"N{i-1}", f"N{i}", label="MemberOf")
        G.add_node("Target", name="DOMAIN ADMINS", type="Group")
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, fast=True, max_paths=5)
        self.assertIn("Fast mode", output)
        self.assertNotIn("Length:", output)
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, max_paths=5)
        path_count = output.count("Length:")
        self.assertLessEqual(path_count, 5)
    def test_new_features_shadow_credentials(self):
        try:
            G = self._load_and_build_graph("shadow-credentials-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_shadow_credentials'], G)
        clean = self._strip_ansi(output)
        self.assertIn("Shadow Credentials abuse right", clean)
        self.assertIn("ATTACKER@TEST.LOCAL", clean)
        self.assertIn("TARGETUSER@TEST.LOCAL", clean)
        self.assertTrue(
            any("AddKeyCredentialLink" in f[2] or "shadow credential path" in f[2]
                for f in bloodbash_globals['global_findings'])
        )
        self.assertIn("Existing KeyCredentialLink", clean)
        self.assertIn("HELLOUSER@TEST.LOCAL", clean)

    def test_shadow_credentials_genericall_path(self):
        """GenericAll on a user is a shadow-credential abuse path (aggregated)."""
        G = nx.MultiDiGraph()
        G.add_node("A", name="ATTACKER", type="User", props={}, is_azure=False)
        G.add_node("T", name="TARGET", type="User", props={}, is_azure=False)
        G.add_edge("A", "T", label="GenericAll")
        bloodbash_globals['global_findings'] = []
        output = self._capture_output(bloodbash_globals['print_shadow_credentials'], G)
        clean = self._strip_ansi(output)
        self.assertIn("Shadow Credentials", clean)
        self.assertIn("GenericAll", clean)
        self.assertIn("ATTACKER", clean)
        self.assertTrue(any("Shadow Credentials" in f[1] for f in bloodbash_globals['global_findings']))
        # Secondary rights are aggregated (principal + right + target count)
        self.assertTrue(
            any("1 principal" in f[2] or "TARGET" in f[2] for f in bloodbash_globals['global_findings'])
        )

    def test_shadow_credentials_aggregates_secondary_and_filters_key_admins(self):
        """Key Admins AddKeyCredentialLink is expected noise; secondary ACLs aggregate."""
        G = nx.MultiDiGraph()
        G.add_node("KA", name="KEY ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("U1", name="user1@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("U2", name="user2@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("A", name="lowpriv@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("KA", "U1", label="AddKeyCredentialLink")
        G.add_edge("KA", "U2", label="AddKeyCredentialLink")
        G.add_edge("A", "U1", label="GenericAll")
        G.add_edge("A", "U2", label="GenericAll")
        bloodbash_globals['global_findings'] = []
        out = self._capture_output(bloodbash_globals['print_shadow_credentials'], G)
        clean = self._strip_ansi(out)
        # Key Admins primary rights filtered
        self.assertFalse(
            any("KEY ADMINS" in f[2] for f in bloodbash_globals['global_findings']),
            msg=str(bloodbash_globals['global_findings']),
        )
        # One aggregated secondary finding for lowpriv GenericAll on 2 principals
        shadow = [f for f in bloodbash_globals['global_findings'] if f[1] == "Shadow Credentials"]
        self.assertEqual(len(shadow), 1)
        self.assertIn("2 principal", shadow[0][2])
        self.assertIn("lowpriv@LAB.LOCAL", clean)

    def test_no_results_shadow_credentials(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User", props={})
        output = self._capture_output(bloodbash_globals['print_shadow_credentials'], G)
        self.assertIn(
            "No Shadow Credentials abuse rights or existing KeyCredentialLink found",
            self._strip_ansi(output),
        )
    def test_no_results_gpo_content_parsing(self):
        G = nx.MultiDiGraph()
        G.add_node("G", name="SafeGPO", type="GPO", props={})
        output = self._capture_output(bloodbash_globals['print_gpo_content_parsing'], G)
        self.assertIn("No exploitable GPO content found", output)
    def test_new_features_constrained_delegation(self):
        try:
            G = self._load_and_build_graph("constrained-delegation-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_constrained_delegation'], G)
        self.assertIn("Constrained Delegation enabled", output)
        self.assertTrue(any("Constrained Delegation" in f[2] for f in bloodbash_globals['global_findings']))
    def test_no_results_constrained_delegation(self):
        G = nx.MultiDiGraph()
        G.add_node("C", name="Comp", type="Computer", props={})
        output = self._capture_output(bloodbash_globals['print_constrained_delegation'], G)
        self.assertIn("No Constrained Delegation found", output)
    def test_new_features_laps_status(self):
        try:
            G = self._load_and_build_graph("laps-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_laps_status'], G)
        self.assertIn("LAPS enabled", output)
        self.assertIn("LAPS not enabled", output)
        # Password attrs (any case) and SharpHound haslaps=true count as enabled
        self.assertIn("Comp1", output)
        self.assertIn("Comp3", output)  # ms-Mcs-AdmPwd case variant
        self.assertIn("Comp5", output)  # haslaps: true (CE)
        # Summary finding only (not one finding per computer)
        laps_findings = [f for f in bloodbash_globals['global_findings'] if f[1] == "LAPS"]
        self.assertEqual(len(laps_findings), 1)
        self.assertRegex(laps_findings[0][2], r"\d+/\d+ computers do not have LAPS")
        # Comp3 must not appear as a missing-LAPS host name in findings
        self.assertFalse(
            any("Comp3" in f[2] for f in laps_findings),
            "Comp3 has ms-Mcs-AdmPwd and should not be a LAPS-missing finding",
        )


    def test_laps_haslaps_flag(self):
        """SharpHound CE haslaps boolean is the primary LAPS signal."""
        G = nx.MultiDiGraph()
        G.add_node("c1", name="HASLAPS-PC", type="Computer", props={"haslaps": True}, is_azure=False)
        G.add_node("c2", name="NOLAPS-PC", type="Computer", props={"haslaps": False}, is_azure=False)
        bloodbash_globals['global_findings'] = []
        output = self._capture_output(bloodbash_globals['print_laps_status'], G)
        self.assertIn("LAPS enabled", output)
        self.assertIn("HASLAPS-PC", output)
        self.assertIn("NOLAPS-PC", output)
        laps_findings = [f for f in bloodbash_globals['global_findings'] if f[1] == "LAPS"]
        self.assertEqual(len(laps_findings), 1)
        self.assertIn("1/2 computers do not have LAPS enabled", laps_findings[0][2])

    def test_collect_laps_readers(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "C",
            name="WORKSTATION01.LAB.LOCAL",
            type="Computer",
            props={"haslaps": True, "domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "U",
            name="HELPDESK@LAB.LOCAL",
            type="User",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_edge("U", "C", label="ReadLAPSPassword")
        G.add_edge("DA", "C", label="ReadLAPSPassword")
        rows = bloodbash_globals["collect_laps_readers"](G)
        # Default high-priv (DA) excluded; helpdesk kept
        names = {(r["reader"], r["computer"]) for r in rows}
        self.assertIn(("HELPDESK@LAB.LOCAL", "WORKSTATION01.LAB.LOCAL"), names)
        self.assertFalse(any(r["reader"] == "DOMAIN ADMINS@LAB.LOCAL" for r in rows))

    def test_print_laps_readers(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "C",
            name="PC01.LAB.LOCAL",
            type="Computer",
            props={"haslaps": True},
            is_azure=False,
        )
        G.add_node("U", name="LAPSREADER@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("U", "C", label="ReadLAPSPassword")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_laps_readers"], G)
        clean = self._strip_ansi(output)
        self.assertIn("LAPSREADER@LAB.LOCAL", clean)
        self.assertIn("PC01.LAB.LOCAL", clean)
        self.assertIn("ReadLAPSPassword", clean)
        self.assertTrue(
            any(
                f[1] == "LAPS Readers" and "LAPSREADER" in f[2]
                for f in bloodbash_globals["global_findings"]
            )
        )


    def test_domain_trusts_ingest(self):
        """SharpHound domain Trusts[] become TrustedDomain edges."""
        nodes = bloodbash_globals['load_json_dir']('SampleSharphoundADData')
        # Only need domains if sample present
        if not nodes:
            self.skipTest('no sample data')
        G, _ = bloodbash_globals['build_graph'](nodes)
        trust_edges = [
            (u, v, d.get('label'))
            for u, v, d in G.edges(data=True)
            if str(d.get('label', '')).startswith('TrustedDomain')
        ]
        self.assertGreater(len(trust_edges), 0, 'expected TrustedDomain edges from sample')
        bloodbash_globals['global_findings'] = []
        out = self._capture_output(bloodbash_globals['print_trust_abuse'], G)
        self.assertIn('Domain trust', out)
        self.assertTrue(any(f[1] == 'Trust Abuse' for f in bloodbash_globals['global_findings']))

    def test_esc9_no_security_extension(self):
        G = nx.MultiDiGraph()
        G.add_node(
            'T',
            name='ESC9TEMPLATE@LAB.LOCAL',
            type='Certificate Template',
            props={
                'enrollmentflag': 'AUTO_ENROLLMENT, NO_SECURITY_EXTENSION',
                'authenticationenabled': True,
                'enrolleesuppliessubject': False,
                'requiresmanagerapproval': False,
                'ekus': ['1.3.6.1.5.5.7.3.2'],
            },
            is_azure=False,
        )
        G.add_node('U', name='LowPriv@LAB.LOCAL', type='User', props={}, is_azure=False)
        G.add_edge('U', 'T', label='Enroll')
        bloodbash_globals['global_findings'] = []
        out = self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        self.assertIn('ESC9', out)
        self.assertTrue(any('ESC9' in f[2] for f in bloodbash_globals['global_findings']))

    def test_shadow_creds_skips_domain_admins(self):
        G = nx.MultiDiGraph()
        G.add_node('DA', name='DOMAIN ADMINS@LAB.LOCAL', type='Group', props={}, is_azure=False)
        G.add_node('U', name='victim@LAB.LOCAL', type='User', props={}, is_azure=False)
        G.add_node('A', name='attacker@LAB.LOCAL', type='User', props={}, is_azure=False)
        G.add_edge('DA', 'U', label='GenericAll')
        G.add_edge('A', 'U', label='AddKeyCredentialLink')
        bloodbash_globals['global_findings'] = []
        out = self._capture_output(bloodbash_globals['print_shadow_credentials'], G)
        clean = self._strip_ansi(out)
        self.assertIn('AddKeyCredentialLink', clean)
        self.assertIn('attacker@LAB.LOCAL', clean)
        # Domain Admins GenericAll should be filtered
        self.assertFalse(any('DOMAIN ADMINS' in f[2] and 'GenericAll' in f[2] for f in bloodbash_globals['global_findings']))
        # Attacker primary right still recorded as a finding
        self.assertTrue(
            any('attacker@LAB.LOCAL' in f[2] and 'AddKeyCredentialLink' in f[2]
                for f in bloodbash_globals['global_findings'])
        )

    def test_kerberoastable_and_asrep_one_finding_per_user(self):
        G = nx.MultiDiGraph()
        G.add_node("K1", name="svc1@LAB.LOCAL", type="User", props={
            "hasspn": True, "sensitive": False, "enabled": True,
        }, is_azure=False)
        G.add_node("K2", name="svc2@LAB.LOCAL", type="User", props={
            "hasspn": True, "sensitive": False, "enabled": True,
        }, is_azure=False)
        G.add_node("KT", name="KRBTGT@LAB.LOCAL", type="User", props={
            "hasspn": True, "sensitive": False, "enabled": True,
        }, is_azure=False)
        G.add_node("A1", name="nopre@LAB.LOCAL", type="User", props={
            "dontreqpreauth": True, "sensitive": False, "enabled": True,
        }, is_azure=False)
        bloodbash_globals['global_findings'] = []
        self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        kerb = [f for f in bloodbash_globals['global_findings'] if f[1] == "Kerberoastable"]
        self.assertEqual(len(kerb), 2)
        self.assertTrue(any("svc1@LAB.LOCAL" in f[2] for f in kerb))
        self.assertTrue(any("svc2@LAB.LOCAL" in f[2] for f in kerb))
        self.assertFalse(any("KRBTGT" in f[2] for f in kerb))

        bloodbash_globals['global_findings'] = []
        self._capture_output(bloodbash_globals['print_as_rep_roastable'], G)
        asrep = [f for f in bloodbash_globals['global_findings'] if f[1] == "AS-REP Roastable"]
        self.assertEqual(len(asrep), 1)
        self.assertIn("nopre@LAB.LOCAL", asrep[0][2])

    def test_no_results_laps_status(self):
        G = nx.MultiDiGraph()
        output = self._capture_output(bloodbash_globals['print_laps_status'], G)
        self.assertIn("No computers found", output)
    # ────────────────────────────────────────────────
    # NEW TESTS for v1.2.1 features
    # ────────────────────────────────────────────────
    def test_paths_to_owned(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="LowPriv@LAB.LOCAL", type="User")
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group")
        G.add_edge("U", "DA", label="MemberOf")
        output = self._capture_output(bloodbash_globals['print_paths_to_owned'], G, "LowPriv")
        self.assertIn("Owned target", output)
        self.assertIn("LowPriv@LAB.LOCAL", output)
    def test_arbitrary_paths(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="LowPriv@LAB.LOCAL", type="User")
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group")
        G.add_edge("U", "DA", label="MemberOf")
        output = self._capture_output(bloodbash_globals['print_arbitrary_paths'], G, path_from="LowPriv", path_to="DOMAIN ADMINS")
        self.assertIn("LowPriv@LAB.LOCAL", output)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output)
        self.assertIn("MemberOf", output)
    def test_trust_abuse(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User@LAB.LOCAL", type="User")
        G.add_node("Foreign", name="ForeignDA@OTHER.CORP", type="Group")
        G.add_edge("U", "Foreign", label="ForeignAdmin")
        output = self._capture_output(bloodbash_globals['print_trust_abuse'], G)
        self.assertIn("Domain trust", output)
        self.assertIn("ForeignAdmin", output)
    def test_inspect_node(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="TestUser@LAB.LOCAL", type="User", props={"description": "Test user"})
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group")
        G.add_edge("U", "DA", label="MemberOf")
        output = self._capture_output(bloodbash_globals['inspect_node'], G, "TestUser")
        self.assertIn("TestUser@LAB.LOCAL", output)
        self.assertIn("description", output)
        self.assertIn("MemberOf", output)
    def test_group_analysis(self):
        G = nx.MultiDiGraph()
        G.add_node("G1", name="Group1", type="Group")
        G.add_node("G2", name="Group2", type="Group")
        G.add_edge("G1", "G2", label="MemberOf")
        output = self._capture_output(bloodbash_globals['print_group_analysis'], G)
        self.assertIn("Group Nesting Depth", output)
        self.assertIn("deepest nested groups", output)
        self.assertIn("Cycle detection skipped", output)  # default behavior
    def test_group_analysis_deep(self):
        G = nx.MultiDiGraph()
        G.add_node("G1", name="Group1", type="Group")
        G.add_node("G2", name="Group2", type="Group")
        G.add_edge("G1", "G2", label="MemberOf")
        output = self._capture_output(bloodbash_globals['print_group_analysis'], G, deep_analysis=True)
        self.assertIn("Group Nesting Depth", output)
    def test_stats_dashboard(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User")
        G.add_node("C", name="Computer", type="Computer")
        G.add_edge("U", "C", label="LocalAdmin")
        output = self._capture_output(bloodbash_globals['print_stats_dashboard'], G)
        self._assert_output_contains(
            output,
            "AD & Azure Statistics Dashboard",
            "User",
            "Computer",
            "LocalAdmin right",
        )

    def test_collect_domain_stats_percentages(self):
        now = 1_700_000_000.0
        G = nx.MultiDiGraph()
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "U1",
            name="ADMIN@LAB.LOCAL",
            type="User",
            props={
                "domain": "LAB.LOCAL",
                "enabled": True,
                "hasspn": True,
                "pwdlastset": int(now - 400 * 86400),
                "lastlogontimestamp": int(now - 200 * 86400),
            },
            is_azure=False,
        )
        G.add_node(
            "U2",
            name="USER@LAB.LOCAL",
            type="User",
            props={
                "domain": "LAB.LOCAL",
                "enabled": True,
                "dontreqpreauth": True,
                "pwdlastset": int(now - 10 * 86400),
                "lastlogontimestamp": int(now - 5 * 86400),
            },
            is_azure=False,
        )
        G.add_node(
            "U3",
            name="DISABLED@LAB.LOCAL",
            type="User",
            props={"domain": "LAB.LOCAL", "enabled": False},
            is_azure=False,
        )
        G.add_node(
            "C1",
            name="PC1.LAB.LOCAL",
            type="Computer",
            props={"domain": "LAB.LOCAL", "haslaps": True},
            is_azure=False,
        )
        G.add_node(
            "C2",
            name="PC2.LAB.LOCAL",
            type="Computer",
            props={"domain": "LAB.LOCAL", "haslaps": False},
            is_azure=False,
        )
        G.add_edge("U1", "DA", label="MemberOf")
        stats = bloodbash_globals["collect_domain_stats"](G, now=now)
        self.assertEqual(stats["all_users"], 3)
        self.assertEqual(stats["enabled_users"], 2)
        self.assertEqual(stats["disabled_users"], 1)
        self.assertEqual(stats["spn_users"], 1)
        self.assertEqual(stats["asrep_users"], 1)
        self.assertEqual(stats["da_users"], 1)
        self.assertEqual(stats["all_computers"], 2)
        self.assertEqual(stats["laps_computers"], 1)
        self.assertEqual(stats["pwd_gt_1y"], 1)
        self.assertAlmostEqual(stats["enabled_pct"], 66.67, places=1)
        self.assertAlmostEqual(stats["laps_pct"], 50.0, places=1)

    def test_stats_dashboard_shows_percentage_table(self):
        now = 1_700_000_000.0
        G = nx.MultiDiGraph()
        G.add_node(
            "U1",
            name="A@LAB.LOCAL",
            type="User",
            props={"enabled": True, "hasspn": True, "domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "C1",
            name="PC.LAB.LOCAL",
            type="Computer",
            props={"haslaps": True, "domain": "LAB.LOCAL"},
            is_azure=False,
        )
        output = self._capture_output(
            bloodbash_globals["print_stats_dashboard"], G, None
        )
        clean = self._strip_ansi(output)
        self.assertIn("Percentage", clean)
        self.assertIn("Users with SPN", clean)
        self.assertIn("LAPS Computers", clean)

    def test_list_domains_from_graph(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "D1",
            name="LAB.LOCAL",
            type="Domain",
            props={"domain": "lab.local"},
            is_azure=False,
        )
        G.add_node(
            "D2",
            name="CORP.LOCAL",
            type="Domain",
            props={"domain": "corp.local"},
            is_azure=False,
        )
        G.add_node(
            "U",
            name="user@other.local",
            type="User",
            props={"domain": "other.local"},
            is_azure=False,
        )
        G.add_node(
            "T",
            name="tenant-a",
            type="AZTenant",
            props={"tenantId": "aaaa-bbbb"},
            is_azure=True,
        )
        domains = bloodbash_globals["list_domains"](G)
        names = [d["name"] for d in domains]
        self.assertIn("LAB.LOCAL", names)
        self.assertIn("CORP.LOCAL", names)
        # user-only domain also appears
        self.assertTrue(any("other.local" in n.lower() for n in names))

    def test_cli_list_domains_exits_early(self):
        """--list-domains prints domains and does not require full analysis."""
        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                "BloodBash.py",
                "testData/basic-tests",
                "--list-domains",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
        combined = result.stdout + result.stderr
        clean = re.sub(r"\x1b\[[0-9;]*m", "", combined)
        self.assertIn("Domain", clean)
    def test_export_bloodhound_compatible(self):
        G = nx.MultiDiGraph()
        G.add_node("1", name="User1", type="User", props={"enabled": True})
        G.add_node("2", name="Group1", type="Group", props={})
        G.add_edge("1", "2", label="MemberOf")
        export_path = os.path.join(self.temp_dir, "test_bh")
        bloodbash_globals['export_bloodhound_compatible'](G, output_prefix=export_path)
        bh_file = f"{export_path}.json"
        self.assertTrue(os.path.exists(bh_file))
        with open(bh_file, 'r') as f:
            data = json.load(f)
            self.assertIn("nodes", data)
            self.assertIn("relationships", data)
            self.assertEqual(data["meta"]["generator"], "BloodBash")
    def test_export_to_dot(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User")
        G.add_node("DA", name="DA", type="Group")
        G.add_edge("U", "DA", label="MemberOf")
        dot_path = os.path.join(self.temp_dir, "test.dot")
        bloodbash_globals['export_to_dot'](G, dot_path)
        self.assertTrue(os.path.exists(dot_path))
        with open(dot_path, 'r') as f:
            content = f.read()
            self.assertIn("digraph BloodBash", content)
            self.assertIn("User", content)
            self.assertIn("MemberOf", content)
    def test_gpo_content_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_path = os.path.join(tmp, "testgpo.xml")
            with open(xml_path, "w") as f:
                f.write("""<GPO><Name>TestGPO</Name><ScheduledTasks><Task><Name>EvilTask</Name><Command>powershell.exe</Command></Task></ScheduledTasks></GPO>""")
            G = nx.MultiDiGraph()
            G.add_node("GPO1", name="TestGPO", type="GPO")
            output = self._capture_output(bloodbash_globals['print_gpo_content_analysis'], G, gpo_content_dir=tmp)
            self.assertIn("Exploitable Scheduled Task", output)
            self.assertIn("EvilTask", output)
    def test_full_new_features_integration(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="LowPriv@LAB.LOCAL", type="User")
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group")
        G.add_edge("U", "DA", label="MemberOf")
        bloodbash_globals['global_findings'] = []
        self._capture_output(bloodbash_globals['print_paths_to_owned'], G, "LowPriv")
        self._capture_output(bloodbash_globals['print_arbitrary_paths'], G, path_from="LowPriv", path_to="DOMAIN ADMINS")
        self._capture_output(bloodbash_globals['print_group_analysis'], G)
        self._capture_output(bloodbash_globals['print_stats_dashboard'], G)
        self.assertGreater(len(bloodbash_globals['global_findings']), 0)
    # ────────────────────────────────────────────────
    # NEW TESTS for AzureHound support (v1.3.1)
    # ────────────────────────────────────────────────
    def test_azure_privileged_roles(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_azure_privileged_roles'], G)
        self._assert_output_contains(output, "Privileged Azure role", "Global Administrator")
        self.assertTrue(any("Azure Privileged Roles" in f[1] for f in bloodbash_globals['global_findings']))
    def test_azure_app_secrets(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_azure_app_secrets'], G)
        # Credential presence alone is not reported; Owns/AddSecret paths are
        self._assert_output_contains(output, "credential abuse path", "Owns")
        self.assertTrue(any("Azure App Secrets" in f[1] for f in bloodbash_globals['global_findings']))
    def test_azure_mfa_bypass(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_azure_mfa_bypass'], G)
        # Fixture sets mfaEnrolled: false explicitly — still a finding
        self._assert_output_contains(output, "Azure user without MFA")
        self.assertTrue(any("Azure MFA Bypass" in f[1] for f in bloodbash_globals['global_findings']))

    def test_azure_mfa_unknown_not_flagged(self):
        """Missing MFA fields must not be treated as MFA bypass."""
        G = nx.MultiDiGraph()
        G.add_node(
            "u1",
            name="no-mfa-fields@tenant.com",
            type="Azure User",
            props={"userType": "Member"},
            is_azure=True,
        )
        bloodbash_globals['global_findings'] = []
        output = self._capture_output(bloodbash_globals['print_azure_mfa_bypass'], G)
        clean = self._strip_ansi(output)
        self.assertIn("not present in data", clean)
        self.assertFalse(any("Azure MFA Bypass" in f[1] for f in bloodbash_globals['global_findings']))

    def test_azure_app_secrets_not_flag_presence_only(self):
        """keyCredentials alone without control rights is not a finding."""
        G = nx.MultiDiGraph()
        G.add_node(
            "a1",
            name="NormalApp",
            type="Azure Application",
            props={"keyCredentials": [{"keyId": "k1"}]},
            is_azure=True,
        )
        bloodbash_globals['global_findings'] = []
        output = self._capture_output(bloodbash_globals['print_azure_app_secrets'], G)
        clean = self._strip_ansi(output)
        self.assertIn("credential presence alone", clean)
        self.assertFalse(any("Azure App Secrets" in f[1] for f in bloodbash_globals['global_findings']))
    def test_azure_guest_access(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_azure_guest_access'], G)
        self._assert_output_contains(output, "Azure guest", "HasRole")
        self.assertTrue(any("Azure Guest Access" in f[1] for f in bloodbash_globals['global_findings']))
    def test_azure_service_principal_abuse(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_azure_service_principal_abuse'], G)
        self._assert_output_contains(output, "Azure SP with dangerous rights", "GenericAll")
        self.assertTrue(any("Azure Service Principal Abuse" in f[1] for f in bloodbash_globals['global_findings']))
    def test_azure_high_value_targets(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        targets = bloodbash_globals['get_high_value_targets'](G)
        target_names = [name for _, name, _ in targets]
        self.assertTrue(any("global administrator" in name.lower() for name in target_names))
    def test_azure_shortest_paths(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        self._assert_output_contains(
            output,
            "Global Administrator",
            "globaladmin@tenant.onmicrosoft.com",
            "HasRole",
        )
    def test_azure_dangerous_permissions(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G)
        self._assert_output_contains(output, "GenericAll", "Azure Role")
    def test_azure_verbose_summary(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_verbose_summary'], G)
        self._assert_output_contains(output, "Azure Objects", "Azure User")
    def test_azure_trust_abuse(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_trust_abuse'], G)
        self._assert_output_contains(output, "Domain trust", "Cross-Tenant")
    def test_azure_group_analysis(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_group_analysis'], G)
        clean = self._strip_ansi(output).lower()
        self.assertIn("azuregroup", clean)
        self.assertIn("nesting depth", clean)
    def test_azure_full_analysis_integration(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        self._capture_output(bloodbash_globals['print_azure_privileged_roles'], G)
        self._capture_output(bloodbash_globals['print_azure_app_secrets'], G)
        self._capture_output(bloodbash_globals['print_azure_mfa_bypass'], G)
        self._capture_output(bloodbash_globals['print_azure_guest_access'], G)
        self._capture_output(bloodbash_globals['print_azure_service_principal_abuse'], G)
        self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        self._capture_output(bloodbash_globals['print_dangerous_permissions'], G)
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Prioritized Findings", output)
        self.assertGreater(len(bloodbash_globals['global_findings']), 0)
    # ────────────────────────────────────────────────
    # FIXES for failing tests
    # ────────────────────────────────────────────────
    def test_adcs_vulnerabilities_fixed(self):
        # Ensure findings are added during the test
        G = nx.MultiDiGraph()
        # Simulate ADCS template with ESC1 conditions
        G.add_node("Template1", name="VulnTemplate", type="Certificate Template", props={"enrolleesuppliessubject": True, "requiresmanagerapproval": False})
        G.add_node("User1", name="User1", type="User")
        G.add_edge("User1", "Template1", label="Enroll")
        bloodbash_globals['global_findings'] = []  # Reset findings
        output = self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        self.assertIn("ESC1", output)
        self.assertNotIn("ESC1/ESC2", output)
        self.assertGreater(len(bloodbash_globals['global_findings']), 0)  # Ensure findings were added

    def test_adcs_esc_labels_specterops(self):
        """ESC labels must match SpecterOps Certified Pre-Owned numbering."""
        G = nx.MultiDiGraph()
        # ESC1: ESS + enroll + no approval
        G.add_node("T1", name="ESC1-Template", type="Certificate Template",
                   props={"enrolleesuppliessubject": True, "requiresmanagerapproval": False,
                          "ekus": ["1.3.6.1.5.5.7.3.2"]})
        G.add_node("U1", name="LowPriv", type="User", props={})
        G.add_edge("U1", "T1", label="Enroll")
        # ESC3: Enrollment Agent EKU
        G.add_node("T3", name="ESC3-Template", type="Certificate Template",
                   props={"ekus": ["1.3.6.1.4.1.311.20.2.1"], "requiresmanagerapproval": False})
        G.add_edge("U1", "T3", label="Enroll")
        # ESC4: dangerous ACL on template
        G.add_node("T4", name="ESC4-Template", type="Certificate Template",
                   props={"requiresmanagerapproval": True})
        G.add_edge("U1", "T4", label="WriteDacl")
        # ESC7: ManageCA on enterprise CA
        G.add_node("CA1", name="ESC7-CA", type="Enterprise CA", props={})
        G.add_edge("U1", "CA1", label="ManageCA")
        # ESC5: GenericAll on CA (PKI object control, not ManageCA)
        G.add_node("CA2", name="ESC5-CA", type="Enterprise CA", props={})
        G.add_edge("U1", "CA2", label="GenericAll")
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_adcs_vulnerabilities"], G)
        self.assertIn("ESC1", output)
        self.assertIn("ESC3", output)
        self.assertIn("ESC4", output)
        self.assertIn("ESC5", output)
        self.assertIn("ESC7", output)
        # Enrollment agent EKU must be ESC3, not ESC5 (old bug)
        self.assertIn("ESC3: ESC3-Template", self._strip_ansi(output))
        self.assertNotIn("ESC5: ESC3-Template", self._strip_ansi(output))
        # Template ACL abuse is ESC4, not ESC3
        self.assertIn("ESC4: ESC4-Template", self._strip_ansi(output))
        findings = " ".join(f[2] for f in bloodbash_globals["global_findings"])
        self.assertIn("ESC1 on", findings)
        self.assertIn("ESC3 on", findings)
        self.assertIn("ESC4 on", findings)
        self.assertIn("ESC7 on", findings)    # ────────────────────────────────────────────────
    # Tests for decode_uac() (UAC attribute translation)
    # ────────────────────────────────────────────────
    def test_decode_uac_single_flag(self):
        # 0x2 = ACCOUNTDISABLE
        result = bloodbash_globals['decode_uac'](2)
        self.assertIn("2", result)
        self.assertIn("ACCOUNTDISABLE", result)

    def test_decode_uac_multiple_flags(self):
        # 514 = 0x202 = ACCOUNTDISABLE (0x2) + NORMAL_ACCOUNT (0x200)
        result = bloodbash_globals['decode_uac'](514)
        self.assertIn("514", result)
        self.assertIn("ACCOUNTDISABLE", result)
        self.assertIn("NORMAL_ACCOUNT", result)

    def test_decode_uac_dont_expire_password(self):
        # 66048 = 0x10200 = NORMAL_ACCOUNT (0x200) + DONT_EXPIRE_PASSWORD (0x10000)
        result = bloodbash_globals['decode_uac'](66048)
        self.assertIn("DONT_EXPIRE_PASSWORD", result)
        self.assertIn("NORMAL_ACCOUNT", result)

    def test_decode_uac_dont_req_preauth(self):
        # 0x400000 = DONT_REQ_PREAUTH (AS-REP roastable flag)
        result = bloodbash_globals['decode_uac'](0x400000)
        self.assertIn("DONT_REQ_PREAUTH", result)

    def test_decode_uac_string_integer_input(self):
        # decode_uac should accept a numeric string and parse it correctly
        result = bloodbash_globals['decode_uac']("512")
        self.assertIn("512", result)
        self.assertIn("NORMAL_ACCOUNT", result)

    def test_decode_uac_zero_no_flags(self):
        # 0 matches no bitmask, should return "0" without any flag name
        result = bloodbash_globals['decode_uac'](0)
        self.assertEqual(result, "0")

    def test_decode_uac_invalid_input(self):
        # Non-numeric string should be returned as-is
        result = bloodbash_globals['decode_uac']("not_a_number")
        self.assertEqual(result, "not_a_number")

    def test_decode_uac_in_kerberoastable_output(self):
        # Verify that UAC is displayed alongside kerberoastable users
        G = nx.MultiDiGraph()
        # 512 = NORMAL_ACCOUNT, a common UAC value for enabled accounts
        G.add_node("K", name="KerbUACUser@LAB.LOCAL", type="User", props={
            "hasspn": True,
            "sensitive": False,
            "enabled": True,
            "useraccountcontrol": 512,
        })
        output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        self.assertIn("KerbUACUser@LAB.LOCAL", output)
        self.assertIn("NORMAL_ACCOUNT", output)

    def test_decode_uac_in_asrep_output(self):
        # Verify that UAC is displayed alongside AS-REP roastable users
        G = nx.MultiDiGraph()
        # 4194816 = NORMAL_ACCOUNT (0x200) + DONT_REQ_PREAUTH (0x400000)
        G.add_node("A", name="AsRepUACUser@LAB.LOCAL", type="User", props={
            "dontreqpreauth": True,
            "sensitive": False,
            "enabled": True,
            "useraccountcontrol": 0x400200,
        })
        output = self._capture_output(bloodbash_globals['print_as_rep_roastable'], G)
        self.assertIn("AsRepUACUser@LAB.LOCAL", output)
        self.assertIn("DONT_REQ_PREAUTH", output)

    # ────────────────────────────────────────────────
    # Additional coverage: fixtures, helpers, dependencies
    # ────────────────────────────────────────────────
    def test_password_never_expires(self):
        G = self._load_and_build_graph("password-never-expires-tests")
        output = self._capture_output(bloodbash_globals['print_password_never_expires'], G)
        self._assert_output_contains(output, "Password Never Expires enabled", "User1", "User3")
        clean = self._strip_ansi(output)
        self.assertEqual(clean.count("Password Never Expires enabled"), 2)

    def test_password_not_required(self):
        G = self._load_and_build_graph("password-not-required-tests")
        output = self._capture_output(bloodbash_globals['print_password_not_required'], G)
        self._assert_output_contains(output, "Password Not Required enabled", "User1", "User3")
        self.assertTrue(any("Password Not Required" in f[1] for f in bloodbash_globals['global_findings']))

    def test_export_yaml(self):
        G = self._load_and_build_graph("yaml-export-tests")
        bloodbash_globals['add_finding']("YAMLTest", "Finding for yaml export")
        export_path = os.path.join(self.temp_dir, "yaml_export")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="yaml")
        yaml_file = f"{export_path}.yaml"
        self.assertTrue(os.path.exists(yaml_file))
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = bloodbash_globals['yaml'].safe_load(f)
        self.assertEqual(data['nodes'], G.number_of_nodes())
        self.assertIn('high_value', data)
        self.assertIn('findings', data)
        self.assertTrue(any(f.get("details") == "Finding for yaml export" for f in data["findings"]))

    def test_export_formats_findings_parity(self):
        """All --export formats share the same high-value + findings report model."""
        G = nx.MultiDiGraph()
        G.add_node("DA", name="Domain Admins", type="Group", props={"domain": "TEST.LOCAL"})
        G.add_node("U", name="Alice", type="User", props={"domain": "TEST.LOCAL"})
        bloodbash_globals['global_findings'] = []
        bloodbash_globals['add_finding']("DCSync", "Alice can DCSync", score=10)
        bloodbash_globals['add_finding']("Kerberoastable", "svc has SPN", score=5)
        report = bloodbash_globals['build_export_report'](G)
        self.assertEqual(report["nodes"], 2)
        self.assertEqual(len(report["findings"]), 2)
        self.assertEqual(report["findings"][0]["category"], "DCSync")  # higher score first
        self.assertTrue(any(h["name"] == "Domain Admins" for h in report["high_value"]))

        export_path = os.path.join(self.temp_dir, "parity")
        for fmt, suffix in [("md", ".md"), ("json", ".json"), ("html", ".html"),
                            ("csv", ".csv"), ("yaml", ".yaml")]:
            bloodbash_globals['export_results'](G, output_prefix=export_path, format_type=fmt)
            path = f"{export_path}{suffix}"
            self.assertTrue(os.path.exists(path), f"missing {path}")
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn("DCSync", content)
            self.assertIn("Alice can DCSync", content)
            if fmt != "csv":
                # CSV is findings-only; other formats also list high-value targets
                self.assertIn("Domain Admins", content)

        with open(f"{export_path}.json", 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        with open(f"{export_path}.yaml", 'r', encoding='utf-8') as f:
            yaml_data = bloodbash_globals['yaml'].safe_load(f)
        self.assertEqual(json_data["nodes"], yaml_data["nodes"])
        self.assertEqual(json_data["edges"], yaml_data["edges"])
        self.assertEqual(
            [(f["score"], f["category"], f["details"]) for f in json_data["findings"]],
            [(f["score"], f["category"], f["details"]) for f in yaml_data["findings"]],
        )

    # ────────────────────────────────────────────────
    # v1.4 PlumHound-inspired reporting features
    # ────────────────────────────────────────────────
    def _path_demo_graph(self):
        """User -> Group -> DA style graph for path/busiest/break tests."""
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={"domain": "LAB.LOCAL", "highvalue": True}, is_azure=False)
        G.add_node("G1", name="IT HELPDESK@LAB.LOCAL", type="Group", props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("C1", name="JUMP01.LAB.LOCAL", type="Computer", props={"domain": "LAB.LOCAL"}, is_azure=False)
        G.add_node("U1", name="ALICE@LAB.LOCAL", type="User", props={"domain": "LAB.LOCAL", "enabled": True}, is_azure=False)
        G.add_node("U2", name="BOB@LAB.LOCAL", type="User", props={"domain": "LAB.LOCAL", "enabled": True}, is_azure=False)
        G.add_node("U3", name="CAROL@LAB.LOCAL", type="User", props={"domain": "LAB.LOCAL", "enabled": True}, is_azure=False)
        # Paths: Alice/Bob via helpdesk; Carol via jump host AdminTo
        G.add_edge("U1", "G1", label="MemberOf")
        G.add_edge("U2", "G1", label="MemberOf")
        G.add_edge("G1", "DA", label="MemberOf")
        G.add_edge("U3", "C1", label="AdminTo")
        G.add_edge("C1", "DA", label="HasSession")
        return G

    def test_parse_ad_timestamp_unix_and_filetime(self):
        parse = bloodbash_globals["parse_ad_timestamp"]
        self.assertIsNone(parse(0))
        self.assertIsNone(parse(-1))
        self.assertIsNone(parse(None))
        self.assertAlmostEqual(parse(1_700_000_000), 1_700_000_000.0)
        # Windows FILETIME for a known-ish modern range
        ft = int((1_700_000_000 + 11644473600) * 10_000_000)
        self.assertAlmostEqual(parse(ft), 1_700_000_000.0, places=0)

    def test_password_age_buckets(self):
        now = 2_000_000_000.0
        G = nx.MultiDiGraph()
        G.add_node("U1", name="New@LAB.LOCAL", type="User", props={
            "domain": "LAB.LOCAL", "pwdlastset": now - 3600, "enabled": True,
        }, is_azure=False)
        G.add_node("U2", name="Old@LAB.LOCAL", type="User", props={
            "domain": "LAB.LOCAL", "pwdlastset": now - (400 * 86400), "enabled": True,
        }, is_azure=False)
        G.add_node("U3", name="Never@LAB.LOCAL", type="User", props={
            "domain": "LAB.LOCAL", "pwdlastset": 0, "enabled": True,
        }, is_azure=False)
        rows = bloodbash_globals["collect_password_age_rows"](G, now=now)
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["New@LAB.LOCAL"]["bucket"], "< 1 day")
        self.assertEqual(by_name["Old@LAB.LOCAL"]["bucket"], "> 1 year")
        self.assertEqual(by_name["Never@LAB.LOCAL"]["bucket"], "Never set / unknown")

    def test_stale_account_buckets(self):
        now = 2_000_000_000.0
        G = nx.MultiDiGraph()
        G.add_node("U1", name="Active@LAB.LOCAL", type="User", props={
            "domain": "LAB.LOCAL", "lastlogontimestamp": now - (10 * 86400), "enabled": True,
        }, is_azure=False)
        G.add_node("U2", name="Stale@LAB.LOCAL", type="User", props={
            "domain": "LAB.LOCAL", "lastlogontimestamp": now - (400 * 86400), "enabled": True,
        }, is_azure=False)
        G.add_node("U3", name="Ghost@LAB.LOCAL", type="User", props={
            "domain": "LAB.LOCAL", "lastlogon": 0, "enabled": True,
        }, is_azure=False)
        rows = bloodbash_globals["collect_stale_account_rows"](G, now=now)
        by_name = {r["name"]: r for r in rows}
        self.assertEqual(by_name["Active@LAB.LOCAL"]["bucket"], "Active < 6 months")
        self.assertEqual(by_name["Stale@LAB.LOCAL"]["bucket"], "Inactive > 12 months")
        self.assertEqual(by_name["Ghost@LAB.LOCAL"]["bucket"], "Never active / unknown")

    def test_busiest_paths_and_path_breaks(self):
        G = self._path_demo_graph()
        busiest = bloodbash_globals["collect_busiest_paths"](G, mode="short", top=5)
        self.assertTrue(busiest)
        # Helpdesk group is on two user paths
        names = {b["name"] for b in busiest}
        self.assertTrue(any("HELPDESK" in n or "JUMP" in n for n in names))

        breaks = bloodbash_globals["collect_path_breaks"](G, top=10)
        self.assertTrue(breaks)
        self.assertGreaterEqual(breaks[0]["paths_broken"], 1)
        self.assertIn("Remove relationship", breaks[0]["recommendation"])

        bloodbash_globals["global_findings"] = []
        out = self._capture_output(bloodbash_globals["print_busiest_paths"], G, mode="short", top=3)
        self._assert_output_contains(out, "Busiest Paths")
        out2 = self._capture_output(bloodbash_globals["print_path_breaks"], G, top=5)
        self._assert_output_contains(out2, "Removing")

    def test_privilege_and_owned_inventory(self):
        G = self._path_demo_graph()
        G.nodes["DA"]["props"]["highvalue"] = True
        priv = bloodbash_globals["collect_privilege_inventory"](G)
        self.assertTrue(any("DOMAIN ADMINS" in r["group"] for r in priv))
        owned = bloodbash_globals["collect_owned_inventory"](G, "ALICE")
        self.assertEqual(len(owned), 1)
        self.assertGreaterEqual(owned[0]["member_of_count"], 1)

    def test_report_pack_and_zip(self):
        G = self._path_demo_graph()
        bloodbash_globals["global_findings"] = []
        bloodbash_globals["add_finding"]("DCSync", "demo", score=10)
        pack_dir = os.path.join(self.temp_dir, "pack")
        written = bloodbash_globals["export_report_pack"](
            G, pack_dir, owned="ALICE", busiest_mode="short", fast=True
        )
        self.assertTrue(written)
        index = os.path.join(pack_dir, "index.html")
        self.assertTrue(os.path.exists(index))
        with open(index, "r", encoding="utf-8") as f:
            idx = f.read()
        self.assertIn("Report Index", idx)
        self.assertIn("sortable", open(os.path.join(pack_dir, "findings.html"), encoding="utf-8").read())
        self.assertTrue(os.path.exists(os.path.join(pack_dir, "csv", "findings.csv")))
        self.assertTrue(os.path.exists(os.path.join(pack_dir, "csv", "busiest_paths.csv")))
        self.assertTrue(os.path.exists(os.path.join(pack_dir, "path_breaks.html")))

        zip_path = os.path.join(self.temp_dir, "out.zip")
        bloodbash_globals["export_zip_pack"](pack_dir, zip_path)
        self.assertTrue(os.path.exists(zip_path))
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
        self.assertIn("index.html", names)
        self.assertTrue(any(n.startswith("csv/") for n in names))

    def test_export_csv_pack_core_files(self):
        """PlumHound-style multi-CSV pack writes inventory CSVs + index."""
        import time as _time
        G = nx.MultiDiGraph()
        G.add_node(
            "DOM",
            name="LAB.LOCAL",
            type="Domain",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL", "highvalue": True},
            is_azure=False,
        )
        G.add_node(
            "U1",
            name="ALICE@LAB.LOCAL",
            type="User",
            props={
                "domain": "LAB.LOCAL",
                "enabled": True,
                "hasspn": True,
                "dontreqpreauth": False,
                "pwdlastset": int(_time.time()) - 400 * 86400,
            },
            is_azure=False,
        )
        G.add_node(
            "U2",
            name="BOB@LAB.LOCAL",
            type="User",
            props={
                "domain": "LAB.LOCAL",
                "enabled": True,
                "dontreqpreauth": True,
                "passwordneverexpires": True,
            },
            is_azure=False,
        )
        G.add_node(
            "C1",
            name="PC01.LAB.LOCAL",
            type="Computer",
            props={"domain": "LAB.LOCAL", "haslaps": True, "operatingsystem": "Windows 10"},
            is_azure=False,
        )
        G.add_node(
            "C2",
            name="DC01.LAB.LOCAL",
            type="Computer",
            props={"domain": "LAB.LOCAL", "haslaps": False, "isdc": True},
            is_azure=False,
        )
        G.add_edge("U1", "DA", label="MemberOf")
        G.add_edge("C2", "DA", label="MemberOf")  # not accurate but ok for group list
        G.add_edge("U1", "C1", label="AdminTo")
        G.add_edge("C1", "U2", label="HasSession")
        pack_dir = os.path.join(self.temp_dir, "csvpack")
        written = bloodbash_globals["export_csv_pack"](G, pack_dir)
        self.assertTrue(written)
        expected = [
            "domains.csv",
            "domain_admins.csv",
            "users.csv",
            "computers.csv",
            "groups.csv",
            "kerberoastable.csv",
            "asrep_roastable.csv",
            "password_never_expires.csv",
            "laps_not_enabled.csv",
            "local_admins_users.csv",
            "user_sessions.csv",
            "index.csv",
            "README.txt",
        ]
        for name in expected:
            path = os.path.join(pack_dir, name)
            self.assertTrue(os.path.exists(path), msg=f"missing {name}")
        with open(os.path.join(pack_dir, "kerberoastable.csv"), encoding="utf-8") as f:
            content = f.read()
        self.assertIn("ALICE@LAB.LOCAL", content)
        with open(os.path.join(pack_dir, "asrep_roastable.csv"), encoding="utf-8") as f:
            content = f.read()
        self.assertIn("BOB@LAB.LOCAL", content)
        with open(os.path.join(pack_dir, "index.csv"), encoding="utf-8") as f:
            idx = f.read()
        self.assertIn("kerberoastable.csv", idx)
        self.assertIn("RowCount", idx)

    def test_csv_pack_cli_flag_in_help(self):
        out = self._capture_output(bloodbash_globals["print_structured_help"], "BloodBash.py")
        clean = self._strip_ansi(out)
        self.assertIn("--csv-pack", clean)

    def test_apply_quick_wins_preset_enables_best_checks(self):
        """--quick-wins enables the high-value triage set without --all."""
        ns = bloodbash_globals["build_arg_parser"]().parse_args(["./data", "--quick-wins"])
        self.assertTrue(ns.quick_wins)
        bloodbash_globals["apply_quick_wins_to_args"](ns)
        # Core privilege / credential quick wins
        self.assertTrue(ns.dcsync)
        self.assertTrue(ns.adcs)
        self.assertTrue(ns.dangerous_permissions)
        self.assertTrue(ns.rbcd)
        self.assertTrue(ns.kerberoastable)
        self.assertTrue(ns.as_rep_roastable)
        self.assertTrue(ns.privileged_roast)
        self.assertTrue(ns.unconstrained_delegation)
        self.assertTrue(ns.shadow_credentials)
        self.assertTrue(ns.laps)
        self.assertTrue(ns.password_descriptions)
        self.assertTrue(ns.password_not_required)
        self.assertTrue(ns.sessions)
        self.assertTrue(ns.shortest_paths)
        self.assertTrue(ns.path_break)
        self.assertEqual(ns.busiest_paths, "short")
        self.assertTrue(ns.fast)
        self.assertTrue(ns.verbose)
        self.assertTrue(ns.all_findings)
        # Not a full --all dump
        self.assertFalse(ns.all)
        self.assertFalse(ns.deep_analysis)
        self.assertFalse(ns.gpo_parsing)

    def test_quick_wins_cli_flag_in_help(self):
        out = self._capture_output(bloodbash_globals["print_structured_help"], "BloodBash.py")
        clean = self._strip_ansi(out)
        self.assertIn("--quick-wins", clean)
        self.assertIn("Quick wins", clean)

    def test_quick_wins_does_not_override_explicit_false_fast(self):
        """User can still add flags; apply only turns checks on, doesn't force all."""
        ns = bloodbash_globals["build_arg_parser"]().parse_args(
            ["./data", "--quick-wins", "--dcsync"]
        )
        bloodbash_globals["apply_quick_wins_to_args"](ns)
        self.assertTrue(ns.dcsync)
        self.assertTrue(ns.privileged_roast)

    def test_csv_pack_computer_adminto_computer(self):
        G = nx.MultiDiGraph()
        G.add_node("C1", name="JUMP.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("C2", name="TARGET.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("U1", name="USER@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("C1", "C2", label="AdminTo")
        G.add_edge("U1", "C2", label="AdminTo")  # user should not appear in computer-computer
        pack = os.path.join(self.temp_dir, "csv-c2c")
        bloodbash_globals["export_csv_pack"](G, pack)
        with open(os.path.join(pack, "computer_adminto_computer.csv"), encoding="utf-8") as f:
            data = f.read()
        self.assertIn("JUMP.LAB.LOCAL", data)
        self.assertIn("TARGET.LAB.LOCAL", data)
        self.assertNotIn("USER@LAB.LOCAL", data)

    def test_csv_pack_dual_lowpriv_and_da(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_node(
            "U",
            name="MERGED@LAB.LOCAL",
            type="User",
            props={"enabled": True, "admincount": False},
            is_azure=False,
        )
        G.add_node(
            "C",
            name="WS.LAB.LOCAL",
            type="Computer",
            props={},
            is_azure=False,
        )
        # Nested into DA but also has low-priv-looking AdminTo (dual use)
        G.add_edge("U", "DA", label="MemberOf")
        G.add_edge("U", "C", label="AdminTo")
        pack = os.path.join(self.temp_dir, "csv-dual")
        bloodbash_globals["export_csv_pack"](G, pack)
        with open(os.path.join(pack, "dual_privileged_and_local_admin.csv"), encoding="utf-8") as f:
            data = f.read()
        self.assertIn("MERGED@LAB.LOCAL", data)
        self.assertIn("WS.LAB.LOCAL", data)

    def test_csv_pack_bulk_adminto_hosts(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="HELP@LAB.LOCAL", type="User", props={}, is_azure=False)
        for i in range(3):
            G.add_node(f"C{i}", name=f"PC{i}.LAB.LOCAL", type="Computer", props={}, is_azure=False)
            G.add_edge("U", f"C{i}", label="AdminTo")
        pack = os.path.join(self.temp_dir, "csv-bulk")
        bloodbash_globals["export_csv_pack"](G, pack)
        with open(os.path.join(pack, "bulk_adminto_hosts.csv"), encoding="utf-8") as f:
            data = f.read()
        self.assertIn("HELP@LAB.LOCAL", data)
        self.assertIn("3", data)
        self.assertIn("PC0.LAB.LOCAL", data)

    def test_csv_pack_everyone_and_overpriv_relationships(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "EVERY",
            name="EVERYONE@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "AUTH",
            name="AUTHENTICATED USERS@LAB.LOCAL",
            type="Group",
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
            "T",
            name="SERVER01.LAB.LOCAL",
            type="Computer",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "GPO",
            name="DEFAULT DOMAIN POLICY@LAB.LOCAL",
            type="GPO",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_edge("EVERY", "T", label="GenericAll")
        G.add_edge("AUTH", "T", label="GenericWrite")
        G.add_edge("DU", "GPO", label="WriteDacl")
        pack_dir = os.path.join(self.temp_dir, "csv-everyone")
        bloodbash_globals["export_csv_pack"](G, pack_dir)
        with open(os.path.join(pack_dir, "relationships_everyone.csv"), encoding="utf-8") as f:
            everyone = f.read()
        self.assertIn("EVERYONE@LAB.LOCAL", everyone)
        self.assertIn("GenericAll", everyone)
        self.assertIn("SERVER01.LAB.LOCAL", everyone)
        with open(os.path.join(pack_dir, "relationships_authenticated_users.csv"), encoding="utf-8") as f:
            auth = f.read()
        self.assertIn("AUTHENTICATED USERS", auth)
        with open(os.path.join(pack_dir, "relationships_domain_users.csv"), encoding="utf-8") as f:
            du = f.read()
        self.assertIn("DOMAIN USERS", du)
        self.assertIn("WriteDacl", du)
        with open(os.path.join(pack_dir, "overprivileged_relationships.csv"), encoding="utf-8") as f:
            over = f.read()
        self.assertIn("EVERYONE", over)
        self.assertIn("AUTHENTICATED USERS", over)
        self.assertIn("DOMAIN USERS", over)

    def test_html_export_sortable_branded(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="Domain Admins", type="Group", props={})
        bloodbash_globals["global_findings"] = []
        bloodbash_globals["add_finding"]("Test", "details", score=5)
        export_path = os.path.join(self.temp_dir, "branded")
        bloodbash_globals["export_results"](G, output_prefix=export_path, format_type="html")
        with open(f"{export_path}.html", "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("sortable", html)
        self.assertIn("SquidSec", html)
        self.assertIn("BloodBash", html)

    def test_load_builtin_profile(self):
        profile = bloodbash_globals["load_analysis_profile"]("quick")
        self.assertIsInstance(profile, dict)
        self.assertTrue(profile.get("fast") or "checks" in profile)
        # Apply to a fake args namespace
        import argparse
        ns = argparse.Namespace(
            all=False, fast=False, verbose=False, indirect=False, domain=None, owned=None,
            export=None, export_bh=False, dot=None, db=None, path_from=None, path_to=None,
            inspect=None, gpo_content_dir=None, busiest_paths=None, busiest_paths_top=5,
            path_break=False, path_break_top=15, inventory=False, password_age=False,
            stale_accounts=False, privilege_inventory=False, owned_inventory=False,
            report_pack=None, export_zip=None, log_file=None, dcsync=False, adcs=False,
            dangerous_permissions=False, kerberoastable=False, as_rep_roastable=False,
            password_never_expires=False, password_not_required=False, password_descriptions=False,
            shortest_paths=False, gpo_abuse=False, rbcd=False, sessions=False, sid_history=False,
            unconstrained_delegation=False, shadow_credentials=False, gpo_parsing=False,
            constrained_delegation=False, laps=False, azure_privileged_roles=False,
            azure_app_secrets=False, azure_mfa_bypass=False, azure_guest_access=False,
            azure_sp_abuse=False, deep_analysis=False,
        )
        bloodbash_globals["apply_profile_to_args"](ns, profile)
        self.assertTrue(ns.fast or ns.dcsync or ns.inventory or ns.path_break or ns.password_age)

    def test_run_logging(self):
        log_path = os.path.join(self.temp_dir, "test-run.log")
        resolved = bloodbash_globals["setup_run_logging"](log_path)
        self.assertEqual(resolved, os.path.abspath(log_path))
        bloodbash_globals["logger"].info("unit-test-log-line")
        # ensure handlers flush
        for h in list(bloodbash_globals["logging"].getLogger().handlers):
            h.flush()
        with open(log_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("unit-test-log-line", content)

    def test_get_bool_prop_ci(self):
        props = {"PasswordNeverExpires": True, "enabled": False}
        self.assertTrue(bloodbash_globals['get_bool_prop_ci'](props, ['passwordneverexpires']))
        self.assertFalse(bloodbash_globals['get_bool_prop_ci'](props, ['passwordnotrequired']))
        self.assertFalse(bloodbash_globals['get_bool_prop_ci'](None, ['enabled']))

    def test_pne_kerb_false_negatives_from_real_collector_quirks(self):
        """Regression: --password-never-expires / --kerberoastable returned 0 despite
        flags present in raw SharpHound JSON.

        Covers: lowercase ``properties`` bag, missing meta.type (filename/type fallback),
        SPN list without hasspn, case-insensitive --domain, krbtgt exclusion.
        """
        G = self._load_and_build_graph("pne-kerb-false-negatives-tests")
        types = {d["type"] for _, d in G.nodes(data=True)}
        self.assertIn("User", types)

        pne_out = self._capture_output(
            bloodbash_globals["print_password_never_expires"], G
        )
        self._assert_output_contains(pne_out, "PNEUSER@CONTOSO.COM")
        self.assertNotIn("No users with 'Password Never Expires' found", self._strip_ansi(pne_out))

        # Case-insensitive domain filter (props.domain is contoso.com)
        pne_filtered = self._capture_output(
            bloodbash_globals["print_password_never_expires"], G, "CONTOSO.COM"
        )
        self._assert_output_contains(pne_filtered, "PNEUSER@CONTOSO.COM")

        kerb_out = self._capture_output(
            bloodbash_globals["print_kerberoastable"], G
        )
        clean = self._strip_ansi(kerb_out)
        self.assertIn("SVC_SQL@CONTOSO.COM", clean)
        self.assertNotIn("KRBTGT@CONTOSO.COM", clean)
        self.assertNotIn("None found", clean)

        # SPN helper: list alone is enough
        self.assertTrue(
            bloodbash_globals["_user_has_spn"](
                {"serviceprincipalnames": ["HTTP/app.contoso.com"]}
            )
        )
        self.assertFalse(bloodbash_globals["_user_has_spn"]({"hasspn": False}))

    def test_domain_matches_case_insensitive(self):
        d = {
            "name": "ALICE@LAB.LOCAL",
            "props": {"domain": "lab.local"},
        }
        self.assertTrue(bloodbash_globals["_domain_matches"](d, "LAB.LOCAL"))
        self.assertTrue(bloodbash_globals["_domain_matches"](d, "lab.local"))
        self.assertFalse(bloodbash_globals["_domain_matches"](d, "other.local"))
        self.assertTrue(bloodbash_globals["_domain_matches"](d, None))

    def test_extract_props_lowercase_and_type_from_filename(self):
        item = {
            "ObjectIdentifier": "S-1-5-21-9-9-9-1",
            "properties": {"name": "X@Y.Z", "type": "User", "pwdneverexpires": True},
        }
        props = bloodbash_globals["_extract_node_props"](item)
        self.assertEqual(props.get("name"), "X@Y.Z")
        self.assertEqual(
            bloodbash_globals["_resolve_object_type"]("", item, "20240101_users.json"),
            "User",
        )
        self.assertEqual(
            bloodbash_globals["_type_from_filename"]("20240305110018_users.json"),
            "User",
        )

    def test_get_object_id_azure_objectid(self):
        item = {"kind": "User", "objectId": "azure-user-abc", "name": "test@tenant.com"}
        self.assertEqual(bloodbash_globals['get_object_id'](item), "azure-user-abc")

    def test_get_object_id_nested_data_id(self):
        item = {"kind": "AZUser", "data": {"id": "/users/12345", "displayName": "Test"}}
        self.assertEqual(bloodbash_globals['get_object_id'](item), "/users/12345")

    def test_azure_graph_relationships_use_object_ids(self):
        nodes = bloodbash_globals['load_json_dir'](os.path.join(self.test_data_dir, AZURE_TEST_DIR))
        self.assertIn("azure-user-1", nodes)
        self.assertIn("azure-role-globaladmin", nodes)
        G, _ = bloodbash_globals['build_graph'](nodes)
        self.assertTrue(G.has_edge("azure-user-1", "azure-role-globaladmin"))
        edge_labels = [d.get('label') for _, _, d in G.edges("azure-user-1", data=True)]
        self.assertIn("HasRole", edge_labels)

    def test_load_json_zip_archive(self):
        with tempfile.TemporaryDirectory() as src_dir:
            fixture = os.path.join(self.test_data_dir, "kerberoastable-tests", "users.json")
            shutil.copy(fixture, os.path.join(src_dir, "users.json"))
            zip_path = os.path.join(self.temp_dir, "collector.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.write(os.path.join(src_dir, "users.json"), arcname="users.json")
            nodes = bloodbash_globals['load_json_dir'](zip_path)
            self.assertGreater(len(nodes), 0)
            G, _ = bloodbash_globals['build_graph'](nodes)
            self.assertGreater(G.number_of_nodes(), 0)

    def test_zip_slip_rejected(self):
        """Malicious zip members with path traversal must not extract outside the target dir."""
        zip_path = os.path.join(self.temp_dir, "evil.zip")
        # Craft a zip whose member path escapes the extract directory
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../../evil_zip_slip_payload.txt", b"pwned")
            zf.writestr("users.json", b'{"meta":{"type":"users"},"data":[]}')
        extract_to = Path(self.temp_dir) / "evil"
        outside = Path(self.temp_dir).parent / "evil_zip_slip_payload.txt"
        if outside.exists():
            outside.unlink()
        with self.assertRaises(ValueError):
            bloodbash_globals["_safe_extract_zip"](zip_path, extract_to)
        self.assertFalse(outside.exists(), msg="Zip Slip wrote outside extract directory")
        # load_json_dir should refuse and return empty nodes (not crash)
        nodes = bloodbash_globals["load_json_dir"](zip_path)
        self.assertEqual(nodes, {})

    def test_safe_extract_nested_ok(self):
        """Legitimate nested paths under extract_to still extract."""
        zip_path = os.path.join(self.temp_dir, "nested.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("subdir/users.json", b'{"meta":{"type":"users"},"data":[]}')
        extract_to = Path(self.temp_dir) / "nested_out"
        bloodbash_globals["_safe_extract_zip"](zip_path, extract_to)
        dest = extract_to / "subdir" / "users.json"
        self.assertTrue(dest.is_file())

    def test_primarygroupsid_memberof_edge(self):
        """PrimaryGroupSID becomes member → MemberOf → primary group."""
        nodes = {
            "S-1-5-21-1-2-3-1100": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-1100",
                "ObjectType": "User",
                "Properties": {"name": "alice@LAB.LOCAL", "domain": "lab.local"},
                "PrimaryGroupSID": "S-1-5-21-1-2-3-513",
            },
            "S-1-5-21-1-2-3-513": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-513",
                "ObjectType": "Group",
                "Properties": {"name": "DOMAIN USERS@LAB.LOCAL", "domain": "lab.local"},
            },
        }
        G, _ = bloodbash_globals["build_graph"](nodes)
        self.assertTrue(
            any(
                u == "S-1-5-21-1-2-3-1100"
                and v == "S-1-5-21-1-2-3-513"
                and d.get("label") == "MemberOf"
                for u, v, d in G.edges(data=True)
            )
        )

    def test_gpo_links_and_containedby_edges(self):
        """Domain/OU Links and ContainedBy become GPLink / Contains edges."""
        nodes = {
            "S-1-5-21-1-2-3": {
                "ObjectIdentifier": "S-1-5-21-1-2-3",
                "ObjectType": "Domain",
                "Properties": {"name": "LAB.LOCAL", "domain": "lab.local"},
                "Links": [{"GUID": "GPO-GUID-1", "IsEnforced": False}],
            },
            "GPO-GUID-1": {
                "ObjectIdentifier": "GPO-GUID-1",
                "ObjectType": "GPO",
                "Properties": {"name": "Default Domain Policy@LAB.LOCAL", "domain": "lab.local"},
            },
            "S-1-5-21-1-2-3-1100": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-1100",
                "ObjectType": "User",
                "Properties": {"name": "alice@LAB.LOCAL", "domain": "lab.local"},
                "ContainedBy": {
                    "ObjectIdentifier": "OU-1",
                    "ObjectType": "OU",
                },
            },
            "OU-1": {
                "ObjectIdentifier": "OU-1",
                "ObjectType": "OU",
                "Properties": {"name": "Users@LAB.LOCAL", "domain": "lab.local"},
            },
        }
        G, _ = bloodbash_globals["build_graph"](nodes)
        self.assertTrue(
            any(
                u == "S-1-5-21-1-2-3"
                and v == "GPO-GUID-1"
                and d.get("label") == "GPLink"
                for u, v, d in G.edges(data=True)
            )
        )
        self.assertTrue(
            any(
                u == "OU-1"
                and v == "S-1-5-21-1-2-3-1100"
                and d.get("label") == "Contains"
                for u, v, d in G.edges(data=True)
            )
        )

    def test_session_and_memberof_dedupe(self):
        """Same session/membership from multiple sources yields one edge."""
        nodes = {
            "S-1-5-21-1-2-3-4001": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-4001",
                "ObjectType": "Computer",
                "Properties": {"name": "PC01.LAB.LOCAL", "domain": "lab.local"},
                "Sessions": {
                    "Results": [{"UserSID": "S-1-5-21-1-2-3-4100"}],
                },
                "PrivilegedSessions": {
                    "Results": [{"UserSID": "S-1-5-21-1-2-3-4100"}],
                },
                "RegistrySessions": {
                    "Results": [{"UserSID": "S-1-5-21-1-2-3-4100"}],
                },
                "HasSession": [{"ObjectIdentifier": "S-1-5-21-1-2-3-4100"}],
            },
            "S-1-5-21-1-2-3-4100": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-4100",
                "ObjectType": "User",
                "Properties": {"name": "alice@LAB.LOCAL", "domain": "lab.local"},
                "MemberOf": [{"ObjectIdentifier": "S-1-5-21-1-2-3-512"}],
            },
            "S-1-5-21-1-2-3-512": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-512",
                "ObjectType": "Group",
                "Properties": {"name": "DOMAIN ADMINS@LAB.LOCAL", "domain": "lab.local"},
                "Members": [{"ObjectIdentifier": "S-1-5-21-1-2-3-4100", "ObjectType": "User"}],
            },
        }
        G, _ = bloodbash_globals["build_graph"](nodes)
        sessions = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "HasSession"
            and u == "S-1-5-21-1-2-3-4001"
            and v == "S-1-5-21-1-2-3-4100"
        ]
        self.assertEqual(len(sessions), 1)
        memberof = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "MemberOf"
            and u == "S-1-5-21-1-2-3-4100"
            and v == "S-1-5-21-1-2-3-512"
        ]
        self.assertEqual(len(memberof), 1)

    def test_aces_none_and_case_insensitive(self):
        """Null Aces must not crash; lowercase aces key still creates edges."""
        nodes = {
            "S-1-5-21-1-2-3-1": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-1",
                "ObjectType": "User",
                "Properties": {"name": "u@LAB.LOCAL"},
                "Aces": None,
            },
            "S-1-5-21-1-2-3-2": {
                "ObjectIdentifier": "S-1-5-21-1-2-3-2",
                "ObjectType": "User",
                "Properties": {"name": "v@LAB.LOCAL"},
                "aces": [
                    {"PrincipalSID": "S-1-5-21-1-2-3-9", "RightName": "GenericWrite"},
                ],
            },
        }
        G, _ = bloodbash_globals["build_graph"](nodes)
        self.assertTrue(
            any(
                u == "S-1-5-21-1-2-3-9"
                and v == "S-1-5-21-1-2-3-2"
                and d.get("label") == "GenericWrite"
                for u, v, d in G.edges(data=True)
            )
        )

    def test_db_roundtrip_preserves_edge_attrs(self):
        """SQLite save/load keeps sid_filtering and other edge attrs."""
        G = nx.MultiDiGraph()
        G.add_node("D1", name="A.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_node("D2", name="B.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_edge("D1", "D2", label="TrustedDomain:Bidirectional", sid_filtering=False)
        db_path = os.path.join(self.temp_dir, "edge-attrs.db")
        bloodbash_globals["save_graph_to_db"](G, db_path)
        G2, _ = bloodbash_globals["load_graph_from_db"](db_path)
        edges = list(G2.edges(data=True))
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0][2].get("label"), "TrustedDomain:Bidirectional")
        self.assertIs(edges[0][2].get("sid_filtering"), False)

    def test_sessions_and_localgroups_ingest(self):
        """SharpHound nested Sessions/LocalGroups become HasSession/LocalAdmin/etc edges."""
        try:
            G = self._load_and_build_graph("sessions-localgroups-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        computer = "S-1-5-21-1-2-3-4001"
        session_user = "S-1-5-21-1-2-3-4100"
        priv_user = "S-1-5-21-1-2-3-4101"
        helpdesk = "S-1-5-21-1-2-3-4102"
        # Computer → HasSession → User
        has_session = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "HasSession"
        ]
        self.assertIn((computer, session_user), has_session)
        self.assertIn((computer, priv_user), has_session)
        # principal → LocalAdmin → computer
        local_admin = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "LocalAdmin"
        ]
        self.assertIn((session_user, computer), local_admin)
        self.assertIn((helpdesk, computer), local_admin)
        # CanRDP / ExecuteDCOM
        can_rdp = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "CanRDP"
        ]
        self.assertIn((priv_user, computer), can_rdp)
        dcom = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "ExecuteDCOM"
        ]
        self.assertIn((helpdesk, computer), dcom)
        # print_sessions_localadmin should surface LocalAdmin counts
        output = self._capture_output(
            bloodbash_globals["print_sessions_localadmin"], G
        )
        self.assertIn("SESSIONUSER@LAB.LOCAL", output)
        self.assertIn("LocalAdmin", output)

    def test_sample_sessions_localgroups_edges(self):
        """Real sample data should yield HasSession and/or LocalAdmin edges."""
        sample_dir = "SampleSharphoundADData"
        if not os.path.isdir(sample_dir):
            self.skipTest(f"Sample directory '{sample_dir}' not present")
        nodes = bloodbash_globals["load_json_dir"](sample_dir)
        G, _ = bloodbash_globals["build_graph"](nodes)
        has_session = sum(
            1 for _, _, d in G.edges(data=True) if d.get("label") == "HasSession"
        )
        local_admin = sum(
            1 for _, _, d in G.edges(data=True) if d.get("label") == "LocalAdmin"
        )
        self.assertGreater(
            has_session + local_admin,
            0,
            msg="Sample data should produce HasSession and/or LocalAdmin edges",
        )

    def test_get_object_id_prefers_objectidentifier(self):
        item = {"ObjectIdentifier": "S-1-5-21-1-2-3-1000", "Properties": {"name": "U"}}
        self.assertEqual(bloodbash_globals["get_object_id"](item), "S-1-5-21-1-2-3-1000")
    def test_get_object_id_fallback_is_stable(self):
        """Fallback OIDs must be stable across calls (not process-randomized hash())."""
        item = {"Properties": {"name": "orphan-user", "domain": "lab.local"}, "Aces": []}
        oid1 = bloodbash_globals["get_object_id"](item)
        oid2 = bloodbash_globals["get_object_id"](item)
        self.assertEqual(oid1, oid2)
        self.assertTrue(oid1.startswith("synth-"), msg=oid1)
        self.assertEqual(len(oid1), len("synth-") + 32)
        # Same content → same id even if key order differs at construction time
        item_reordered = {"Aces": [], "Properties": {"domain": "lab.local", "name": "orphan-user"}}
        self.assertEqual(bloodbash_globals["get_object_id"](item_reordered), oid1)
        # Different content → different id
        other = {"Properties": {"name": "other-user", "domain": "lab.local"}, "Aces": []}
        self.assertNotEqual(bloodbash_globals["get_object_id"](other), oid1)

    def test_import_dependencies(self):
        for module_name in ("networkx", "rich", "tqdm", "yaml"):
            __import__(module_name)

    def test_cli_help(self):
        result = subprocess.run(
            [sys.executable, "BloodBash.py", "--help"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__)) or ".",
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        out = result.stdout
        # Structured Rich-table help (sections + key flags)
        self.assertIn("--azure-privileged-roles", out)
        self.assertIn("--export", out)
        self.assertIn("Flag / argument", out)
        self.assertIn("Description", out)
        self.assertIn("Notes / values", out)
        self.assertIn("Paths & remediation", out)
        self.assertIn("Export & deliverables", out)
        self.assertIn("Examples", out)
        self.assertIn("compromise dossier", out.lower())
        self.assertIn("--from-user", out)
        self.assertIn("--from-user-export", out)
        self.assertIn("--busiest-paths", out)
        self.assertIn("--report-pack", out)
        self.assertIn("--csv-pack", out)
        self.assertIn("--list-domains", out)
        self.assertIn("--privileged-roast", out)
        self.assertIn("--quick-wins", out)
        # Plenty of categorized examples
        self.assertIn("Examples — basics", out)
        self.assertIn("Examples — compromise dossier", out)
        self.assertIn("Examples — attack paths", out)
        self.assertIn("Examples — selective AD", out)
        self.assertIn("Examples — inventory", out)
        self.assertIn("Examples — Azure", out)
        self.assertIn("PlumHound-style multi-CSV pack", out)

    def test_print_structured_help_callable(self):
        out = self._capture_output(bloodbash_globals["print_structured_help"], "BloodBash.py")
        clean = self._strip_ansi(out)
        self.assertIn("Usage", clean)
        self.assertIn("Inventory", clean)
        self.assertIn("--path-break", clean)
        self.assertIn("--all-findings", clean)
        self.assertIn("--csv-pack", clean)
        self.assertIn("--list-domains", clean)
        self.assertIn("--privileged-roast", clean)

    def test_all_findings_table_empty(self):
        """--all-findings always prints a table, even with zero findings."""
        bloodbash_globals["global_findings"] = []
        out = self._capture_output(bloodbash_globals["print_prioritized_findings"], show_all=True)
        clean = self._strip_ansi(out)
        self.assertIn("All Findings", clean)
        self.assertIn("No findings recorded", clean)
        self.assertIn("Total findings: 0", clean)

    def test_all_findings_table_lists_every_row(self):
        """--all-findings prints more than the default top-20 cap."""
        bloodbash_globals["global_findings"] = []
        for i in range(25):
            bloodbash_globals["add_finding"]("Kerberoastable", f"user{i}@lab.local", score=5)
        bloodbash_globals["add_finding"]("DCSync", "attacker can DCSync", score=10)
        out_all = self._capture_output(bloodbash_globals["print_prioritized_findings"], show_all=True)
        clean_all = self._strip_ansi(out_all)
        self.assertIn("All Findings", clean_all)
        self.assertIn("Total findings: 26", clean_all)
        self.assertIn("attacker can DCSync", clean_all)
        self.assertIn("user24@lab.local", clean_all)
        # default mode still caps at 20
        bloodbash_globals["global_findings"] = []
        for i in range(25):
            bloodbash_globals["add_finding"]("Kerberoastable", f"user{i}@lab.local", score=5)
        out_default = self._capture_output(bloodbash_globals["print_prioritized_findings"])
        clean_default = self._strip_ansi(out_default)
        self.assertIn("Prioritized Findings", clean_default)
        self.assertIn("--all-findings", clean_default)
        self.assertIn("and 5 more", clean_default)

    def test_severity_scores_defaults(self):
        scores = bloodbash_globals['SEVERITY_SCORES']
        self.assertEqual(scores["DCSync"], 10)
        self.assertEqual(scores["Azure Privileged Roles"], 10)
        self.assertEqual(scores["Kerberoastable"], 5)

    def test_add_finding_default_score(self):
        bloodbash_globals['add_finding']("DCSync", "Test default score")
        self.assertEqual(bloodbash_globals['global_findings'][-1][0], 10)

    # ────────────────────────────────────────────────
    # Privilege-context tags (AdminCount / OWNED / LASTLOG)
    # ────────────────────────────────────────────────
    def test_format_lastlog_bucket_never(self):
        props = {"lastlogontimestamp": -1}
        self.assertEqual(
            bloodbash_globals["format_lastlog_bucket"](props),
            "NEVER",
        )
        props2 = {"lastlogon": 0}
        self.assertEqual(
            bloodbash_globals["format_lastlog_bucket"](props2),
            "NEVER",
        )

    def test_format_lastlog_bucket_age_bands(self):
        now = 1_700_000_000.0  # fixed epoch
        # ~400 days ago -> > 1 year
        props = {"lastlogontimestamp": int(now - 400 * 86400)}
        self.assertEqual(
            bloodbash_globals["format_lastlog_bucket"](props, now=now),
            "> 1 year",
        )
        # ~10 days ago -> < 1 year
        props2 = {"lastlogontimestamp": int(now - 10 * 86400)}
        self.assertEqual(
            bloodbash_globals["format_lastlog_bucket"](props2, now=now),
            "< 1 year",
        )
        # ~4 years
        props3 = {"lastlogontimestamp": int(now - 4 * 365 * 86400)}
        self.assertEqual(
            bloodbash_globals["format_lastlog_bucket"](props3, now=now),
            "> 3 years",
        )
        # ~6 years
        props4 = {"lastlogontimestamp": int(now - 6 * 365 * 86400)}
        self.assertEqual(
            bloodbash_globals["format_lastlog_bucket"](props4, now=now),
            "> 5 years",
        )
        # ~11 years
        props5 = {"lastlogontimestamp": int(now - 11 * 365 * 86400)}
        self.assertEqual(
            bloodbash_globals["format_lastlog_bucket"](props5, now=now),
            "> 10 years",
        )

    def test_format_privilege_context_tags_admincount_owned(self):
        d = {
            "name": "SVC@LAB.LOCAL",
            "type": "User",
            "props": {
                "admincount": True,
                "owned": True,
                "lastlogontimestamp": -1,
            },
        }
        tags = bloodbash_globals["format_privilege_context_tags"](d)
        self.assertIn("[AdminCount]", tags)
        self.assertIn("[OWNED]", tags)
        self.assertIn("[LASTLOG: NEVER]", tags)

    def test_format_privilege_context_tags_empty_when_clean(self):
        import time as _time
        d = {
            "name": "NORMAL@LAB.LOCAL",
            "type": "User",
            "props": {
                "admincount": False,
                "owned": False,
                "lastlogontimestamp": int(_time.time()),
            },
        }
        tags = bloodbash_globals["format_privilege_context_tags"](d)
        self.assertNotIn("[AdminCount]", tags)
        self.assertNotIn("[OWNED]", tags)
        # recent logon still gets a LASTLOG band
        self.assertIn("[LASTLOG:", tags)

    def test_kerberoastable_shows_privilege_context_tags(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "K",
            name="PRIVKERB@LAB.LOCAL",
            type="User",
            props={
                "hasspn": True,
                "sensitive": False,
                "enabled": True,
                "admincount": True,
                "owned": True,
                "lastlogontimestamp": -1,
            },
            is_azure=False,
        )
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_kerberoastable"], G)
        clean = self._strip_ansi(output)
        self.assertIn("PRIVKERB@LAB.LOCAL", clean)
        self.assertIn("[AdminCount]", clean)
        self.assertIn("[OWNED]", clean)
        self.assertIn("[LASTLOG: NEVER]", clean)
        # findings text also carries tags for report export
        details = " ".join(f[2] for f in bloodbash_globals["global_findings"] if f[1] == "Kerberoastable")
        self.assertIn("[AdminCount]", details)
        self.assertIn("[OWNED]", details)

    def test_as_rep_roastable_shows_privilege_context_tags(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "A",
            name="PRIVASREP@LAB.LOCAL",
            type="User",
            props={
                "dontreqpreauth": True,
                "sensitive": False,
                "enabled": True,
                "admincount": True,
                "lastlogontimestamp": -1,
            },
            is_azure=False,
        )
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(bloodbash_globals["print_as_rep_roastable"], G)
        clean = self._strip_ansi(output)
        self.assertIn("PRIVASREP@LAB.LOCAL", clean)
        self.assertIn("[AdminCount]", clean)
        self.assertIn("[LASTLOG: NEVER]", clean)
        details = " ".join(f[2] for f in bloodbash_globals["global_findings"] if f[1] == "AS-REP Roastable")
        self.assertIn("[AdminCount]", details)

    # ────────────────────────────────────────────────
    # Privileged Kerberoast / AS-REP (DA-path members)
    # ────────────────────────────────────────────────
    def _priv_roast_graph(self):
        """User with SPN + ASREP nested into Domain Admins; normal user also roastable."""
        G = nx.MultiDiGraph()
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL", "objectid": "S-1-5-21-1-2-3-512"},
            is_azure=False,
        )
        G.add_node(
            "G1",
            name="NestedAdmins@LAB.LOCAL",
            type="Group",
            props={"domain": "LAB.LOCAL"},
            is_azure=False,
        )
        G.add_node(
            "U_PRIV",
            name="SPN_ADMIN@LAB.LOCAL",
            type="User",
            props={
                "domain": "LAB.LOCAL",
                "hasspn": True,
                "dontreqpreauth": True,
                "sensitive": False,
                "enabled": True,
                "admincount": True,
                "lastlogontimestamp": -1,
            },
            is_azure=False,
        )
        G.add_node(
            "U_NORM",
            name="SPN_USER@LAB.LOCAL",
            type="User",
            props={
                "domain": "LAB.LOCAL",
                "hasspn": True,
                "dontreqpreauth": True,
                "sensitive": False,
                "enabled": True,
                "admincount": False,
            },
            is_azure=False,
        )
        # Nested membership: U_PRIV -> G1 -> DA
        G.add_edge("U_PRIV", "G1", label="MemberOf")
        G.add_edge("G1", "DA", label="MemberOf")
        return G

    def test_is_member_of_privileged_group_nested(self):
        G = self._priv_roast_graph()
        is_priv, groups = bloodbash_globals["is_member_of_privileged_group"](G, "U_PRIV")
        self.assertTrue(is_priv)
        self.assertTrue(any("domain admins" in g.lower() for g in groups))
        is_priv_n, groups_n = bloodbash_globals["is_member_of_privileged_group"](G, "U_NORM")
        self.assertFalse(is_priv_n)
        self.assertEqual(groups_n, [])

    def test_collect_privileged_roast_targets(self):
        G = self._priv_roast_graph()
        rows = bloodbash_globals["collect_privileged_roast_targets"](G)
        names = {r["name"] for r in rows}
        self.assertIn("SPN_ADMIN@LAB.LOCAL", names)
        self.assertNotIn("SPN_USER@LAB.LOCAL", names)
        priv = next(r for r in rows if r["name"] == "SPN_ADMIN@LAB.LOCAL")
        self.assertTrue(priv["kerberoastable"])
        self.assertTrue(priv["asrep"])
        self.assertTrue(any("domain admins" in g.lower() for g in priv["groups"]))

    def test_print_privileged_roast_targets(self):
        G = self._priv_roast_graph()
        bloodbash_globals["global_findings"] = []
        output = self._capture_output(
            bloodbash_globals["print_privileged_roast_targets"], G
        )
        clean = self._strip_ansi(output)
        self.assertIn("Privileged", clean)
        self.assertIn("SPN_ADMIN@LAB.LOCAL", clean)
        self.assertNotIn("SPN_USER@LAB.LOCAL", clean)
        self.assertIn("Kerberoast", clean)
        self.assertIn("AS-REP", clean)
        cats = [f[1] for f in bloodbash_globals["global_findings"]]
        self.assertTrue(
            any(c in ("Privileged Kerberoastable", "Privileged AS-REP Roastable", "Privileged Roast") for c in cats)
        )

if __name__ == '__main__':
    unittest.main()