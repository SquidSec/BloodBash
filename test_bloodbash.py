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
    def test_gpo_abuse(self):
        try:
            G = self._load_and_build_graph("gpo-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_gpo_abuse'], G)
        self.assertIn("Weak GPO", output)
        self.assertIn("High-risk", output)
        self.assertIn("Vulnerable-GPO", output)
    def test_dcsync_rights(self):
        try:
            G = self._load_and_build_graph("dcsync-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_dcsync_rights'], G)
        self.assertIn("DCSync possible", output)
        self.assertIn("LOWPRIV@LAB.LOCAL", output)
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
        self.assertIn("DC1$", output)
        self.assertIn("USER2@LAB.LOCAL", output)
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
            self.assertIn("<html>", content)
            self.assertIn("BloodBash Report", content)
    def test_export_csv(self):
        try:
            G = self._load_and_build_graph("local-admin-sessions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="csv")
        csv_file = f"{export_path}_sessions.csv"
        self.assertTrue(os.path.exists(csv_file))
        with open(csv_file, 'r') as f:
            lines = f.readlines()
            self.assertGreater(len(lines), 1)
            self.assertIn("Principal", lines[0])
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
        G.add_node("C", name="DC1$", type="computer")
        G.add_node("G", name="Group", type="GROUP")
        G.add_edge("U", "C", label="ADMinto")
        targets = bloodbash_globals['get_high_value_targets'](G)
        self.assertTrue(any("computer" in t[2].lower() for t in targets))
        path = ["U", "C"]
        formatted = bloodbash_globals['format_path'](G, path)
        self.assertIn("ADMinto", formatted)
    def test_performance_fast_mode_and_limits(self):
        G = nx.MultiDiGraph()
        G.add_node("T", name="DC1$", type="Computer")
        for i in range(100):
            G.add_node(f"N{i}", name=f"Node{i}", type="User" if i % 2 == 0 else "Computer")
            if i > 0:
                G.add_edge(f"N{i-1}", f"N{i}", label="MemberOf")
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, fast=True, max_paths=5)
        self.assertIn("Fast mode enabled", output)
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
            self.assertNotIn("<script>", content)
            self.assertIn("&lt;script&gt;", content)
    def test_new_features_unconstrained_delegation(self):
        G = nx.MultiDiGraph()
        G.add_node("C1", name="Comp1", type="Computer", props={"TrustedForDelegation": True})
        G.add_node("C2", name="Comp2", type="Computer", props={"TrustedForDelegation": False})
        output = self._capture_output(bloodbash_globals['print_unconstrained_delegation'], G)
        self.assertIn("Unconstrained delegation enabled", output)
        self.assertIn("Comp1", output)
        self.assertNotIn("Comp2", output)
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
        G.add_node("T", name="Target", type="User")
        bloodbash_globals['add_finding']("Test", "Sample finding")
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="md")
        self.assertTrue(os.path.exists(f"{export_path}.md"))
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="json")
        self.assertTrue(os.path.exists(f"{export_path}.json"))
        with open(f"{export_path}.json", 'r') as f:
            data = json.load(f)
            self.assertIn("nodes", data)
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
        self.assertIn("No obvious ESC1–ESC8 misconfigurations detected", output)
    def test_no_results_shortest_paths(self):
        G = nx.MultiDiGraph()
        G.add_node("User", name="User", type="User")
        G.add_node("Target", name="DC1$", type="Computer")
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
        G.add_node("T", name="DC1$", type="Computer")
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
            self.assertNotIn("<script>", content)
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
        G.add_node("Target", name="DC1$", type="Computer")
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, fast=True, max_paths=5)
        self.assertIn("Fast mode enabled", output)
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
        self.assertIn("Shadow Credentials detected", output)
        self.assertTrue(any("Shadow Credentials" in f[2] for f in bloodbash_globals['global_findings']))
    def test_no_results_shadow_credentials(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User", props={})
        output = self._capture_output(bloodbash_globals['print_shadow_credentials'], G)
        self.assertIn("No accounts with Shadow Credentials found", output)
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
        self.assertTrue(any("LAPS" in f[2] for f in bloodbash_globals['global_findings']))
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
        self.assertIn("Trust abuse possible", output)
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
        self._assert_output_contains(output, "Azure app with secrets", "Owns")
        self.assertTrue(any("Azure App Secrets" in f[1] for f in bloodbash_globals['global_findings']))
    def test_azure_mfa_bypass(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_azure_mfa_bypass'], G)
        self._assert_output_contains(output, "Azure user without MFA")
        self.assertTrue(any("Azure MFA Bypass" in f[1] for f in bloodbash_globals['global_findings']))
    def test_azure_guest_access(self):
        G = self._load_and_build_graph(AZURE_TEST_DIR)
        output = self._capture_output(bloodbash_globals['print_azure_guest_access'], G)
        self._assert_output_contains(output, "Azure guest user", "Has role")
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
        self._assert_output_contains(output, "Trust abuse possible", "Cross-Tenant")
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
        self.assertIn("ESC1/ESC2", output)
        self.assertGreater(len(bloodbash_globals['global_findings']), 0)  # Ensure findings were added
    # ────────────────────────────────────────────────
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
        export_path = os.path.join(self.temp_dir, "yaml_export")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="yaml")
        yaml_file = f"{export_path}.yaml"
        self.assertTrue(os.path.exists(yaml_file))
        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = bloodbash_globals['yaml'].safe_load(f)
        self.assertEqual(data['nodes'], G.number_of_nodes())
        self.assertIn('high_value', data)
        self.assertIn('findings', data)

    def test_get_bool_prop_ci(self):
        props = {"PasswordNeverExpires": True, "enabled": False}
        self.assertTrue(bloodbash_globals['get_bool_prop_ci'](props, ['passwordneverexpires']))
        self.assertFalse(bloodbash_globals['get_bool_prop_ci'](props, ['passwordnotrequired']))
        self.assertFalse(bloodbash_globals['get_bool_prop_ci'](None, ['enabled']))

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
        self.assertIn("--azure-privileged-roles", result.stdout)
        self.assertIn("--export", result.stdout)

    def test_severity_scores_defaults(self):
        scores = bloodbash_globals['SEVERITY_SCORES']
        self.assertEqual(scores["DCSync"], 10)
        self.assertEqual(scores["Azure Privileged Roles"], 10)
        self.assertEqual(scores["Kerberoastable"], 5)

    def test_add_finding_default_score(self):
        bloodbash_globals['add_finding']("DCSync", "Test default score")
        self.assertEqual(bloodbash_globals['global_findings'][-1][0], 10)

if __name__ == '__main__':
    unittest.main()