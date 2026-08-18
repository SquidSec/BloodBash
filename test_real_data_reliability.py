#!/usr/bin/env python3
"""Regression tests for real-collection reliability improvements (12 items)."""
import os
import sys
import unittest

import networkx as nx

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import BloodBash as bb  # noqa: E402


class TestRealDataReliability(unittest.TestCase):
    def setUp(self):
        bb.global_findings.clear()

    def _capture(self, fn, *args, **kwargs):
        from io import StringIO
        from unittest.mock import patch

        buf = StringIO()
        with patch.object(bb.console, "print", side_effect=lambda *a, **k: buf.write(str(a[0]) + "\n") if a else None):
            fn(*args, **kwargs)
        return buf.getvalue()

    def test_capture_does_not_swallow_detector_errors(self):
        def _boom():
            raise RuntimeError("detector crashed")

        with self.assertRaises(RuntimeError):
            self._capture(_boom)

    def test_01_privileged_roast_direct_da_with_spn(self):
        """EXECSQL-style: direct DA member + SPN must be privileged roast."""
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node(
            "U",
            name="EXECSQL@LAB.LOCAL",
            type="User",
            props={
                "enabled": True,
                "hasspn": True,
                "sensitive": True,  # NOT_DELEGATED — must NOT block roast
                "serviceprincipalnames": ["MSSQLSvc/db.lab.local"],
            },
            is_azure=False,
        )
        G.add_edge("U", "DA", label="MemberOf")
        rows = bb.collect_privileged_roast_targets(G)
        self.assertTrue(any(r["name"] == "EXECSQL@LAB.LOCAL" for r in rows))
        self.assertTrue(rows[0]["kerberoastable"])

    def test_02_privileged_roast_admincount_fallback(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "U",
            name="SPN_ADMIN@LAB.LOCAL",
            type="User",
            props={"enabled": True, "hasspn": True, "admincount": True},
            is_azure=False,
        )
        rows = bb.collect_privileged_roast_targets(G)
        self.assertEqual(len(rows), 1)
        self.assertIn("AdminCount=1", rows[0]["groups"])

    def test_03_hv_includes_builtin_administrators_priority(self):
        G = nx.MultiDiGraph()
        G.add_node("BA", name="ADMINISTRATORS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("U", name="user@lab.local", type="User", props={}, is_azure=False)
        targets = bb.get_high_value_targets(G)
        names = [t[1].lower() for t in targets]
        self.assertTrue(any("administrators@" in n for n in names))
        pri = bb._priority_high_value_targets(G, limit=5)
        pri_names = [t[1].lower() for t in pri]
        self.assertTrue(any("domain admins" in n or "administrators@" in n for n in pri_names))

    def test_03b_highvalue_flag_does_not_flood_workstation_admin_groups(self):
        """SharpHound highvalue on HOST_ADMINISTRATORS-GG must not make it HV by default."""
        G = nx.MultiDiGraph()
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={"highvalue": True},
            is_azure=False,
        )
        G.add_node(
            "WS",
            name="QANHOST1_ADMINISTRATORS-GG@LAB.LOCAL",
            type="Group",
            props={"highvalue": True},
            is_azure=False,
        )
        G.add_node(
            "U",
            name="PRIVUSER@LAB.LOCAL",
            type="User",
            props={"highvalue": True, "admincount": True},
            is_azure=False,
        )
        names = {t[1] for t in bb.get_high_value_targets(G)}
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", names)
        self.assertIn("PRIVUSER@LAB.LOCAL", names)
        self.assertNotIn("QANHOST1_ADMINISTRATORS-GG@LAB.LOCAL", names)
        # Opt-in still includes collector highvalue marks
        names_all = {t[1] for t in bb.get_high_value_targets(G, include_all_highvalue=True)}
        self.assertIn("QANHOST1_ADMINISTRATORS-GG@LAB.LOCAL", names_all)

    def test_03c_domain_controller_computers_are_high_value(self):
        """isdc computers stay HV even when named DC01 (not 'domain controllers')."""
        G = nx.MultiDiGraph()
        G.add_node(
            "DC",
            name="DC01.LAB.LOCAL",
            type="Computer",
            props={"isdc": True, "highvalue": True},
            is_azure=False,
        )
        G.add_node(
            "WS",
            name="WS01.LAB.LOCAL",
            type="Computer",
            props={"highvalue": True},
            is_azure=False,
        )
        names = {t[1] for t in bb.get_high_value_targets(G)}
        self.assertIn("DC01.LAB.LOCAL", names)
        self.assertNotIn("WS01.LAB.LOCAL", names)

    def test_04_foreign_sid_labeling(self):
        G = nx.MultiDiGraph()
        dsid = "S-1-5-21-111-222-333"
        G.add_node(
            dsid,
            name="PARENT.LOCAL",
            type="Domain",
            props={"name": "PARENT.LOCAL", "domainsid": dsid},
            is_azure=False,
        )
        foreign = f"{dsid}-16119"
        G.add_node(foreign, name=foreign, type="Unknown", props={}, is_azure=False)
        label = bb.resolve_principal_display_name(G, foreign)
        self.assertIn("FOREIGN", label)
        self.assertIn("PARENT.LOCAL", label)
        self.assertIn("16119", label)

    def test_05_dcsync_partial_expected_no_finding(self):
        """Domain Controllers GetChangesAll-only should not be a scored finding."""
        G = nx.MultiDiGraph()
        G.add_node("DOM", name="LAB.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_node(
            "DCG",
            name="DOMAIN CONTROLLERS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_edge("DCG", "DOM", label="GetChangesAll")
        bb.global_findings.clear()
        bb.print_dcsync_rights(G)
        partial = [
            f
            for f in bb.global_findings
            if f[1] == "DCSync" and "GetChangesAll only" in f[2]
        ]
        self.assertEqual(partial, [])

    def test_06_dcsync_unexpected_uses_display_name(self):
        G = nx.MultiDiGraph()
        dsid = "S-1-5-21-9-9-9"
        G.add_node(
            "DOM",
            name="CHILD.LOCAL",
            type="Domain",
            props={"domainsid": "S-1-5-21-1-2-3"},
            is_azure=False,
        )
        G.add_node(
            dsid,
            name="PARENT.LOCAL",
            type="Domain",
            props={"name": "PARENT.LOCAL", "domainsid": dsid},
            is_azure=False,
        )
        foreign = f"{dsid}-99"
        G.add_node(foreign, name=foreign, type="Unknown", props={}, is_azure=False)
        G.add_edge(foreign, "DOM", label="GetChanges")
        G.add_edge(foreign, "DOM", label="GetChangesAll")
        bb.global_findings.clear()
        bb.print_dcsync_rights(G)
        dcs = [f for f in bb.global_findings if f[1] == "DCSync"]
        self.assertTrue(dcs)
        self.assertTrue(any("FOREIGN" in f[2] or "UNRESOLVED" in f[2] for f in dcs))

    def test_07_kerberoast_reports_total_count(self):
        G = nx.MultiDiGraph()
        for i in range(3):
            G.add_node(
                f"U{i}",
                name=f"svc{i}@lab.local",
                type="User",
                props={"enabled": True, "hasspn": True},
                is_azure=False,
            )
        from io import StringIO
        from unittest.mock import patch

        buf = StringIO()

        def _p(*a, **k):
            if a:
                buf.write(str(a[0]) + "\n")

        with patch.object(bb.console, "print", side_effect=_p):
            with patch.object(bb, "print_abuse_panel", lambda *a, **k: None):
                bb.print_kerberoastable(G)
        out = buf.getvalue()
        self.assertIn("Found 3", out)
        self.assertEqual(sum(1 for f in bb.global_findings if f[1] == "Kerberoastable"), 3)

    def test_08_path_break_prefers_acl_over_default_memberof(self):
        G = nx.MultiDiGraph()
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("ADMIN", name="ADMINISTRATOR@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("U", name="oliver@lab.local", type="User", props={}, is_azure=False)
        G.add_node("M", name="maria@lab.local", type="User", props={}, is_azure=False)
        G.add_edge("ADMIN", "DA", label="MemberOf")
        G.add_edge("U", "M", label="ForceChangePassword")
        G.add_edge("M", "DA", label="WriteOwner")
        # Paths from users to DA
        ranked = bb.collect_path_breaks(G, top=10, fast=False)
        self.assertTrue(ranked)
        # First actionable should not be Admin→DA MemberOf if ACL edges exist
        top = ranked[0]
        if top.get("non_actionable"):
            # If only membership paths, OK; else fail
            actionable = [r for r in ranked if not r.get("non_actionable")]
            self.assertTrue(actionable, "expected an actionable ACL edge")
        else:
            self.assertIn(top["relationship"].lower(), ("writeowner", "forcechangepassword"))

    def test_09_rbcd_tier_dc_vs_bulk(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "DC",
            name="DC01.LAB.LOCAL",
            type="Computer",
            props={"isdc": True},
            is_azure=False,
        )
        G.add_node("PC", name="WS01.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node("SVC", name="SVC_APACHE@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("JOIN", name="APP-SCCM-DOMAINJOIN@LAB.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("SVC", "DC", label="GenericWrite")
        for i in range(25):
            cid = f"C{i}"
            G.add_node(cid, name=f"PC{i}.LAB.LOCAL", type="Computer", props={}, is_azure=False)
            G.add_edge("JOIN", cid, label="WriteAccountRestrictions")
        rows = bb.collect_can_configure_rbcd(G)
        summary = bb.summarize_can_configure_rbcd(rows)
        by_p = {s["principal"]: s for s in summary}
        sc_svc, note_svc = bb._rbcd_configure_severity(G, by_p["SVC_APACHE@LAB.LOCAL"], rows)
        sc_join, note_join = bb._rbcd_configure_severity(
            G, by_p["APP-SCCM-DOMAINJOIN@LAB.LOCAL"], rows
        )
        self.assertEqual(sc_svc, 9)
        self.assertIn("domain controller", note_svc.lower())
        self.assertLessEqual(sc_join, 7)

    def test_10_sessions_hasession_table(self):
        G = nx.MultiDiGraph()
        G.add_node("C", name="WS.LAB.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_node(
            "U",
            name="ADMINISTRATOR@LAB.LOCAL",
            type="User",
            props={},
            is_azure=False,
        )
        G.add_node("DA", name="DOMAIN ADMINS@LAB.LOCAL", type="Group", props={}, is_azure=False)
        G.add_edge("U", "DA", label="MemberOf")
        G.add_edge("C", "U", label="HasSession")
        bb.global_findings.clear()
        from unittest.mock import patch

        with patch.object(bb.console, "print", lambda *a, **k: None):
            bb.print_sessions_localadmin(G)
        self.assertTrue(any(f[1] == "HasSession" for f in bb.global_findings))

    def test_11_collection_health_banner(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="u@lab.local", type="User", props={}, is_azure=False)
        G.add_node("C", name="c.lab.local", type="Computer", props={}, is_azure=False)
        from unittest.mock import patch

        with patch.object(bb.console, "print", lambda *a, **k: None):
            with patch.object(bb.console, "rule", lambda *a, **k: None):
                health = bb.print_collection_health(G)
        self.assertIn(health["ceiling"], ("high", "medium", "low"))
        self.assertEqual(health["users"], 1)

    def test_12_quick_wins_includes_trust(self):
        self.assertIn("trust", bb.QUICK_WINS_CHECKS)
        ns = bb.build_arg_parser().parse_args(["./data", "--quick-wins"])
        bb.apply_quick_wins_to_args(ns)
        self.assertTrue(ns.trust)

    def test_13_merge_flag_present(self):
        ns = bb.build_arg_parser().parse_args(
            ["./a", "--merge", "./b", "./c.zip", "--dcsync"]
        )
        self.assertEqual(ns.merge, ["./b", "./c.zip"])

    def test_14_trust_flag_runs_intent(self):
        ns = bb.build_arg_parser().parse_args(["./data", "--trust"])
        self.assertTrue(ns.trust)
        self.assertTrue(bb.cli_has_explicit_analysis_intent(ns))

    def test_15_hv_excludes_workstation_administrators_groups(self):
        """Bare 'administrators' must not match HOST_ADMINISTRATORS-GG."""
        G = nx.MultiDiGraph()
        G.add_node(
            "BA",
            name="ADMINISTRATORS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_node(
            "WS",
            name="QANHOST1_ADMINISTRATORS-GG@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        G.add_node(
            "DA",
            name="DOMAIN ADMINS@LAB.LOCAL",
            type="Group",
            props={},
            is_azure=False,
        )
        names = [t[1] for t in bb.get_high_value_targets(G)]
        self.assertIn("ADMINISTRATORS@LAB.LOCAL", names)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", names)
        self.assertNotIn("QANHOST1_ADMINISTRATORS-GG@LAB.LOCAL", names)

    def test_16_foreign_ea_rid_expected_dcsync(self):
        """Forest Enterprise Admins (RID 519) unresolved SID is expected DCSync."""
        G = nx.MultiDiGraph()
        parent = "S-1-5-21-9-9-9"
        G.add_node(
            "DOM",
            name="CHILD.LOCAL",
            type="Domain",
            props={"domainsid": "S-1-5-21-1-2-3"},
            is_azure=False,
        )
        G.add_node(
            parent,
            name="PARENT.LOCAL",
            type="Domain",
            props={"name": "PARENT.LOCAL", "domainsid": parent},
            is_azure=False,
        )
        ea = f"{parent}-519"
        G.add_node(ea, name=ea, type="Unknown", props={}, is_azure=False)
        G.add_edge(ea, "DOM", label="GenericAll")
        self.assertTrue(bb.is_expected_dcsync_principal(G, ea))
        bb.global_findings.clear()
        from unittest.mock import patch

        with patch.object(bb.console, "print", lambda *a, **k: None):
            with patch.object(bb, "print_abuse_panel", lambda *a, **k: None):
                bb.print_dcsync_rights(G)
        unexpected = [
            f for f in bb.global_findings
            if f[1] == "DCSync" and "unexpected" in f[2].lower()
        ]
        self.assertEqual(unexpected, [])

    def test_17_unconstrained_skips_disabled_users(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "U1",
            name="DISABLED@LAB.LOCAL",
            type="User",
            props={"unconstraineddelegation": True, "enabled": False},
            is_azure=False,
        )
        G.add_node(
            "U2",
            name="LIVE@LAB.LOCAL",
            type="User",
            props={"unconstraineddelegation": True, "enabled": True},
            is_azure=False,
        )
        bb.global_findings.clear()
        from unittest.mock import patch

        with patch.object(bb.console, "print", lambda *a, **k: None):
            with patch.object(bb, "print_abuse_panel", lambda *a, **k: None):
                bb.print_unconstrained_delegation(G)
        details = [f[2] for f in bb.global_findings if f[1] == "Unconstrained Delegation"]
        self.assertTrue(any("LIVE@" in d for d in details))
        self.assertFalse(any("DISABLED@" in d for d in details))

    def test_18_password_in_desc_ignores_account_ticket_text(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "U1",
            name="ticket@lab.local",
            type="User",
            props={"description": "REQTASK Extend Privileged User Access for account: 138894"},
            is_azure=False,
        )
        G.add_node(
            "U2",
            name="secret@lab.local",
            type="User",
            props={"description": "Password: P@ssw0rd123"},
            is_azure=False,
        )
        bb.global_findings.clear()
        from unittest.mock import patch

        with patch.object(bb.console, "print", lambda *a, **k: None):
            with patch.object(bb, "print_abuse_panel", lambda *a, **k: None):
                bb.print_password_in_descriptions(G)
        details = [f[2] for f in bb.global_findings if f[1] == "Password in Description"]
        self.assertTrue(any("secret@" in d for d in details))
        self.assertFalse(any("ticket@" in d for d in details))

    def test_19_collapse_findings_hygiene_volume(self):
        rows = []
        for i in range(50):
            rows.append((8, "Password Not Required", f"User u{i}@lab"))
        rows.append((10, "DCSync", "attacker can DCSync"))
        collapsed = bb.collapse_findings(rows)
        pnr = [r for r in collapsed if r[1] == "Password Not Required"]
        # Cap + one summary row
        self.assertLessEqual(len(pnr), bb.FINDING_COLLAPSE_CAPS["Password Not Required"] + 1)
        self.assertTrue(any("collapsed" in r[2].lower() for r in pnr))
        self.assertTrue(any(r[1] == "DCSync" for r in collapsed))

    def test_21_parent_child_trust_inventory_not_scored(self):
        """Normal parent/child trusts are inventory; SID filtering off is a finding."""
        G = nx.MultiDiGraph()
        G.add_node("C", name="CHILD.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_node("P", name="PARENT.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_edge(
            "C", "P",
            label="TrustedDomain:2:ParentChild",
            sid_filtering=True,
        )
        G.add_edge(
            "C", "P",
            label="TrustedDomain:3:ParentChild",
            sid_filtering=False,
        )
        bb.global_findings.clear()
        from unittest.mock import patch
        with patch.object(bb.console, "print", lambda *a, **k: None):
            bb.print_trust_abuse(G)
        abuses = [f for f in bb.global_findings if f[1] == "Trust Abuse"]
        self.assertTrue(any("SID filtering disabled" in f[2] for f in abuses))
        # Must not score every parent/child as abuse
        self.assertTrue(all("SID filtering" in f[2] or "forest" in f[2].lower() or "foreign" in f[2].lower() for f in abuses) or len(abuses) == 1)

    def test_20_legacy_sharphound_json_ingest(self):
        """Pre-CE SharpHound: users/groups keys, PrincipalName ACEs, sessions.json."""
        path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "testData",
            "legacy-sharphound-tests",
        )
        if not os.path.isdir(path):
            self.skipTest("legacy fixture missing")
        from unittest.mock import patch

        with patch.object(bb.console, "print", lambda *a, **k: None):
            nodes = bb.load_json_dir(path)
            G, _ = bb.build_graph(nodes)
        self.assertGreaterEqual(
            len([k for k in nodes if not str(k).startswith("__")]), 4
        )
        self.assertGreaterEqual(G.number_of_nodes(), 5)
        labels = {d.get("label") for *_, d in G.edges(data=True)}
        self.assertIn("HasSession", labels)
        self.assertIn("LocalAdmin", labels)
        self.assertTrue({"GetChanges", "GetChangesAll"} & labels)


if __name__ == "__main__":
    unittest.main()
