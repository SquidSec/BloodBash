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
            try:
                fn(*args, **kwargs)
            except Exception:
                # Some rich Panel objects; still capture findings
                pass
        return buf.getvalue()

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


if __name__ == "__main__":
    unittest.main()
