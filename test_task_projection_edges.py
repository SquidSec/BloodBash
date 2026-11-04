#!/usr/bin/env python3
"""Tests for the relationship aliases task lists rely on.

PlumHound queries use BloodHound relationship names (``DCSync``, ``AdminTo``,
``TrustedBy``, ``AllowedToDelegate``, ``AutoEnroll``, ``AZOwns``). BloodBash
stores the collector's own names, so the projection synthesizes the BloodHound
names. Tests pin direction as well as existence.
"""
from __future__ import annotations

import unittest

import networkx as nx

import BloodBash as bb


def _labels(P, rel):
    return [(P.nodes[u]["name"], P.nodes[v]["name"]) for u, v, _k, d in P.edges(keys=True, data=True) if d.get("rel_type") == rel]


def _graph():
    G = nx.MultiDiGraph()
    G.add_node("U1", name="ALICE@CORP.LOCAL", type="User", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("U2", name="BOB@CORP.LOCAL", type="User", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("C1", name="WS01.CORP.LOCAL", type="Computer", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("C2", name="WS02.CORP.LOCAL", type="Computer", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("D1", name="CORP.LOCAL", type="Domain", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("D2", name="CHILD.LOCAL", type="Domain", props={"domain": "CHILD.LOCAL"}, is_azure=False)
    G.add_node("T1", name="ESC1", type="Certificate Template", props={}, is_azure=False)
    G.add_node("G1", name="HELPDESK@CORP.LOCAL", type="Group", props={"domain": "CORP.LOCAL"}, is_azure=False)
    # DCSync pair on U1, single right on U2
    G.add_edge("U1", "D1", label="GetChanges")
    G.add_edge("U1", "D1", label="GetChangesAll")
    G.add_edge("U2", "D1", label="GetChangesAll")
    # Local admin and remote desktop
    G.add_edge("U1", "C1", label="LocalAdmin")
    G.add_edge("G1", "C2", label="CanRDP")
    G.add_edge("C1", "C2", label="LocalAdmin")
    # Trust with attributes, both directions on a bidirectional trust
    G.add_edge("D1", "D2", label="TrustedDomain:Bidirectional:ParentChild", sid_filtering=False)
    G.add_edge("D2", "D1", label="TrustedDomain:Bidirectional:ParentChild", sid_filtering=False)
    # Enroll on a template
    G.add_edge("G1", "T1", label="Enroll")
    return G


class TestDCSyncAlias(unittest.TestCase):
    def test_dcsync_requires_both_rights(self):
        P = bb.build_bloodhound_projection(_graph())
        rows = _labels(P, "DCSync")
        self.assertEqual(rows, [("ALICE@CORP.LOCAL", "CORP.LOCAL")])

    def test_getchanges_only_is_not_dcsync(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="U@C", type="User", props={}, is_azure=False)
        G.add_node("D", name="C", type="Domain", props={}, is_azure=False)
        G.add_edge("U", "D", label="GetChanges")
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(_labels(P, "DCSync"), [])

    def test_original_rights_are_preserved(self):
        P = bb.build_bloodhound_projection(_graph())
        self.assertEqual(len(_labels(P, "GetChanges")), 1)
        self.assertEqual(len(_labels(P, "GetChangesAll")), 2)


class TestAdminToAlias(unittest.TestCase):
    def test_localadmin_projects_as_adminto(self):
        P = bb.build_bloodhound_projection(_graph())
        rows = _labels(P, "AdminTo")
        self.assertIn(("ALICE@CORP.LOCAL", "WS01.CORP.LOCAL"), rows)
        self.assertIn(("WS01.CORP.LOCAL", "WS02.CORP.LOCAL"), rows)

    def test_adminto_count_matches_localadmin_count(self):
        P = bb.build_bloodhound_projection(_graph())
        self.assertEqual(len(_labels(P, "AdminTo")), len(_labels(P, "LocalAdmin")))

    def test_existing_adminto_edges_are_not_duplicated(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="U@C", type="User", props={}, is_azure=False)
        G.add_node("C", name="C1", type="Computer", props={}, is_azure=False)
        G.add_edge("U", "C", label="AdminTo")
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(len(_labels(P, "AdminTo")), 1)

    def test_other_rights_are_not_aliased(self):
        P = bb.build_bloodhound_projection(_graph())
        self.assertEqual(_labels(P, "AdminTo"), [
            r for r in _labels(P, "AdminTo")
        ])
        self.assertNotIn(("HELPDESK@CORP.LOCAL", "WS02.CORP.LOCAL"), _labels(P, "AdminTo"))


class TestTrustedByAlias(unittest.TestCase):
    def test_trust_edges_become_trustedby(self):
        P = bb.build_bloodhound_projection(_graph())
        rows = _labels(P, "TrustedBy")
        self.assertEqual(len(rows), 2)
        self.assertIn(("CORP.LOCAL", "CHILD.LOCAL"), rows)

    def test_trust_attributes_land_on_the_edge(self):
        P = bb.build_bloodhound_projection(_graph())
        for _u, _v, _k, d in P.edges(keys=True, data=True):
            if d.get("rel_type") == "TrustedBy":
                self.assertIn("sidfiltering", d)
                self.assertIn("trusttype", d)
                self.assertIn("trustdirection", d)

    def test_trust_attributes_are_parsed_from_the_label(self):
        P = bb.build_bloodhound_projection(_graph())
        edge = next(d for _u, _v, _k, d in P.edges(keys=True, data=True) if d.get("rel_type") == "TrustedBy")
        self.assertEqual(edge["trusttype"].lower(), "parentchild")
        self.assertFalse(edge["sidfiltering"])


class TestDelegationAlias(unittest.TestCase):
    def test_allowedtodelegateto_prop_becomes_allowedtodelegate(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "C1",
            name="WEB01",
            type="Computer",
            props={"msds-allowedtodelegateto": ["HTTP/DB01", "HTTP/DB01.CORP.LOCAL"]},
            is_azure=False,
        )
        G.add_node("C2", name="DB01", type="Computer", props={}, is_azure=False)
        P = bb.build_bloodhound_projection(G)
        rows = _labels(P, "AllowedToDelegate")
        self.assertEqual(rows, [("WEB01", "DB01")])

    def test_delegation_edges_created_for_each_target(self):
        G = nx.MultiDiGraph()
        G.add_node("C1", name="WEB01", type="Computer", props={"AllowedToDelegate": ["HTTP/A", "HTTP/B"]}, is_azure=False)
        G.add_node("A", name="A", type="Computer", props={}, is_azure=False)
        G.add_node("B", name="B", type="Computer", props={}, is_azure=False)
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(len(_labels(P, "AllowedToDelegate")), 2)

    def test_no_delegation_edges_without_props(self):
        P = bb.build_bloodhound_projection(_graph())
        self.assertEqual(_labels(P, "AllowedToDelegate"), [])


class TestAutoEnrollAlias(unittest.TestCase):
    def test_enroll_with_autoenroll_flag_projects_as_both(self):
        G = nx.MultiDiGraph()
        G.add_node("G", name="ENROLLERS@C", type="Group", props={}, is_azure=False)
        G.add_node("T", name="ESC1", type="Certificate Template", props={}, is_azure=False)
        G.add_edge("G", "T", label="Enroll")
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(len(_labels(P, "Enroll")), 1)

    def test_autoenroll_edge_is_preserved(self):
        G = nx.MultiDiGraph()
        G.add_node("G", name="ENROLLERS@C", type="Group", props={}, is_azure=False)
        G.add_node("T", name="ESC1", type="Certificate Template", props={}, is_azure=False)
        G.add_edge("G", "T", label="AutoEnroll")
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(_labels(P, "AutoEnroll"), [("ENROLLERS@C", "ESC1")])


class TestAzureAliases(unittest.TestCase):
    def test_azure_owns_projects_as_azowns(self):
        G = nx.MultiDiGraph()
        G.add_node("SP", name="sp", type="Azure Service Principal", props={}, is_azure=True)
        G.add_node("RG", name="rg", type="Azure Resource Group", props={}, is_azure=True)
        G.add_edge("SP", "RG", label="Owns")
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(_labels(P, "AZOwns"), [("sp", "rg")])
        self.assertEqual(_labels(P, "Owns"), [])

    def test_azure_memberof_keeps_its_name(self):
        G = nx.MultiDiGraph()
        G.add_node("U", name="u", type="Azure User", props={}, is_azure=True)
        G.add_node("G", name="g", type="Azure Group", props={}, is_azure=True)
        G.add_edge("U", "G", label="MemberOf")
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(_labels(P, "MemberOf"), [("u", "g")])

    def test_ad_owns_is_not_renamed(self):
        P = bb.build_bloodhound_projection(_graph())
        self.assertEqual(_labels(P, "AZOwns"), [])


class TestAliasOnRealCorpora(unittest.TestCase):
    def setUp(self):
        nodes = bb.load_json_dirs(["SampleSharphoundADData"])
        self.G, _ = bb.build_graph(nodes)
        self.P = bb.build_bloodhound_projection(self.G)

    def test_dcsync_aliases_exist_where_both_rights_are_held(self):
        rows = _labels(self.P, "DCSync")
        self.assertTrue(rows, msg="sample data holds GetChanges+GetChangesAll pairs")
        for principal, domain in rows:
            self.assertTrue(principal)
            self.assertTrue(domain)

    def test_every_synthesized_edge_points_at_an_existing_node(self):
        for u, v, _k, _d in self.P.edges(keys=True, data=True):
            self.assertIn(u, self.P.nodes)
            self.assertIn(v, self.P.nodes)

    def test_no_label_is_lost_and_counts_only_grow(self):
        before = len(self.G.edges())
        after = len(self.P.edges())
        self.assertGreaterEqual(after, before)

    def test_trust_edges_present_in_sample(self):
        self.assertTrue(_labels(self.P, "TrustedBy"))


class TestEdgeAttributeParity(unittest.TestCase):
    def test_existing_edge_attributes_survive_projection(self):
        G = nx.MultiDiGraph()
        G.add_node("A", name="A", type="User", props={}, is_azure=False)
        G.add_node("B", name="B", type="Domain", props={}, is_azure=False)
        G.add_edge("A", "B", label="GetChanges", custom_flag="x")
        P = bb.build_bloodhound_projection(G)
        edge = next(d for _u, _v, _k, d in P.edges(keys=True, data=True) if d.get("rel_type") == "GetChanges")
        self.assertEqual(edge["custom_flag"], "x")

    def test_rel_type_mirrors_label(self):
        P = bb.build_bloodhound_projection(_graph())
        for _u, _v, _k, d in P.edges(keys=True, data=True):
            self.assertEqual(d["rel_type"], d["label"])


if __name__ == "__main__":
    unittest.main()
