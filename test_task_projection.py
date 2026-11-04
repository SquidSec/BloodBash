#!/usr/bin/env python3
"""Tests for the BloodHound-shaped projection used by task lists.

The projection is a read-only view: it must never mutate the analysis graph.
"""
from __future__ import annotations

import unittest

import networkx as nx

import BloodBash as bb


def _graph():
    G = nx.MultiDiGraph()
    G.add_node(
        "U1",
        name="ALICE@CORP.LOCAL",
        type="User",
        props={
            "name": "ALICE@CORP.LOCAL",
            "domain": "CORP.LOCAL",
            "enabled": True,
            "serviceprincipalnames": ["MSSQLSvc/db01"],
        },
        is_azure=False,
    )
    G.add_node(
        "S-1-5-21-1-512",
        name="DOMAIN ADMINS@CORP.LOCAL",
        type="Group",
        props={"name": "DOMAIN ADMINS@CORP.LOCAL", "domain": "CORP.LOCAL", "highvalue": True},
        is_azure=False,
    )
    G.add_node(
        "C1",
        name="DC01.CORP.LOCAL",
        type="Computer",
        props={"name": "DC01.CORP.LOCAL", "domain": "CORP.LOCAL", "isdc": True},
        is_azure=False,
    )
    G.add_node(
        "D1",
        name="CORP.LOCAL",
        type="Domain",
        props={"name": "CORP.LOCAL", "domain": "CORP.LOCAL"},
        is_azure=False,
    )
    G.add_node(
        "T1",
        name="ESC1-TEMPLATE",
        type="Certificate Template",
        props={"name": "ESC1-TEMPLATE"},
        is_azure=False,
    )
    G.add_node(
        "AZU1",
        name="bob@contoso.onmicrosoft.com",
        type="Azure User",
        props={"displayName": "bob", "accountEnabled": True},
        is_azure=True,
    )
    G.add_edge("U1", "S-1-5-21-1-512", label="MemberOf")
    G.add_edge("C1", "S-1-5-21-1-512", label="MemberOf")
    return G


class TestProjectionLabels(unittest.TestCase):
    def test_ad_types_map_to_bloodhound_labels(self):
        expected = {
            "User": "User",
            "Computer": "Computer",
            "Group": "Group",
            "Domain": "Domain",
            "GPO": "GPO",
            "OU": "OU",
            "Container": "Container",
            "Certificate Template": "CertificateTemplate",
            "Enterprise CA": "EnterpriseCA",
            "Root CA": "RootCA",
            "AIA CA": "AIACA",
            "NTAuth Store": "NTAuthStore",
        }
        for raw, label in expected.items():
            self.assertEqual(bb.projection_label(raw), label, msg=raw)

    def test_project_uses_bloodhound_names_for_every_alias_source(self):
        # Raw SharpHound meta.type values, which are what the collector writes.
        expected = {
            "certtemplates": "CertificateTemplate",
            "enterprisecas": "EnterpriseCA",
            "ntauthstores": "NTAuthStore",
        }
        for raw, label in expected.items():
            self.assertEqual(bb.projection_label(raw), label, msg=raw)

    def test_collector_meta_aliases_resolve_through_type_map(self):
        for raw, label in (
            ("certTemplates", "CertificateTemplate"),
            ("enterpriseCAs", "EnterpriseCA"),
        ):
            normalized = bb._normalize_object_type(raw)
            self.assertEqual(bb.projection_label(normalized), label, msg=raw)

    def test_azure_types_map_to_az_labels(self):
        expected = {
            "Azure User": "AZUser",
            "Azure Group": "AZGroup",
            "Azure Application": "AZApp",
            "Azure Service Principal": "AZServicePrincipal",
            "Azure Role": "AZRole",
            "Azure Device": "AZDevice",
            "Azure Tenant": "AZTenant",
        }
        for raw, label in expected.items():
            self.assertEqual(bb.projection_label(raw), label, msg=raw)

    def test_unknown_type_projects_to_unknown(self):
        self.assertEqual(bb.projection_label("Blorp"), "Unknown")
        self.assertEqual(bb.projection_label(None), "Unknown")


class TestProjectedProperties(unittest.TestCase):
    def setUp(self):
        self.G = _graph()
        self.P = bb.build_bloodhound_projection(self.G, owned="ALICE@CORP.LOCAL")

    def test_every_node_has_an_objectid(self):
        for oid, d in self.P.nodes(data=True):
            self.assertEqual(d["props"]["objectid"], oid)

    def test_property_names_are_lowercased(self):
        props = self.P.nodes["AZU1"]["props"]
        self.assertIn("displayname", props)
        self.assertNotIn("displayName", props)

    def test_highvalue_derived_for_privileged_group_and_dc(self):
        self.assertTrue(self.P.nodes["S-1-5-21-1-512"]["props"]["highvalue"])
        self.assertTrue(self.P.nodes["C1"]["props"]["highvalue"])
        self.assertFalse(self.P.nodes["U1"]["props"]["highvalue"])

    def test_owned_flag_follows_cli_principal(self):
        self.assertTrue(self.P.nodes["U1"]["props"]["owned"])
        self.assertFalse(self.P.nodes["C1"]["props"]["owned"])

    def test_hasspn_derived_from_spn_list(self):
        self.assertTrue(self.P.nodes["U1"]["props"]["hasspn"])
        self.assertNotIn("hasspn", self.P.nodes["D1"]["props"])

    def test_owned_accepts_sequences_and_is_empty_by_default(self):
        P = bb.build_bloodhound_projection(self.G)
        self.assertFalse(P.nodes["U1"]["props"]["owned"])
        P2 = bb.build_bloodhound_projection(self.G, owned=["ALICE@CORP.LOCAL"])
        self.assertTrue(P2.nodes["U1"]["props"]["owned"])

    def test_projection_does_not_mutate_the_source_graph(self):
        for oid, d in self.G.nodes(data=True):
            self.assertNotIn("objectid", d.get("props") or {})
            self.assertNotIn("labels", d)
        self.assertNotIn("objectid", self.G.nodes["U1"]["props"])

    def test_labels_list_is_present_on_every_node(self):
        for _, d in self.P.nodes(data=True):
            self.assertTrue(d["labels"])
            self.assertIn(d["labels"][0], bb.PROJECTION_LABELS.values())

    def test_node_type_kept_for_existing_detectors(self):
        self.assertEqual(self.P.nodes["U1"]["type"], "User")
        self.assertTrue(self.P.nodes["AZU1"]["is_azure"])


class TestProjectionOnRealCorpora(unittest.TestCase):
    def test_sample_sharphound_schema_is_covered(self):
        nodes = bb.load_json_dirs(["SampleSharphoundADData"])
        G, _ = bb.build_graph(nodes)
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(P.number_of_nodes(), G.number_of_nodes())
        unknown = [d["name"] for _, d in P.nodes(data=True) if d["labels"][0] == "Unknown"]
        self.assertLessEqual(len(unknown), 0, msg=f"unmapped types: {unknown[:5]}")
        # Aliases add edges; nothing is dropped.
        self.assertGreaterEqual(P.number_of_edges(), G.number_of_edges())
        for _, _, e in P.edges(data=True):
            self.assertIn("label", e)

    def test_synthetic_corpus_highvalue_props(self):
        nodes = bb.load_json_dirs(["testData/synthetic-corp-lab"])
        G, _ = bb.build_graph(nodes)
        P = bb.build_bloodhound_projection(G)
        hv = [d["name"] for _, d in P.nodes(data=True) if d["props"].get("highvalue")]
        self.assertTrue(hv, msg="expected derived high-value nodes in the synthetic corpus")
        self.assertIn("DOMAIN ADMINS@CORPLAB.LOCAL", {n.upper() for n in hv})


class TestProjectionCache(unittest.TestCase):
    def test_projection_is_cached_per_graph(self):
        G = _graph()
        first = bb.build_bloodhound_projection(G, owned="ALICE@CORP.LOCAL")
        second = bb.build_bloodhound_projection(G, owned="ALICE@CORP.LOCAL")
        self.assertIs(first, second)

    def test_cache_key_includes_owned_principals(self):
        G = _graph()
        first = bb.build_bloodhound_projection(G, owned="ALICE@CORP.LOCAL")
        second = bb.build_bloodhound_projection(G, owned="DC01.CORP.LOCAL")
        self.assertIsNot(first, second)
        self.assertFalse(second.nodes["U1"]["props"]["owned"])
        self.assertTrue(second.nodes["C1"]["props"]["owned"])


if __name__ == "__main__":
    unittest.main()
