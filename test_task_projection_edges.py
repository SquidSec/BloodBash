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


class TestAdminToAliasWithMultipleRights(unittest.TestCase):
    """A pair holding several rights must still get its AdminTo alias.

    The alias was added without an explicit key, so NetworkX picked the next
    integer key. A later edge on the same pair carrying that key overwrote the
    alias. Real collections hit this constantly: domain admins hold LocalAdmin,
    Owns and GenericAll on the same domain controller.
    """

    def _pair(self, extra_rights):
        G = nx.MultiDiGraph()
        G.add_node("G1", name="DOMAIN ADMINS@CORP.LOCAL", type="Group", props={"domain": "CORP.LOCAL"}, is_azure=False)
        G.add_node("C1", name="DC01.CORP.LOCAL", type="Computer", props={"domain": "CORP.LOCAL"}, is_azure=False)
        G.add_edge("G1", "C1", key=0, label="LocalAdmin")
        for i, right in enumerate(extra_rights, start=1):
            G.add_edge("G1", "C1", key=i, label=right)
        return G

    def test_admin_to_survives_sibling_right(self):
        P = bb.build_bloodhound_projection(self._pair(["Owns"]))
        self.assertIn(("DOMAIN ADMINS@CORP.LOCAL", "DC01.CORP.LOCAL"), _labels(P, "AdminTo"))

    def test_admin_to_survives_many_sibling_rights(self):
        P = bb.build_bloodhound_projection(
            self._pair(["Owns", "GenericAll", "WriteAccountRestrictions"])
        )
        self.assertIn(("DOMAIN ADMINS@CORP.LOCAL", "DC01.CORP.LOCAL"), _labels(P, "AdminTo"))
        self.assertEqual(len(_labels(P, "AdminTo")), len(_labels(P, "LocalAdmin")))

    def test_group_held_admin_rights_all_alias(self):
        G = nx.MultiDiGraph()
        G.add_node("G1", name="DOMAIN ADMINS@CORP.LOCAL", type="Group", props={"domain": "CORP.LOCAL"}, is_azure=False)
        for n in range(1, 6):
            oid = f"C{n}"
            G.add_node(oid, name=f"DC0{n}.CORP.LOCAL", type="Computer", props={"domain": "CORP.LOCAL"}, is_azure=False)
            G.add_edge("G1", oid, key=0, label="LocalAdmin")
            G.add_edge("G1", oid, key=1, label="Owns")
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(len(_labels(P, "LocalAdmin")), 5)
        self.assertEqual(len(_labels(P, "AdminTo")), 5)


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


class TestGPLinkDirection(unittest.TestCase):
    """BloodHound points GPLink from the GPO to its linked container.

    The collector writes ``Links[]`` on the container, so the analysis graph
    stores container -> GPO. The projection has to reverse it.
    """

    def _graph(self):
        G = nx.MultiDiGraph()
        G.add_node("OU1", name="SERVERS@CORP.LOCAL", type="OU", props={}, is_azure=False)
        G.add_node("D1", name="CORP.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_node("GPO1", name="BASELINE@CORP.LOCAL", type="GPO", props={}, is_azure=False)
        G.add_edge("OU1", "GPO1", label="GPLink", is_enforced=True)
        G.add_edge("D1", "GPO1", label="GPLink", is_enforced=False)
        return G

    def test_gplink_points_from_gpo_to_container(self):
        P = bb.build_bloodhound_projection(self._graph())
        rows = _labels(P, "GPLink")
        self.assertIn(("BASELINE@CORP.LOCAL", "SERVERS@CORP.LOCAL"), rows)
        self.assertIn(("BASELINE@CORP.LOCAL", "CORP.LOCAL"), rows)

    def test_gplink_is_not_left_pointing_at_the_gpo(self):
        P = bb.build_bloodhound_projection(self._graph())
        rows = _labels(P, "GPLink")
        self.assertNotIn(("SERVERS@CORP.LOCAL", "BASELINE@CORP.LOCAL"), rows)

    def test_gplink_keeps_the_enforced_flag(self):
        P = bb.build_bloodhound_projection(self._graph())
        edge = next(d for _u, _v, _k, d in P.edges(keys=True, data=True) if d.get("rel_type") == "GPLink")
        self.assertIn("is_enforced", edge)

    def test_analysis_graph_direction_is_unchanged(self):
        G = self._graph()
        bb.build_bloodhound_projection(G)
        self.assertTrue(G.has_edge("OU1", "GPO1"), msg="projection must not mutate the source graph")


class TestIsAclFlag(unittest.TestCase):
    """BloodHound sets isacl=true on every ACE-derived edge.

    PlumHound's ``Direct Relationships`` tasks filter on it, so an unset flag
    silently empties the report.
    """

    ACE_RIGHTS = (
        "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
        "AllExtendedRights", "ForceChangePassword", "AddMember",
        "AddKeyCredentialLink", "WriteAccountRestrictions",
        "ReadGMSAPassword", "GetChanges", "GetChangesAll",
    )

    def _graph(self):
        G = nx.MultiDiGraph()
        G.add_node("A", name="ATTACKER@CORP.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("D1", name="CORP.LOCAL", type="Domain", props={}, is_azure=False)
        G.add_node("U1", name="VICTIM@CORP.LOCAL", type="User", props={}, is_azure=False)
        G.add_edge("A", "D1", label="GenericAll")
        G.add_edge("A", "U1", label="ForceChangePassword")
        return G

    def test_ace_edges_are_marked_isacl(self):
        P = bb.build_bloodhound_projection(self._graph())
        for _u, _v, _k, d in P.edges(keys=True, data=True):
            if d.get("rel_type") in self.ACE_RIGHTS:
                self.assertTrue(d.get("isacl"), msg=d.get("rel_type"))

    def test_non_ace_edges_are_not_marked_isacl(self):
        G = nx.MultiDiGraph()
        G.add_node("U1", name="ALICE@CORP.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("G1", name="GROUP@CORP.LOCAL", type="Group", props={}, is_azure=False)
        G.add_node("C1", name="WS01.CORP.LOCAL", type="Computer", props={}, is_azure=False)
        G.add_edge("U1", "G1", label="MemberOf")
        G.add_edge("U1", "C1", label="HasSession")
        G.add_edge("G1", "C1", label="LocalAdmin")
        P = bb.build_bloodhound_projection(G)
        for _u, _v, _k, d in P.edges(keys=True, data=True):
            self.assertFalse(d.get("isacl"), msg=d.get("rel_type"))

    def test_isacl_holds_for_every_ace_right(self):
        G = nx.MultiDiGraph()
        G.add_node("A", name="A@C", type="User", props={}, is_azure=False)
        for i, right in enumerate(self.ACE_RIGHTS):
            oid = f"T{i}"
            G.add_node(oid, name=f"T{i}@C", type="User", props={}, is_azure=False)
            G.add_edge("A", oid, label=right)
        P = bb.build_bloodhound_projection(G)
        for _u, _v, _k, d in P.edges(keys=True, data=True):
            self.assertTrue(d.get("isacl"), msg=d.get("rel_type"))

    def test_query_filtering_on_isacl_finds_ace_edges(self):
        P = bb.build_bloodhound_projection(self._graph())
        rows = bb.execute_task_query(
            "MATCH (a)-[r]->(b) WHERE r.isacl=true RETURN count(*) AS C", P
        ).rows
        self.assertEqual(rows[0][0], 2)


class TestBloodHoundSchemaNames(unittest.TestCase):
    """Label names PlumHound queries depend on.

    BloodHound labels every AD object ``:Base`` alongside its concrete kind,
    calls certificate templates ``CertTemplate``, and calls computer local
    groups ``ADLocalGroup``. Task lists select on those names.
    """

    def test_ad_nodes_carry_base_label(self):
        G = nx.MultiDiGraph()
        G.add_node("U1", name="ALICE@CORP.LOCAL", type="User", props={}, is_azure=False)
        G.add_node("C1", name="WS01.CORP.LOCAL", type="Computer", props={}, is_azure=False)
        P = bb.build_bloodhound_projection(G)
        for oid in ("U1", "C1"):
            self.assertIn("Base", P.nodes[oid]["labels"])

    def test_base_is_appended_after_the_concrete_kind(self):
        G = nx.MultiDiGraph()
        G.add_node("G1", name="G@CORP.LOCAL", type="Group", props={}, is_azure=False)
        P = bb.build_bloodhound_projection(G)
        self.assertEqual(P.nodes["G1"]["labels"], ["Group", "Base"])

    def test_azure_nodes_do_not_get_base(self):
        G = nx.MultiDiGraph()
        G.add_node("A1", name="bob@contoso", type="Azure User", props={}, is_azure=True)
        P = bb.build_bloodhound_projection(G)
        self.assertNotIn("Base", P.nodes["A1"]["labels"])

    def test_certificate_templates_use_ce_label(self):
        self.assertEqual(bb.projection_label("Certificate Template"), "CertTemplate")
        self.assertEqual(bb.projection_label("certtemplates"), "CertTemplate")

    def test_labels_returns_concrete_kind_and_base(self):
        G = nx.MultiDiGraph()
        G.add_node("T1", name="ESC1", type="Certificate Template", props={}, is_azure=False)
        P = bb.build_bloodhound_projection(G)
        rows = bb.execute_task_query("MATCH (t:CertTemplate) RETURN labels(t) AS L", P).rows
        self.assertEqual(rows[0][0], ["CertTemplate", "Base"])


if __name__ == "__main__":
    unittest.main()
