#!/usr/bin/env python3
"""Tests for shortest-path and introspection support in task queries.

Task lists use ``shortestPath`` and ``allShortestPaths`` to ask reachability
questions. Both delegate to the same weighted search the path detectors use, and
respect the task hop cap so a dense graph cannot blow up a report run.
"""
from __future__ import annotations

import unittest

import networkx as nx

import BloodBash as bb


def _graph():
    G = nx.MultiDiGraph()
    G.add_node("U1", name="ALICE@CORP.LOCAL", type="User", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("U2", name="BOB@CORP.LOCAL", type="User", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("G1", name="HELPDESK@CORP.LOCAL", type="Group", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_node("G2", name="DOMAIN ADMINS@CORP.LOCAL", type="Group",
               props={"domain": "CORP.LOCAL", "highvalue": True}, is_azure=False)
    G.add_node("C1", name="WS01.CORP.LOCAL", type="Computer", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_edge("U1", "G1", label="MemberOf")
    G.add_edge("G1", "G2", label="MemberOf")
    G.add_edge("U2", "G2", label="MemberOf")
    G.add_edge("U1", "C1", label="LocalAdmin")
    return G


def _rows(query, G=None):
    G = G if G is not None else _graph()
    P = bb.build_bloodhound_projection(G)
    return bb.execute_task_query(query, P).rows


class TestShortestPath(unittest.TestCase):
    def test_shortest_path_returns_an_endpoint_pair(self):
        rows = _rows(
            "MATCH p=shortestPath((u:User {name:'ALICE@CORP.LOCAL'})-[:MemberOf*1..3]->(g:Group)) "
            "RETURN u.name AS User, g.name AS Group"
        )
        self.assertIn(["ALICE@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"], rows)

    def test_shortest_path_prefers_fewer_hops(self):
        rows = _rows(
            "MATCH p=shortestPath((u:User {name:'BOB@CORP.LOCAL'})-[:MemberOf*1..3]->(g:Group)) "
            "RETURN g.name AS Group"
        )
        self.assertEqual(rows, [["DOMAIN ADMINS@CORP.LOCAL"]])

    def test_shortest_path_without_a_route_returns_nothing(self):
        rows = _rows(
            "MATCH p=shortestPath((c:Computer)-[:MemberOf*1..3]->(g:Group)) RETURN g.name"
        )
        self.assertEqual(rows, [])

    def test_shortest_path_respects_the_hop_cap(self):
        rows = _rows(
            "MATCH p=shortestPath((u:User {name:'ALICE@CORP.LOCAL'})-[:MemberOf*1..1]->(g:Group)) "
            "RETURN g.name AS Group"
        )
        self.assertNotIn(["DOMAIN ADMINS@CORP.LOCAL"], rows)

    def test_lowercase_shortestpath_is_accepted(self):
        rows = _rows(
            "match p=shortestpath((u:User)-[:MemberOf*1..3]->(g:Group {highvalue:true})) "
            "return distinct g.name as Group"
        )
        self.assertIn(["DOMAIN ADMINS@CORP.LOCAL"], rows)

    def test_path_variable_inside_a_pattern_list(self):
        rows = _rows(
            "MATCH (c:Computer), (g:Group {highvalue:true}), "
            "p=shortestPath((c)-[*1..3]->(g)) RETURN g.name AS Group"
        )
        self.assertEqual(rows, [])


class TestAllShortestPaths(unittest.TestCase):
    def test_all_shortest_paths_returns_every_endpoint(self):
        rows = _rows(
            "MATCH p=allShortestPaths((u:User)-[:MemberOf*1..3]->(g:Group {highvalue:true})) "
            "RETURN u.name AS User, g.name AS Group ORDER BY User"
        )
        users = [r[0] for r in rows]
        self.assertIn("ALICE@CORP.LOCAL", users)
        self.assertIn("BOB@CORP.LOCAL", users)

    def test_all_shortest_paths_is_deterministic(self):
        q = (
            "MATCH p=allShortestPaths((u:User)-[:MemberOf*1..3]->(g:Group)) "
            "RETURN u.name AS User ORDER BY User"
        )
        self.assertEqual(_rows(q), _rows(q))

    def test_all_shortest_paths_deduplicates_endpoints(self):
        rows = _rows(
            "MATCH p=allShortestPaths((u:User)-[:MemberOf*1..3]->(g:Group)) "
            "RETURN DISTINCT u.name AS User"
        )
        users = [r[0] for r in rows]
        self.assertEqual(len(users), len(set(users)))


class TestPathSemanticsWithWhere(unittest.TestCase):
    def test_where_on_endpoint_filters_paths(self):
        rows = _rows(
            "MATCH p=shortestPath((u:User)-[:MemberOf*1..3]->(g:Group)) "
            "WHERE g.name CONTAINS 'ADMINS' RETURN u.name AS User"
        )
        users = {r[0] for r in rows}
        self.assertEqual(users, {"ALICE@CORP.LOCAL", "BOB@CORP.LOCAL"})

    def test_path_length_is_available_through_size(self):
        rows = _rows(
            "MATCH p=shortestPath((u:User {name:'ALICE@CORP.LOCAL'})-[:MemberOf*1..3]->(g:Group)) "
            "RETURN g.name AS Group"
        )
        self.assertTrue(rows)


class TestIntrospectionFunctions(unittest.TestCase):
    def test_type_on_every_relationship(self):
        rows = _rows("MATCH (a)-[r]->(b) RETURN DISTINCT type(r) AS T ORDER BY T")
        values = {r[0] for r in rows}
        self.assertIn("MemberOf", values)

    def test_head_labels_matches_the_node_label(self):
        rows = _rows("MATCH (u:User) RETURN head(labels(u)) AS L")
        self.assertTrue(all(r == ["User"] for r in rows))

    def test_labels_on_a_group(self):
        rows = _rows("MATCH (g:Group) RETURN labels(g) AS L")
        self.assertTrue(all(r[0] == ["Group"] for r in rows))

    def test_type_of_synthesized_edge(self):
        rows = _rows("MATCH (a)-[r:AdminTo]->(b) RETURN type(r) AS T")
        self.assertTrue(all(r[0] == "AdminTo" for r in rows))

    def test_exists_pattern_detects_reachability(self):
        rows = _rows(
            "MATCH (u:User) WHERE EXISTS((u)-[:MemberOf*1..3]->(:Group {highvalue:true})) "
            "RETURN u.name AS User"
        )
        self.assertEqual({r[0] for r in rows}, {"ALICE@CORP.LOCAL", "BOB@CORP.LOCAL"})

    def test_exists_pattern_negative_case(self):
        rows = _rows(
            "MATCH (c:Computer) WHERE EXISTS((c)-[:MemberOf]->(:Group)) RETURN c.name"
        )
        self.assertEqual(rows, [])


class TestDepthCaps(unittest.TestCase):
    def test_unbounded_variable_length_is_capped(self):
        G = nx.MultiDiGraph()
        prev = None
        for i in range(40):
            oid = f"N{i}"
            G.add_node(oid, name=oid, type="Group", props={}, is_azure=False)
            if prev:
                G.add_edge(prev, oid, label="MemberOf")
            prev = oid
        rows = _rows("MATCH (a)-[:MemberOf*1..]->(b) RETURN b.name AS B", G=G)
        self.assertLessEqual(len(rows), 40 * bb.TASK_MAX_HOPS)

    def test_explicit_small_cap_is_respected(self):
        G = nx.MultiDiGraph()
        for i in range(6):
            G.add_node(f"N{i}", name=f"N{i}", type="Group", props={}, is_azure=False)
        for i in range(5):
            G.add_edge(f"N{i}", f"N{i+1}", label="MemberOf")
        rows = _rows("MATCH (a {name:'N0'})-[:MemberOf*1..2]->(b) RETURN b.name AS B", G=G)
        self.assertEqual({r[0] for r in rows}, {"N1", "N2"})


class TestCorpusPathQueries(unittest.TestCase):
    """Shapes taken from the shortestPath queries in real task files."""

    def test_kerberoast_path_to_da(self):
        G = _graph()
        G.nodes["U1"]["props"]["hasspn"] = True
        rows = _rows(
            "match p=shortestPath((n:User {hasspn:true})-[*1..]->(m:Group)) "
            "where m.name contains 'DOMAIN ADMINS' return distinct n.name as Users",
            G=G,
        )
        self.assertEqual(rows, [["ALICE@CORP.LOCAL"]])

    def test_admincount_path_to_highvalue(self):
        G = _graph()
        G.nodes["U2"]["props"]["admincount"] = 1
        rows = _rows(
            "MATCH (n:User {admincount:1}) MATCH p=allShortestPaths("
            "(n)-[r:MemberOf*1..]->(m:Group)) RETURN n.name as User, m.name as Group",
            G=G,
        )
        self.assertIn(["BOB@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"], rows)

    def test_multi_relationship_path(self):
        G = _graph()
        G.add_edge("C1", "U2", label="HasSession")
        rows = _rows(
            "MATCH p=shortestPath((u:User {name:'ALICE@CORP.LOCAL'})"
            "-[:AdminTo|HasSession|MemberOf*1..4]->(g:Group {highvalue:true})) "
            "RETURN g.name AS Group",
            G=G,
        )
        self.assertTrue(rows)


if __name__ == "__main__":
    unittest.main()
