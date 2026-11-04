#!/usr/bin/env python3
"""Tests for the native Cypher subset evaluator used by task lists.

The evaluator runs read-only queries over the projection graph. It supports the
constructs that appear in real task lists; anything else raises
``TaskQueryError`` with the offending text so the task is reported and skipped.
"""
from __future__ import annotations

import unittest

import networkx as nx

import BloodBash as bb


def _graph():
    G = nx.MultiDiGraph()
    G.add_node("U1", name="ALICE@CORP.LOCAL", type="User",
               props={"domain": "CORP.LOCAL", "enabled": True, "hasspn": True,
                      "pwdneverexpires": False, "admincount": 1, "description": "helpdesk"},
               is_azure=False)
    G.add_node("U2", name="BOB@CORP.LOCAL", type="User",
               props={"domain": "CORP.LOCAL", "enabled": True, "hasspn": False,
                      "pwdneverexpires": True, "admincount": 0, "description": None},
               is_azure=False)
    G.add_node("C1", name="DC01.CORP.LOCAL", type="Computer",
               props={"domain": "CORP.LOCAL", "operatingsystem": "Windows Server 2022",
                      "haslaps": False}, is_azure=False)
    G.add_node("C2", name="WS01.CORP.LOCAL", type="Computer",
               props={"domain": "CORP.LOCAL", "operatingsystem": "Windows 11",
                      "haslaps": True}, is_azure=False)
    G.add_node("G1", name="DOMAIN ADMINS@CORP.LOCAL", type="Group",
               props={"domain": "CORP.LOCAL", "highvalue": True}, is_azure=False)
    G.add_node("G2", name="HELPDESK@CORP.LOCAL", type="Group",
               props={"domain": "CORP.LOCAL", "highvalue": False}, is_azure=False)
    G.add_node("D1", name="CORP.LOCAL", type="Domain",
               props={"domain": "CORP.LOCAL", "functionallevel": "2016"}, is_azure=False)
    G.add_node("OU1", name="STAFF", type="OU", props={"domain": "CORP.LOCAL"}, is_azure=False)
    G.add_edge("U1", "G2", label="MemberOf")
    G.add_edge("G2", "G1", label="MemberOf")
    G.add_edge("U2", "G1", label="MemberOf")
    G.add_edge("C1", "G1", label="MemberOf")
    G.add_edge("U1", "C2", label="LocalAdmin")
    G.add_edge("OU1", "U1", label="Contains")
    return G


def _run(query, G=None, **kwargs):
    G = G if G is not None else _graph()
    P = bb.build_bloodhound_projection(G, **kwargs)
    return bb.execute_task_query(query, P)


def _rows(query, **kwargs):
    return _run(query, **kwargs).rows


class TestLexerAndParser(unittest.TestCase):
    def test_parse_simple_match(self):
        q = bb.parse_cypher("MATCH (n:User) RETURN n.name")
        self.assertEqual(q[-1].kind, "return")
        self.assertEqual(q[0].kind, "match")

    def test_parse_strips_comments_and_whitespace(self):
        q = bb.parse_cypher("  MATCH (n:User)   RETURN n.name  ")
        self.assertEqual(len(q), 2)

    def test_parse_single_quoted_and_double_quoted_literals(self):
        q = bb.parse_cypher("MATCH (n) WHERE n.name = 'A' RETURN n.name")
        self.assertTrue(any(c.kind == "match" for c in q))

    def test_unparseable_query_raises(self):
        with self.assertRaises(bb.TaskQueryError):
            bb.parse_cypher("MATCH (n:User")

    def test_unknown_clause_raises(self):
        with self.assertRaises(bb.TaskQueryError):
            bb.parse_cypher("DELETE (n)")

    def test_write_clause_is_rejected(self):
        for clause in ("CREATE (n:X)", "MERGE (n:X)", "SET n.x = 1"):
            with self.assertRaises(bb.TaskQueryError):
                bb.parse_cypher(clause)


class TestSinglePattern(unittest.TestCase):
    def test_select_all_users(self):
        rows = _rows("MATCH (n:User) RETURN n.name")
        self.assertEqual({r[0] for r in rows}, {"ALICE@CORP.LOCAL", "BOB@CORP.LOCAL"})

    def test_select_by_label_group(self):
        rows = _rows("MATCH (g:Group) RETURN g.name")
        self.assertEqual(len(rows), 2)

    def test_no_label_scans_every_node(self):
        self.assertEqual(len(_rows("MATCH (n) RETURN n.name")), 8)

    def test_property_filter_in_pattern_map(self):
        rows = _rows("MATCH (u:User {hasspn:true}) RETURN u.name")
        self.assertEqual(rows, [["ALICE@CORP.LOCAL"]])

    def test_multiple_properties_in_pattern_map(self):
        rows = _rows("MATCH (u:User {hasspn:true, admincount:1}) RETURN u.name")
        self.assertEqual(rows, [["ALICE@CORP.LOCAL"]])

    def test_column_names_come_from_aliases(self):
        res = _run("MATCH (n:User) RETURN n.name AS Name, n.enabled AS Enabled")
        self.assertEqual(res.columns, ["Name", "Enabled"])

    def test_column_names_default_to_expression_text(self):
        res = _run("MATCH (n:User) RETURN n.name")
        self.assertEqual(len(res.columns), 1)

    def test_missing_property_yields_none(self):
        rows = _rows("MATCH (n:User) RETURN n.notreal")
        self.assertTrue(all(r[0] is None for r in rows))


class TestRelationships(unittest.TestCase):
    def test_single_hop(self):
        rows = _rows("MATCH (u:User)-[:MemberOf]->(g:Group) RETURN u.name, g.name")
        self.assertIn(["ALICE@CORP.LOCAL", "HELPDESK@CORP.LOCAL"], rows)

    def test_relationship_alternation(self):
        rows = _rows("MATCH (u)-[:MemberOf|LocalAdmin]->(x) RETURN u.name, x.name")
        self.assertGreaterEqual(len(rows), 4)

    def test_relationship_variable_is_usable(self):
        rows = _rows("MATCH (u:User)-[r:MemberOf]->(g) RETURN u.name")
        self.assertTrue(rows)

    def test_inbound_direction(self):
        rows = _rows("MATCH (g:Group)<-[:MemberOf]-(u:User) RETURN g.name, u.name")
        names = {r[0] for r in rows}
        self.assertIn("DOMAIN ADMINS@CORP.LOCAL", names)

    def test_undirected_direction(self):
        rows = _rows("MATCH (a)-[:MemberOf]-(b) RETURN a.name, b.name")
        self.assertTrue(any(r[0] == "DOMAIN ADMINS@CORP.LOCAL" for r in rows))

    def test_variable_length_reaches_transitive_members(self):
        rows = _rows("MATCH (u:User)-[:MemberOf*1..]->(g:Group) RETURN u.name, g.name")
        self.assertIn(["ALICE@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"], rows)

    def test_variable_length_bounded(self):
        rows = _rows("MATCH (u:User)-[:MemberOf*1..1]->(g:Group) RETURN u.name, g.name")
        self.assertNotIn(["ALICE@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"], rows)

    def test_variable_length_zero_hop_matches_self(self):
        rows = _rows("MATCH (u:User)-[:MemberOf*0..1]->(g:Group) RETURN u.name")
        self.assertTrue(rows)

    def test_two_patterns_join(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group), (g)-[:MemberOf]->(p:Group) "
            "RETURN u.name, p.name"
        )
        self.assertIn(["ALICE@CORP.LOCAL", "DOMAIN ADMINS@CORP.LOCAL"], rows)

    def test_path_variable_is_accepted(self):
        rows = _rows("MATCH p=(u:User)-[:MemberOf]->(g) RETURN u.name")
        self.assertTrue(rows)


class TestWhere(unittest.TestCase):
    def test_equality(self):
        rows = _rows("MATCH (u:User) WHERE u.name = 'BOB@CORP.LOCAL' RETURN u.name")
        self.assertEqual(rows, [["BOB@CORP.LOCAL"]])

    def test_contaIns_case_sensitive(self):
        rows = _rows("MATCH (u:User) WHERE u.name CONTAINS 'ALICE' RETURN u.name")
        self.assertEqual(len(rows), 1)

    def test_ends_with(self):
        rows = _rows("MATCH (g:Group) WHERE g.name ENDS WITH 'ADMINS@CORP.LOCAL' RETURN g.name")
        self.assertEqual(len(rows), 1)

    def test_starts_with(self):
        rows = _rows("MATCH (c:Computer) WHERE c.name STARTS WITH 'DC' RETURN c.name")
        self.assertEqual(rows, [["DC01.CORP.LOCAL"]])

    def test_regex_full_match_with_inline_flag(self):
        rows = _rows(
            "MATCH (g:Group) WHERE g.name =~ '(?i)DOMAIN ADMINS.*' RETURN g.name"
        )
        self.assertEqual(len(rows), 1)

    def test_regex_does_not_match_substring_without_wildcards(self):
        rows = _rows("MATCH (g:Group) WHERE g.name =~ 'DOMAIN' RETURN g.name")
        self.assertEqual(rows, [])

    def test_boolean_property_truthiness(self):
        rows = _rows("MATCH (u:User) WHERE u.admincount RETURN u.name")
        self.assertEqual(rows, [["ALICE@CORP.LOCAL"]])

    def test_and_or_not(self):
        self.assertEqual(
            _rows("MATCH (u:User) WHERE u.enabled AND NOT u.hasspn RETURN u.name"),
            [["BOB@CORP.LOCAL"]],
        )
        self.assertEqual(
            len(_rows("MATCH (u:User) WHERE u.hasspn OR u.admincount RETURN u.name")), 1
        )

    def test_in_list(self):
        rows = _rows("MATCH (c:Computer) WHERE c.name IN ['DC01.CORP.LOCAL'] RETURN c.name")
        self.assertEqual(len(rows), 1)

    def test_is_null_and_is_not_null(self):
        self.assertEqual(
            len(_rows("MATCH (u:User) WHERE u.description IS NULL RETURN u.name")), 1
        )
        self.assertEqual(
            len(_rows("MATCH (u:User) WHERE u.description IS NOT NULL RETURN u.name")), 1
        )

    def test_numeric_comparison(self):
        rows = _rows("MATCH (u:User) WHERE u.admincount >= 1 RETURN u.name")
        self.assertEqual(len(rows), 1)

    def test_where_after_with(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group) WITH u, count(g) AS n "
            "WHERE n >= 1 RETURN u.name, n"
        )
        self.assertTrue(rows)


class TestAggregation(unittest.TestCase):
    def test_count_star(self):
        rows = _rows("MATCH (n:User) RETURN count(*) AS Total")
        self.assertEqual(rows, [[2]])

    def test_count_of_property(self):
        rows = _rows("MATCH (u:User) RETURN count(u.name) AS Total")
        self.assertEqual(rows, [[2]])

    def test_count_distinct(self):
        rows = _rows("MATCH (u:User)-[:MemberOf]->(g:Group) RETURN count(DISTINCT g.name) AS N")
        self.assertEqual(rows, [[2]])

    def test_group_by_implicit_on_non_aggregate(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group) RETURN g.name AS Group, count(u) AS Members"
        )
        by_group = {r[0]: r[1] for r in rows}
        self.assertEqual(by_group["DOMAIN ADMINS@CORP.LOCAL"], 1)
        self.assertEqual(by_group["HELPDESK@CORP.LOCAL"], 1)

    def test_collect_produces_a_list(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group) RETURN g.name AS Group, collect(u.name) AS Users"
        )
        values = {r[0]: r[1] for r in rows}
        self.assertEqual(values["HELPDESK@CORP.LOCAL"], ["ALICE@CORP.LOCAL"])

    def test_collect_distinct(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group) "
            "RETURN g.name AS Group, collect(DISTINCT u.enabled) AS Enabled"
        )
        self.assertTrue(all(isinstance(r[1], list) for r in rows))

    def test_with_aggregate_then_unwind(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group) "
            "WITH g, collect(u.name) AS users UNWIND users AS u RETURN g.name, u"
        )
        self.assertGreaterEqual(len(rows), 2)

    def test_head_of_collect(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group) "
            "RETURN g.name AS Group, head(collect(u.name)) AS First"
        )
        self.assertTrue(all(r[1] for r in rows))


class TestFunctions(unittest.TestCase):
    def test_labels(self):
        rows = _rows("MATCH (u:User) RETURN labels(u) AS L")
        self.assertEqual(rows[0], [["User"]])

    def test_head_labels(self):
        rows = _rows("MATCH (n:Group) RETURN head(labels(n)) AS Type")
        self.assertEqual(rows[0], ["Group"])

    def test_type_of_relationship(self):
        rows = _rows("MATCH (u:User)-[r:MemberOf]->(g) RETURN type(r) AS T")
        self.assertEqual(rows[0], ["MemberOf"])

    def test_toupper_and_tolower(self):
        rows = _rows("MATCH (u:User) WHERE toUpper(u.name) CONTAINS 'ALICE' RETURN u.name")
        self.assertEqual(len(rows), 1)
        rows = _rows("MATCH (g:Group) WHERE toLower(g.name) CONTAINS 'domain' RETURN g.name")
        self.assertEqual(len(rows), 1)

    def test_tointeger(self):
        rows = _rows("MATCH (u:User) RETURN toInteger(u.admincount) AS N")
        self.assertTrue(all(isinstance(r[0], int) for r in rows))

    def test_tostring(self):
        rows = _rows("MATCH (u:User) RETURN toString(u.admincount) AS N")
        self.assertTrue(all(isinstance(r[0], str) for r in rows))

    def test_coalesce(self):
        rows = _rows("MATCH (u:User) RETURN coalesce(u.description, 'none') AS D")
        values = {r[0] for r in rows}
        self.assertIn("none", values)

    def test_datetime_epoch_seconds(self):
        rows = _rows("MATCH (u:User) RETURN toString(datetime({epochSeconds: 0})) AS D")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(isinstance(r[0], str) for r in rows))
        self.assertEqual(rows[0][0], "1970-01-01T00:00:00Z")

    def test_unknown_function_raises(self):
        with self.assertRaises(bb.TaskQueryError):
            _rows("MATCH (u:User) RETURN bogusFunction(u) AS X")


class TestOrderingAndLimits(unittest.TestCase):
    def test_order_by_ascending(self):
        rows = _rows("MATCH (u:User) RETURN u.name AS n ORDER BY n")
        self.assertEqual([r[0] for r in rows], sorted(r[0] for r in rows))

    def test_order_by_descending(self):
        rows = _rows("MATCH (u:User) RETURN u.name AS n ORDER BY n DESC")
        self.assertEqual([r[0] for r in rows], sorted((r[0] for r in rows), reverse=True))

    def test_order_by_two_keys(self):
        rows = _rows(
            "MATCH (u:User)-[:MemberOf]->(g:Group) RETURN g.name AS G, u.name AS U "
            "ORDER BY G, U"
        )
        self.assertTrue(rows)

    def test_limit(self):
        rows = _rows("MATCH (n) RETURN n.name ORDER BY n.name LIMIT 2")
        self.assertEqual(len(rows), 2)

    def test_limit_with_order_is_deterministic(self):
        a = _rows("MATCH (n:User) RETURN n.name ORDER BY n.name LIMIT 1")
        b = _rows("MATCH (n:User) RETURN n.name ORDER BY n.name LIMIT 1")
        self.assertEqual(a, b)

    def test_return_distinct(self):
        rows = _rows("MATCH (u:User)-[:MemberOf]->(g:Group) RETURN DISTINCT g.name")
        self.assertEqual(len(rows), len({r[0] for r in rows}))


class TestOptionalMatchAndUnion(unittest.TestCase):
    def test_optional_match_keeps_rows_without_a_match(self):
        rows = _rows(
            "MATCH (u:User) OPTIONAL MATCH (u)-[:LocalAdmin]->(c:Computer) "
            "RETURN u.name, c.name"
        )
        self.assertEqual(len(rows), 2)
        self.assertTrue(any(r[1] is None for r in rows))

    def test_union_deduplicates(self):
        rows = _rows(
            "MATCH (u:User) RETURN u.name AS n UNION MATCH (g:Group) RETURN g.name AS n"
        )
        self.assertEqual(len(rows), 4)

    def test_union_all_keeps_duplicates(self):
        rows = _rows(
            "MATCH (u:User) RETURN u.name AS n UNION ALL MATCH (u:User) RETURN u.name AS n"
        )
        self.assertEqual(len(rows), 4)


class TestResultContract(unittest.TestCase):
    def test_columns_and_rows(self):
        res = _run("MATCH (u:User) RETURN u.name AS Name")
        self.assertEqual(res.columns, ["Name"])
        self.assertEqual(res.row_count, 2)
        self.assertEqual(res.status, "ok")

    def test_node_projection_renders_display_name(self):
        rows = _rows("MATCH (u:User) RETURN u")
        self.assertEqual({r[0] for r in rows}, {"ALICE@CORP.LOCAL", "BOB@CORP.LOCAL"})

    def test_execute_accepts_a_task_spec_query(self):
        res = bb.execute_task_query("MATCH (d:Domain) RETURN d.name AS Domain", bb.build_bloodhound_projection(_graph()))
        self.assertEqual(res.rows, [["CORP.LOCAL"]])

    def test_empty_result_still_has_columns(self):
        res = bb.execute_task_query(
            "MATCH (n:User) WHERE n.name = 'NOBODY' RETURN n.name AS Name",
            bb.build_bloodhound_projection(_graph()),
        )
        self.assertEqual(res.columns, ["Name"])
        self.assertEqual(res.row_count, 0)


class TestCorpusShapes(unittest.TestCase):
    """Queries shaped like the ones in real PlumHound lists."""

    def test_domain_inventory(self):
        rows = _rows(
            "MATCH (n:Domain) return n.name as Domain, n.functionallevel as FunctionalLevel, "
            "n.highvalue as HighValue, n.domain as DNS"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "CORP.LOCAL")

    def test_domain_controllers_by_rid(self):
        rows = _rows(
            "MATCH (c:Computer)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH '-516' "
            "RETURN c.name as Hostname"
        )
        self.assertEqual(rows, [])

    def test_admin_groups_contains(self):
        rows = _rows(
            "Match (n:Group) WHERE n.name CONTAINS 'ADMIN' return n.name as Name, "
            "n.highvalue as HighValue, n.description as Description"
        )
        self.assertEqual(len(rows), 1)

    def test_direct_group_members(self):
        rows = _rows(
            "MATCH (n:Group)<-[:MemberOf]-(m) WHERE n.objectid =~ '(?i)S-1-5-.*-512' "
            "RETURN m.name as Name"
        )
        self.assertEqual(rows, [])

    def test_kerberoastable(self):
        rows = _rows(
            "MATCH (n:User) WHERE n.hasspn = true RETURN n.name as Username, "
            "n.admincount as AdminCount"
        )
        self.assertEqual(rows, [["ALICE@CORP.LOCAL", 1]])

    def test_sessions_join(self):
        G = _graph()
        G.add_edge("C1", "U1", label="HasSession")
        rows = _rows(
            "MATCH (c:Computer)-[:HasSession]->(u:User) RETURN u.name as Username, "
            "c.name as Computer",
            G=G,
        )
        self.assertEqual(rows, [["ALICE@CORP.LOCAL", "DC01.CORP.LOCAL"]])

    def test_count_with_order_by(self):
        rows = _rows(
            "MATCH (u)-[:MemberOf]->(g:Group) RETURN g.name as Group, "
            "Count(DISTINCT(u.name)) as Members ORDER BY Members DESC"
        )
        self.assertTrue(rows)
        self.assertGreaterEqual(rows[0][1], rows[-1][1])


class TestErrorReporting(unittest.TestCase):
    def test_unsupported_clause_names_the_clause(self):
        with self.assertRaises(bb.TaskQueryError) as ctx:
            _rows("MATCH (n) CALL db.labels() RETURN n")
        self.assertIn("CALL", str(ctx.exception).upper())

    def test_error_includes_query_text(self):
        try:
            _rows("MATCH (n) RETURN unknownFn(n)")
        except bb.TaskQueryError as exc:
            self.assertIn("unknownFn", str(exc))
        else:
            self.fail("expected TaskQueryError")

    def test_projection_can_be_none_for_empty_query(self):
        with self.assertRaises(bb.TaskQueryError):
            bb.execute_task_query("", None)


if __name__ == "__main__":
    unittest.main()
