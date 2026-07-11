#!/usr/bin/env python3
"""Regression tests: SharpHound Members -> MemberOf edges."""
import os
import unittest
import networkx as nx

bloodbash_globals = {}
with open("BloodBash.py", "r") as f:
    exec(f.read(), bloodbash_globals)


class TestMembersIngest(unittest.TestCase):
    def test_sharphound_members_become_memberof_edges(self):
        test_dir = os.path.join("testData", "members-tests")
        if not os.path.isdir(test_dir):
            self.skipTest(f"missing {test_dir}")
        nodes = bloodbash_globals["load_json_dir"](test_dir)
        G, _ = bloodbash_globals["build_graph"](nodes)
        memberof = [
            (u, v)
            for u, v, d in G.edges(data=True)
            if d.get("label") == "MemberOf"
        ]
        self.assertEqual(len(memberof), 4, msg=f"Expected 4 MemberOf edges, got {memberof}")
        self.assertIn(("S-1-5-21-1-2-3-1100", "S-1-5-21-1-2-3-512"), memberof)
        self.assertIn(("S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-512"), memberof)
        self.assertIn(("S-1-5-21-1-2-3-1102", "S-1-5-21-1-2-3-512"), memberof)
        self.assertIn(("S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-1102"), memberof)
        self.assertTrue(nx.has_path(G, "S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-512"))
        path = nx.shortest_path(G, "S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-512")
        self.assertEqual(
            path,
            ["S-1-5-21-1-2-3-1103", "S-1-5-21-1-2-3-1102", "S-1-5-21-1-2-3-512"],
        )
        orphan_edges = [
            (u, v)
            for u, v in memberof
            if u == "S-1-5-21-1-2-3-1199" or v == "S-1-5-21-1-2-3-1199"
        ]
        self.assertEqual(orphan_edges, [])

    def test_sample_sharphound_memberof_edges_from_members(self):
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


if __name__ == "__main__":
    unittest.main()
