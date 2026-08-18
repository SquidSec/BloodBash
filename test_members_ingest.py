#!/usr/bin/env python3
"""Regression tests: SharpHound Members -> MemberOf edges."""
import json
import os
import tempfile
import unittest
from pathlib import Path

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


class TestAzureDirMerge(unittest.TestCase):
    def test_load_json_dirs_keeps_azure_pending_edges(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            users = root / "users"
            rels = root / "rels"
            users.mkdir()
            rels.mkdir()
            (users / "azusers.json").write_text(
                json.dumps(
                    {
                        "meta": {"type": "azusers", "count": 1, "version": 4},
                        "data": [
                            {
                                "objectId": "user-1",
                                "displayName": "alice@contoso.com",
                                "userPrincipalName": "alice@contoso.com",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (rels / "azgroupmembers.json").write_text(
                json.dumps(
                    {
                        "meta": {"type": "azgroupmembers", "count": 1, "version": 4},
                        "data": [
                            {
                                "kind": "AZGroupMember",
                                "groupId": "group-1",
                                "members": [{"objectId": "user-1"}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            merged = bloodbash_globals["load_json_dirs"]([str(users), str(rels)])
            self.assertIn("__azure_pending_edges__", merged)
            pending = merged["__azure_pending_edges__"]["_pending_edges"]
            self.assertIn(("user-1", "group-1", "MemberOf"), pending)
            G, _ = bloodbash_globals["build_graph"](merged)
            memberof = [
                (u, v)
                for u, v, d in G.edges(data=True)
                if d.get("label") == "MemberOf"
            ]
            self.assertIn(("user-1", "group-1"), memberof)


if __name__ == "__main__":
    unittest.main()
