#!/usr/bin/env python3
"""Tests for automatic graph caching (fingerprint, hit/miss, invalidation)."""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from io import StringIO

import networkx as nx
from rich.console import Console

bloodbash_globals = {}
with open("BloodBash.py", "r", encoding="utf-8") as f:
    exec(f.read(), bloodbash_globals)


class TestGraphCache(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="bb-cache-test-")
        self.cache_dir = os.path.join(self.temp_dir, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.collection = os.path.join(self.temp_dir, "collection")
        os.makedirs(self.collection, exist_ok=True)
        # Minimal SharpHound-like users file
        users = {
            "meta": {"type": "users", "count": 1, "version": 5},
            "data": [
                {
                    "ObjectIdentifier": "S-1-5-21-1-2-3-1001",
                    "Properties": {
                        "name": "ALICE@LAB.LOCAL",
                        "domain": "LAB.LOCAL",
                        "enabled": True,
                    },
                    "Aces": [],
                }
            ],
        }
        with open(os.path.join(self.collection, "users.json"), "w", encoding="utf-8") as f:
            json.dump(users, f)
        self._saved_findings = bloodbash_globals["global_findings"]
        bloodbash_globals["global_findings"] = []
        # Isolate default cache from developer machine
        self._env_patch = patch.dict(
            os.environ,
            {
                "BLOODBASH_CACHE_DIR": self.cache_dir,
                "BLOODBASH_NO_CACHE": "",
            },
            clear=False,
        )
        self._env_patch.start()
        # Drop empty string NO_CACHE if set to empty
        if "BLOODBASH_NO_CACHE" in os.environ and os.environ["BLOODBASH_NO_CACHE"] == "":
            os.environ.pop("BLOODBASH_NO_CACHE", None)

    def tearDown(self):
        self._env_patch.stop()
        bloodbash_globals["global_findings"] = self._saved_findings
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @staticmethod
    def _strip_ansi(text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*m", "", text)

    def _capture(self, fn, *args, **kwargs):
        string_io = StringIO()
        test_console = Console(file=string_io, width=100, legacy_windows=False)
        with patch.object(bloodbash_globals["console"], "print", side_effect=test_console.print):
            result = fn(*args, **kwargs)
        return result, self._strip_ansi(string_io.getvalue())

    def test_fingerprint_stable_for_unchanged_files(self):
        fp1 = bloodbash_globals["compute_collection_fingerprint"]([self.collection])
        fp2 = bloodbash_globals["compute_collection_fingerprint"]([self.collection])
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 64)

    def test_fingerprint_changes_on_content_size(self):
        fp1 = bloodbash_globals["compute_collection_fingerprint"]([self.collection])
        path = Path(self.collection) / "users.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["data"].append(
            {
                "ObjectIdentifier": "S-1-5-21-1-2-3-1002",
                "Properties": {"name": "BOB@LAB.LOCAL", "domain": "LAB.LOCAL"},
                "Aces": [],
            }
        )
        # Ensure mtime changes even on coarse FS
        time.sleep(0.05)
        path.write_text(json.dumps(data), encoding="utf-8")
        fp2 = bloodbash_globals["compute_collection_fingerprint"]([self.collection])
        self.assertNotEqual(fp1, fp2)

    def test_fingerprint_includes_merge_paths(self):
        other = os.path.join(self.temp_dir, "other")
        os.makedirs(other, exist_ok=True)
        with open(os.path.join(other, "groups.json"), "w", encoding="utf-8") as f:
            json.dump(
                {
                    "meta": {"type": "groups", "count": 0, "version": 5},
                    "data": [],
                },
                f,
            )
        fp_one = bloodbash_globals["compute_collection_fingerprint"]([self.collection])
        fp_merge = bloodbash_globals["compute_collection_fingerprint"](
            [self.collection, other]
        )
        self.assertNotEqual(fp_one, fp_merge)

    def test_auto_cache_path_uses_fingerprint_prefix(self):
        fp = "abcdef0123456789" + "0" * 48
        p = bloodbash_globals["auto_graph_cache_path"](fp, self.cache_dir)
        self.assertEqual(p.name, "graph-abcdef0123456789.db")
        self.assertEqual(str(p.parent), self.cache_dir)

    def test_load_or_build_cache_miss_then_hit(self):
        G1, _, info1 = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
        )[0]
        self.assertFalse(info1["cache_hit"])
        self.assertTrue(info1["rebuilt"])
        self.assertTrue(os.path.isfile(info1["cache_path"]))
        self.assertGreater(G1.number_of_nodes(), 0)

        (G2, _, info2), out2 = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
        )
        self.assertTrue(info2["cache_hit"])
        self.assertFalse(info2["rebuilt"])
        self.assertEqual(G1.number_of_nodes(), G2.number_of_nodes())
        self.assertEqual(G1.number_of_edges(), G2.number_of_edges())
        self.assertIn("cache hit", out2.lower())

    def test_rebuild_cache_forces_reingest(self):
        self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
        )
        (_, _, info), out = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
            rebuild_cache=True,
        )
        self.assertFalse(info["cache_hit"])
        self.assertTrue(info["rebuilt"])
        self.assertTrue(os.path.isfile(info["cache_path"]))

    def test_no_cache_skips_write_and_read(self):
        (G1, _, info1), _ = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
            no_cache=True,
        )
        self.assertIsNone(info1["cache_path"])
        self.assertFalse(info1["cache_hit"])
        # Nothing written under cache dir
        remaining = list(Path(self.cache_dir).glob("graph-*.db"))
        self.assertEqual(remaining, [])

        # Populate a cache, then no_cache must not load it
        self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
        )
        (G2, _, info2), _ = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
            no_cache=True,
        )
        self.assertFalse(info2["cache_hit"])
        self.assertTrue(info2["rebuilt"])

    def test_stale_cache_on_collection_change(self):
        """Auto-cache uses a new file per fingerprint; collection edits force rebuild."""
        (_, _, info1), _ = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
        )
        old_path = info1["cache_path"]
        self.assertTrue(os.path.isfile(old_path))

        path = Path(self.collection) / "users.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["data"][0]["Properties"]["name"] = "ALICE2@LAB.LOCAL"
        time.sleep(0.05)
        path.write_text(json.dumps(data), encoding="utf-8")

        (G2, _, info2), out2 = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
        )
        self.assertFalse(info2["cache_hit"])
        self.assertTrue(info2["rebuilt"])
        self.assertNotEqual(info1["fingerprint"], info2["fingerprint"])
        # New fingerprint → different auto path (old file left in place)
        self.assertNotEqual(old_path, info2["cache_path"])
        self.assertTrue(os.path.isfile(info2["cache_path"]))

    def test_explicit_db_stale_message_on_collection_change(self):
        db = os.path.join(self.temp_dir, "fixed.db")
        self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            db_path=db,
        )
        path = Path(self.collection) / "users.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["data"][0]["Properties"]["description"] = "changed"
        time.sleep(0.05)
        path.write_text(json.dumps(data), encoding="utf-8")

        (_, _, info2), out2 = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            db_path=db,
        )
        self.assertFalse(info2["cache_hit"])
        self.assertTrue(info2["rebuilt"])
        self.assertIn("stale", out2.lower())


    def test_explicit_db_path_with_fingerprint(self):
        db = os.path.join(self.temp_dir, "explicit.db")
        (_, _, info1), _ = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            db_path=db,
            cache_dir=self.cache_dir,
        )
        self.assertEqual(info1["cache_path"], db)
        self.assertTrue(os.path.isfile(db))
        meta = bloodbash_globals["read_graph_cache_meta"](db)
        self.assertEqual(meta.get("fingerprint"), info1["fingerprint"])
        self.assertEqual(
            meta.get("schema_version"),
            str(bloodbash_globals["GRAPH_CACHE_SCHEMA_VERSION"]),
        )

        (_, _, info2), out2 = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            db_path=db,
        )
        self.assertTrue(info2["cache_hit"])
        self.assertIn("cache hit", out2.lower())

    def test_legacy_db_without_meta_invalid_when_sources_present(self):
        """Pre-meta SQLite files must not silently skip re-ingest when sources exist."""
        G = nx.MultiDiGraph()
        G.add_node("X", name="X", type="User", props={}, is_azure=False)
        db = os.path.join(self.temp_dir, "legacy.db")
        # save without meta
        bloodbash_globals["save_graph_to_db"](G, db)
        # Ensure no fingerprint in meta (save with meta=None still creates empty meta table)
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM meta")
        conn.commit()
        conn.close()

        self.assertFalse(
            bloodbash_globals["graph_cache_is_valid"](
                db,
                bloodbash_globals["compute_collection_fingerprint"]([self.collection]),
                require_fingerprint=True,
            )
        )
        (_, _, info), out = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            db_path=db,
        )
        self.assertFalse(info["cache_hit"])
        self.assertTrue(info["rebuilt"])
        # After rebuild, meta is present
        meta = bloodbash_globals["read_graph_cache_meta"](db)
        self.assertTrue(meta.get("fingerprint"))

    def test_db_only_reopen_without_sources(self):
        db = os.path.join(self.temp_dir, "solo.db")
        self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            db_path=db,
        )
        empty = os.path.join(self.temp_dir, "empty_dir")
        os.makedirs(empty, exist_ok=True)
        (G, _, info), out = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [empty],
            db_path=db,
        )
        self.assertTrue(info["cache_hit"])
        self.assertGreater(G.number_of_nodes(), 0)

    def test_schema_version_mismatch_invalidates(self):
        (_, _, info), _ = self._capture(
            bloodbash_globals["load_or_build_graph"],
            [self.collection],
            cache_dir=self.cache_dir,
        )
        db = info["cache_path"]
        bloodbash_globals["write_graph_cache_meta"](
            db, {"schema_version": "999", "fingerprint": info["fingerprint"]}
        )
        self.assertFalse(
            bloodbash_globals["graph_cache_is_valid"](db, info["fingerprint"])
        )

    def test_env_no_cache(self):
        os.environ["BLOODBASH_NO_CACHE"] = "1"
        try:
            # Prime would-be cache path
            fp = bloodbash_globals["compute_collection_fingerprint"]([self.collection])
            would = bloodbash_globals["auto_graph_cache_path"](fp, self.cache_dir)
            (_, _, info), _ = self._capture(
                bloodbash_globals["load_or_build_graph"],
                [self.collection],
                cache_dir=self.cache_dir,
            )
            self.assertFalse(info["cache_hit"])
            self.assertFalse(os.path.isfile(str(would)))
        finally:
            os.environ.pop("BLOODBASH_NO_CACHE", None)

    def test_cli_second_run_cache_hit(self):
        """End-to-end: two CLI invocations; second should report cache hit."""
        env = os.environ.copy()
        env["BLOODBASH_CACHE_DIR"] = self.cache_dir
        env.pop("BLOODBASH_NO_CACHE", None)
        cmd_base = [
            sys.executable,
            "BloodBash.py",
            self.collection,
            "--list-domains",
            "--cache-dir",
            self.cache_dir,
        ]
        r1 = subprocess.run(
            cmd_base,
            capture_output=True,
            text=True,
            env=env,
            cwd=os.path.dirname(os.path.abspath("BloodBash.py")) or ".",
        )
        self.assertEqual(r1.returncode, 0, msg=r1.stderr + r1.stdout)
        out1 = self._strip_ansi(r1.stdout + r1.stderr)
        self.assertIn("Graph cached", out1)

        r2 = subprocess.run(
            cmd_base,
            capture_output=True,
            text=True,
            env=env,
            cwd=os.path.dirname(os.path.abspath("BloodBash.py")) or ".",
        )
        self.assertEqual(r2.returncode, 0, msg=r2.stderr + r2.stdout)
        out2 = self._strip_ansi(r2.stdout + r2.stderr)
        self.assertIn("cache hit", out2.lower())
        self.assertNotIn("Building graph", out2)

    def test_cli_different_checks_reuse_cache(self):
        env = os.environ.copy()
        env["BLOODBASH_CACHE_DIR"] = self.cache_dir
        env.pop("BLOODBASH_NO_CACHE", None)
        cwd = os.getcwd()
        r1 = subprocess.run(
            [
                sys.executable,
                "BloodBash.py",
                self.collection,
                "--password-not-required",
                "--cache-dir",
                self.cache_dir,
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd,
        )
        self.assertEqual(r1.returncode, 0, msg=r1.stderr + r1.stdout)

        r2 = subprocess.run(
            [
                sys.executable,
                "BloodBash.py",
                self.collection,
                "--kerberoastable",
                "--cache-dir",
                self.cache_dir,
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd,
        )
        self.assertEqual(r2.returncode, 0, msg=r2.stderr + r2.stdout)
        out2 = self._strip_ansi(r2.stdout + r2.stderr)
        self.assertIn("cache hit", out2.lower())

    def test_meta_roundtrip_on_save(self):
        G = nx.MultiDiGraph()
        G.add_node("A", name="A", type="User", props={"x": 1}, is_azure=False)
        G.add_edge("A", "A", label="MemberOf")
        db = os.path.join(self.temp_dir, "meta.db")
        bloodbash_globals["save_graph_to_db"](
            G,
            db,
            meta={
                "fingerprint": "abc",
                "schema_version": "1",
                "sources": [self.collection],
            },
        )
        meta = bloodbash_globals["read_graph_cache_meta"](db)
        self.assertEqual(meta["fingerprint"], "abc")
        self.assertIn(self.collection, meta["sources"])
        G2, _ = bloodbash_globals["load_graph_from_db"](db)
        self.assertEqual(G2.number_of_nodes(), 1)


if __name__ == "__main__":
    unittest.main()
