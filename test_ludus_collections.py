#!/usr/bin/env python3
"""Accuracy checks against ludus-env-data SharpHound collections (lab.local).

Each s0N.zip was collected after planting a known misconfig (see
ludus-env-data/scenarios/). These tests load the zip, run the relevant
BloodBash detectors, and assert the planted signal appears in output and/or
global_findings — without requiring --from-user.
"""
from __future__ import annotations

import os
import re
import unittest
from io import StringIO
from pathlib import Path
from typing import Callable, List, Sequence, Tuple
from unittest.mock import patch

import networkx as nx
from rich.console import Console

import BloodBash as bb

ROOT = Path(__file__).resolve().parent
LUDUS_COLLECTIONS = ROOT / "ludus-env-data" / "collections"

# scenario_id -> (detector callables, regexes that must all match combined blob)
# Detectors are pure print_* functions that take G (and optional kwargs via lambda).
LUDUS_EXPECTATIONS: List[Tuple[str, str, Sequence[Callable], Sequence[str]]] = [
    (
        "s01",
        "helpdesk_fcp",
        (bb.print_interesting_acl_abuse, bb.print_sessions_localadmin),
        (r"ForceChangePassword", r"HOPADMIN", r"HELPDESK"),
    ),
    (
        "s02",
        "kerberoast",
        (bb.print_kerberoastable,),
        (r"SVC_SQL", r"Kerberoast"),
    ),
    (
        "s03",
        "asrep",
        (bb.print_as_rep_roastable,),
        (r"ASREP_USER", r"AS-?REP"),
    ),
    (
        "s04",
        "genericall_user",
        (bb.print_interesting_acl_abuse, bb.print_shadow_credentials),
        (r"GenericAll", r"HOPADMIN"),
    ),
    (
        "s05",
        "localadmin_path",
        (bb.print_interesting_acl_abuse, bb.print_sessions_localadmin),
        (r"PATH_USER", r"LocalAdmin|AdminTo"),
    ),
    (
        "s06",
        "genericall_group",
        (bb.print_interesting_acl_abuse,),
        (r"GenericAll", r"BBTEST|TGTGRP"),
    ),
    (
        "s07",
        "genericwrite_computer",
        (bb.print_interesting_acl_abuse,),
        (r"GenericWrite", r"SS-HOP01"),
    ),
    (
        "s08",
        "rbcd",
        (bb.print_rbcd,),
        (r"RBCD|AllowedToAct",),
    ),
    (
        "s09",
        "unconstrained_deleg",
        (bb.print_unconstrained_delegation,),
        (r"Unconstrained|TrustedForDelegation",),
    ),
    (
        "s10",
        "constrained_deleg",
        (bb.print_constrained_delegation,),
        (r"Constrained|DELEG_SVC|AllowedToDelegate",),
    ),
    (
        "s11",
        "gpo_genericall",
        (bb.print_gpo_abuse,),
        (r"GenericAll|DEFAULT DOMAIN|GPO",),
    ),
    (
        "s12",
        "dcsync",
        (bb.print_dcsync_rights,),
        (r"DCSync|DCSYNC",),
    ),
    (
        "s13",
        "shadow_creds",
        (bb.print_shadow_credentials, bb.print_interesting_acl_abuse),
        (r"Shadow|KeyCredential|SHADOW_TGT|GenericWrite",),
    ),
]


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _capture_detectors(G: nx.MultiDiGraph, funcs: Sequence[Callable]) -> str:
    buf = StringIO()
    console = Console(file=buf, width=120, legacy_windows=False, force_terminal=False)
    with patch.object(bb.console, "print", side_effect=console.print):
        for fn in funcs:
            fn(G)
    return _strip_ansi(buf.getvalue())


class _QuietTqdm:
    """Minimal tqdm stand-in for build_graph(total=..., ...) context manager."""

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def update(self, n=1):
        pass


def _load_ludus_graph(zip_path: Path) -> nx.MultiDiGraph:
    with patch.object(bb.console, "print", lambda *a, **k: None):
        with patch.object(bb, "tqdm", _QuietTqdm):
            nodes = bb.load_json_dir(str(zip_path))
            G, _ = bb.build_graph(nodes)
    return G


@unittest.skipUnless(
    LUDUS_COLLECTIONS.is_dir(),
    f"ludus collections missing: {LUDUS_COLLECTIONS}",
)
class TestLudusCollections(unittest.TestCase):
    """Ground-truth accuracy on planted lab.local SharpHound zips."""

    def setUp(self):
        bb.global_findings.clear()

    def tearDown(self):
        bb.global_findings.clear()

    def test_all_scenario_zips_present(self):
        missing = [
            sid
            for sid, _, _, _ in LUDUS_EXPECTATIONS
            if not (LUDUS_COLLECTIONS / f"{sid}.zip").is_file()
        ]
        self.assertEqual(missing, [], msg=f"Missing ludus zips: {missing}")

    def test_graph_has_azure_false_on_ludus_ad_only(self):
        z = LUDUS_COLLECTIONS / "s02.zip"
        if not z.is_file():
            self.skipTest("s02.zip missing")
        G = _load_ludus_graph(z)
        self.assertFalse(bb.graph_has_azure(G))

    def test_s07_genericwrite_visible_without_from_user(self):
        """Regression: computer GenericWrite must appear via interesting ACL, not only dossier."""
        z = LUDUS_COLLECTIONS / "s07.zip"
        if not z.is_file():
            self.skipTest("s07.zip missing")
        G = _load_ludus_graph(z)
        bb.global_findings.clear()
        out = _capture_detectors(G, (bb.print_interesting_acl_abuse,))
        blob = out + "\n" + "\n".join(f[2] for f in bb.global_findings)
        self.assertRegex(blob, re.compile(r"GenericWrite", re.I))
        self.assertRegex(blob, re.compile(r"SS-HOP01", re.I))
        self.assertTrue(
            any(
                "GenericWrite" in f[2] and "SS-HOP01" in f[2]
                for f in bb.global_findings
                if f[1] == "Dangerous Permissions"
            ),
            msg=str(bb.global_findings),
        )


def _make_scenario_test(sid: str, name: str, funcs: Sequence[Callable], patterns: Sequence[str]):
    def _test(self, _sid=sid, _name=name, _funcs=tuple(funcs), _patterns=tuple(patterns)):
        zpath = LUDUS_COLLECTIONS / f"{_sid}.zip"
        if not zpath.is_file():
            self.skipTest(f"{_sid}.zip missing")
        G = _load_ludus_graph(zpath)
        bb.global_findings.clear()
        out = _capture_detectors(G, _funcs)
        findings_blob = "\n".join(f"{f[1]}|{f[2]}" for f in bb.global_findings)
        blob = out + "\n" + findings_blob
        missing = [p for p in _patterns if not re.search(p, blob, re.I | re.S)]
        self.assertEqual(
            missing,
            [],
            msg=(
                f"{_sid} ({_name}) missing patterns {missing}\n"
                f"--- output (tail) ---\n{out[-2500:]}\n"
                f"--- findings ---\n{findings_blob[:2000]}"
            ),
        )

    _test.__name__ = f"test_ludus_{sid}_{name}"
    _test.__doc__ = f"Ludus {sid} {name}: planted indicators must appear"
    return _test


for _sid, _name, _funcs, _pats in LUDUS_EXPECTATIONS:
    setattr(
        TestLudusCollections,
        f"test_ludus_{_sid}_{_name}",
        _make_scenario_test(_sid, _name, _funcs, _pats),
    )


if __name__ == "__main__":
    unittest.main()
