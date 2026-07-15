#!/usr/bin/env python3
"""Generate N distinct synthetic AD scenarios, run BloodBash, validate accuracy.

Single command:

  python3 tools/run_scenario_battery.py
  python3 tools/run_scenario_battery.py --count 10 --seed 42
  python3 tools/run_scenario_battery.py --keep --work-dir /tmp/bb-scenarios -v

Each scenario is a different *archetype* (not just random toggles of one lab):

  1. unexpected_dcsync      — non-default GetChanges+GetChangesAll
  2. expected_vs_false_pos  — nested DA expected; System Administrators NOT high-priv
  3. broad_acl_gpo          — Auth Users write on linked GPO + Everyone→user
  4. rbcd_bulk_configure    — helpdesk/AWS can-configure on many hosts
  5. rbcd_already_set       — AllowedToAct already configured
  6. adcs_esc1              — ESC1 template enrollable by lowpriv
  7. roast_combo            — priv Kerberoast + AS-REP
  8. shadow_credentials     — AddKeyCredentialLink path
  9. sessions_localadmin    — real LocalAdmin/CanRDP (not GenericAll noise)
 10. password_hygiene       — PNE + PNR + LAPS gap

Seed varies counts/names inside each archetype so every run differs.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import sys
import tempfile
import time
import traceback
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from generate_synthetic_sharphound import (  # noqa: E402
    DOMAIN,
    build_corpus,
)

bb: Dict[str, Any] = {}
with open(ROOT / "BloodBash.py", encoding="utf-8") as f:
    exec(f.read(), bb)

# Ordered archetypes — cycled for scenario 1..N
ARCHETYPES = [
    "unexpected_dcsync",
    "expected_vs_false_pos",
    "broad_acl_gpo",
    "rbcd_bulk_configure",
    "rbcd_already_set",
    "adcs_esc1",
    "roast_combo",
    "shadow_credentials",
    "sessions_localadmin",
    "password_hygiene",
]


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _capture(fn: Callable, *args, **kwargs) -> str:
    sio = StringIO()
    from rich.console import Console

    tc = Console(file=sio, width=160, force_terminal=False, legacy_windows=False)
    with patch.object(bb["console"], "print", side_effect=tc.print):
        # quiet progress bars slightly by reusing console
        fn(*args, **kwargs)
    return _strip_ansi(sio.getvalue())


def _all_off() -> Dict[str, Any]:
    return {
        "bulk_hosts": 0,
        "msol_dcsync": False,
        "esc1": False,
        "auth_users_gpo": False,
        "everyone_user_gw": False,
        "rbcd_configured": False,
        "alice_war_pentest": False,
        "helpdesk_bulk": False,
        "aws_bulk": False,
        "privileged_kerb": False,
        "asrep": False,
        "shadow_creds": False,
        "pne": False,
        "pnr": False,
        "laps_mixed": True,  # always leave some LAPS variance in base hosts
        "localadmin_help": False,
        "nested_da_dcsync": False,
    }


def knobs_for_archetype(archetype: str, seed: int) -> Dict[str, Any]:
    """One focused archetype + seed-based size noise."""
    rng = random.Random(seed)
    k = _all_off()
    k["label"] = archetype
    k["archetype"] = archetype
    k["bulk_hosts"] = rng.randint(15, 40)

    if archetype == "unexpected_dcsync":
        k["msol_dcsync"] = True
        k["nested_da_dcsync"] = True  # expected control case still present
    elif archetype == "expected_vs_false_pos":
        k["nested_da_dcsync"] = True
        k["msol_dcsync"] = False
        # System Administrators always in base corpus
    elif archetype == "broad_acl_gpo":
        k["auth_users_gpo"] = True
        k["everyone_user_gw"] = True
    elif archetype == "rbcd_bulk_configure":
        k["helpdesk_bulk"] = True
        k["aws_bulk"] = True
        k["bulk_hosts"] = rng.randint(20, 40)
    elif archetype == "rbcd_already_set":
        k["rbcd_configured"] = True
        k["alice_war_pentest"] = True
    elif archetype == "adcs_esc1":
        k["esc1"] = True
    elif archetype == "roast_combo":
        k["privileged_kerb"] = True
        k["asrep"] = True
    elif archetype == "shadow_credentials":
        k["shadow_creds"] = True
    elif archetype == "sessions_localadmin":
        k["localadmin_help"] = True
    elif archetype == "password_hygiene":
        k["pne"] = True
        k["pnr"] = True
        k["laps_mixed"] = True
    else:
        # unknown → full lab
        for key in list(k.keys()):
            if isinstance(k[key], bool) and key not in ("laps_mixed",):
                k[key] = True
        k["bulk_hosts"] = 40
        k["label"] = "full-fallback"
    return k


def apply_knobs_to_corpus(files: dict, knobs: Dict[str, Any]) -> Tuple[dict, dict]:
    """Start from full base corpus; strip everything not needed for this archetype."""
    users = files["users.json"]["data"]
    computers = files["computers.json"]["data"]
    groups = files["groups.json"]["data"]
    gpos = files["gpos.json"]["data"]
    domains = files["domains.json"]["data"]
    templates = files["certtemplates.json"]["data"]

    def find_user(part: str):
        for u in users:
            if part.upper() in (u.get("Properties") or {}).get("name", "").upper():
                return u
        return None

    def find_computer(part: str):
        for c in computers:
            if part.upper() in (c.get("Properties") or {}).get("name", "").upper():
                return c
        return None

    def find_group(part: str):
        for g in groups:
            if part.upper() in (g.get("Properties") or {}).get("name", "").upper():
                return g
        return None

    # --- Domain DCSync ACEs ---
    dom = domains[0]
    msol = find_user("MSOL_SYNC")
    nested = find_user("CAROL.ADMIN")
    msol_sid = msol["ObjectIdentifier"] if msol else None
    nested_sid = nested["ObjectIdentifier"] if nested else None

    kept_dom = []
    for a in dom.get("Aces") or []:
        ps = a.get("PrincipalSID")
        if ps == msol_sid:
            if knobs["msol_dcsync"]:
                kept_dom.append(a)
            continue
        if ps == nested_sid:
            if knobs.get("nested_da_dcsync") or knobs["msol_dcsync"]:
                # keep nested DA as expected control when testing dcsync
                kept_dom.append(a)
            continue
        kept_dom.append(a)  # DA/EA/Admins baseline
    if not knobs["msol_dcsync"] and not knobs.get("nested_da_dcsync"):
        # strip user dcsync only
        pass
    if not knobs.get("nested_da_dcsync") and nested_sid:
        kept_dom = [a for a in kept_dom if a.get("PrincipalSID") != nested_sid]
    dom["Aces"] = kept_dom

    # --- ESC1 ---
    if not knobs["esc1"]:
        templates[:] = [
            t
            for t in templates
            if "ESC1" not in (t.get("Properties") or {}).get("name", "").upper()
        ]

    # --- Auth Users on PAM GPO ---
    for g in gpos:
        if "PAMAGENT" in (g.get("Properties") or {}).get("name", "").upper():
            if not knobs["auth_users_gpo"]:
                g["Aces"] = [
                    a
                    for a in (g.get("Aces") or [])
                    if "S-1-5-11" not in str(a.get("PrincipalSID", ""))
                ]

    # --- Everyone → MRIOS ---
    mrios = find_user("MRIOS")
    if mrios and not knobs["everyone_user_gw"]:
        mrios["Aces"] = [
            a
            for a in (mrios.get("Aces") or [])
            if "S-1-1-0" not in str(a.get("PrincipalSID", ""))
        ]

    # --- PENTESTPC RBCD ---
    pentest = find_computer("PENTESTPC")
    alice = find_user("ALICE.LOW")
    if pentest:
        if not knobs["rbcd_configured"]:
            pentest["AllowedToAct"] = []
        if not knobs["alice_war_pentest"] and alice:
            pentest["Aces"] = [
                a
                for a in (pentest.get("Aces") or [])
                if a.get("PrincipalSID") != alice["ObjectIdentifier"]
            ]

    # --- Bulk hosts ---
    bulk = [
        c
        for c in computers
        if (c.get("Properties") or {}).get("name", "").startswith("HOST")
    ]
    core = [
        c
        for c in computers
        if not (c.get("Properties") or {}).get("name", "").startswith("HOST")
    ]
    want = min(int(knobs.get("bulk_hosts") or 0), len(bulk))
    knobs = dict(knobs)
    knobs["bulk_hosts"] = want
    bulk = bulk[:want] if want else []

    aws = find_group("AWS AD CONNECTORS")
    hd = find_group("CORP HELPDESK")
    aws_sid = aws["ObjectIdentifier"] if aws else None
    hd_sid = hd["ObjectIdentifier"] if hd else None
    for c in bulk:
        aces = []
        for a in c.get("Aces") or []:
            ps = a.get("PrincipalSID")
            if ps == aws_sid and not knobs["aws_bulk"]:
                continue
            if ps == hd_sid and not knobs["helpdesk_bulk"]:
                continue
            aces.append(a)
        c["Aces"] = aces
    # If neither bulk flag, drop bulk hosts entirely for a cleaner graph
    if not knobs["aws_bulk"] and not knobs["helpdesk_bulk"]:
        bulk = []
    computers[:] = core + bulk

    # --- Privileged kerb ---
    if not knobs["privileged_kerb"]:
        da = find_group("DOMAIN ADMINS")
        svc = find_user("SVC_SQL")
        if da and svc:
            da["Members"] = [
                m
                for m in (da.get("Members") or [])
                if m.get("ObjectIdentifier") != svc["ObjectIdentifier"]
            ]
        if svc:
            svc["Properties"]["hasspn"] = False
            svc["Properties"]["serviceprincipalnames"] = []

    if not knobs["asrep"]:
        bob = find_user("BOB.ASREP")
        if bob:
            bob["Properties"]["dontreqpreauth"] = False

    if not knobs["shadow_creds"]:
        grace = find_user("GRACE.SHADOW")
        if grace:
            grace["Aces"] = [
                a
                for a in (grace.get("Aces") or [])
                if a.get("RightName") != "AddKeyCredentialLink"
            ]

    if not knobs["pne"]:
        eve = find_user("EVE.PNE")
        if eve:
            eve["Properties"]["pwdneverexpires"] = False
    if not knobs["pnr"]:
        frank = find_user("FRANK.PNR")
        if frank:
            frank["Properties"]["passwordnotreqd"] = False

    if not knobs["localadmin_help"]:
        ws01 = find_computer("WS01")
        dave = find_user("DAVE.HELP")
        if ws01 and dave:
            for lg in ws01.get("LocalGroups") or []:
                lg["Results"] = [
                    r
                    for r in (lg.get("Results") or [])
                    if r.get("ObjectIdentifier") != dave["ObjectIdentifier"]
                ]

    # meta counts
    files["users.json"]["meta"]["count"] = len(users)
    files["computers.json"]["data"] = computers
    files["computers.json"]["meta"]["count"] = len(computers)
    files["groups.json"]["data"] = groups
    files["gpos.json"]["data"] = gpos
    files["domains.json"]["data"] = domains
    files["certtemplates.json"]["data"] = templates
    files["certtemplates.json"]["meta"]["count"] = len(templates)

    checks = build_checks(knobs)
    gt = {
        "domain": DOMAIN,
        "archetype": knobs.get("archetype"),
        "knobs": knobs,
        "checks": checks,
        "stats": {
            "users": len(users),
            "computers": len(computers),
            "groups": len(groups),
            "bulk_hosts": want if (knobs["aws_bulk"] or knobs["helpdesk_bulk"]) else 0,
        },
    }
    return files, gt


def build_checks(knobs: Dict[str, Any]) -> List[dict]:
    """Archetype-focused checks: assert presence of planted issues and absence of noise."""
    arch = knobs.get("archetype") or knobs.get("label")
    checks: List[dict] = []

    # Always: System Administrators must not be treated as Builtin Administrators
    checks.append(
        {
            "id": "false_pos_system_admins",
            "type": "predicate",
            "predicate": "system_admins_not_default_priv",
        }
    )

    if arch == "unexpected_dcsync":
        checks += [
            {
                "id": "msol_unexpected",
                "type": "output_contains",
                "detector": "print_dcsync_rights",
                "must_contain": ["MSOL_SYNC", "UNEXPECTED"],
            },
            {
                "id": "msol_finding",
                "type": "finding",
                "category": "DCSync",
                "must_contain": "MSOL_SYNC",
            },
            {
                "id": "carol_expected",
                "type": "output_contains",
                "detector": "print_dcsync_rights",
                "must_contain": ["CAROL.ADMIN", "EXPECTED"],
            },
            {
                "id": "no_esc1_noise",
                "type": "output_not_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_not_contain": ["ESC1-USERAUTH"],
            },
        ]
    elif arch == "expected_vs_false_pos":
        checks += [
            {
                "id": "no_msol",
                "type": "output_not_contains",
                "detector": "print_dcsync_rights",
                "must_not_contain": ["MSOL_SYNC@"],
            },
            {
                "id": "carol_expected_if_present",
                "type": "output_contains",
                "detector": "print_dcsync_rights",
                "must_contain": ["CAROL.ADMIN", "EXPECTED"],
            },
            {
                "id": "helpdesk_not_expected_admin",
                "type": "predicate",
                "predicate": "helpdesk_not_expected_admin",
            },
        ]
    elif arch == "broad_acl_gpo":
        checks += [
            {
                "id": "gpo_auth_users",
                "type": "output_contains",
                "detector": "print_gpo_abuse",
                "must_contain": ["PAMAGENTINSTALL", "AUTHENTICATED USERS"],
                "must_not_contain": ["NO LINKS DETECTED"],
            },
            {
                "id": "broad_auth_users",
                "type": "broad_acl",
                "principal_contains": "AUTHENTICATED USERS",
                "target_contains": "PAMAGENTINSTALL",
            },
            {
                "id": "broad_everyone",
                "type": "broad_acl",
                "principal_contains": "EVERYONE",
                "target_contains": "MRIOS",
            },
            {
                "id": "default_gpo_not_weak",
                "type": "output_not_contains",
                "detector": "print_gpo_abuse",
                "must_not_contain": ["WEAK GPO: DEFAULT DOMAIN POLICY"],
            },
        ]
    elif arch == "rbcd_bulk_configure":
        checks += [
            {
                "id": "helpdesk_bulk",
                "type": "rbcd_principal_min",
                "principal_contains": "HELPDESK",
                "min_count": knobs["bulk_hosts"],
            },
            {
                "id": "aws_bulk",
                "type": "rbcd_principal_min",
                "principal_contains": "AWS AD CONNECTORS",
                "min_count": knobs["bulk_hosts"],
            },
            {
                "id": "summary_aggregates",
                "type": "rbcd_summary_principals",
                "min_principals": 2,
            },
        ]
    elif arch == "rbcd_already_set":
        checks += [
            {
                "id": "rbcd_configured",
                "type": "output_contains",
                "detector": "print_rbcd",
                "must_contain": ["PENTESTPC", "RBCD CONFIGURED"],
            },
            {
                "id": "alice_can_configure",
                "type": "rbcd_pair",
                "principal_contains": "ALICE.LOW",
                "target_contains": "PENTESTPC",
            },
            {
                "id": "dossier_impact",
                "type": "dossier_impact",
                "principal": f"ALICE.LOW@{DOMAIN}",
                "min_impact": 1,
            },
        ]
    elif arch == "adcs_esc1":
        checks += [
            {
                "id": "esc1_present",
                "type": "output_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_contain": ["ESC1", "ESC1-USERAUTH", "ALICE.LOW"],
            },
            {
                "id": "not_empty_adcs",
                "type": "output_not_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_not_contain": ["NO ADCS OBJECTS"],
            },
        ]
    elif arch == "roast_combo":
        checks += [
            {
                "id": "kerb",
                "type": "output_contains",
                "detector": "print_kerberoastable",
                "must_contain": ["SVC_SQL"],
            },
            {
                "id": "priv_kerb",
                "type": "output_contains",
                "detector": "print_privileged_roast_targets",
                "must_contain": ["SVC_SQL", "DOMAIN ADMINS"],
            },
            {
                "id": "asrep",
                "type": "output_contains",
                "detector": "print_as_rep_roastable",
                "must_contain": ["BOB.ASREP"],
            },
        ]
    elif arch == "shadow_credentials":
        checks += [
            {
                "id": "shadow_path",
                "type": "output_contains",
                "detector": "print_shadow_credentials",
                "must_contain_any": ["DAVE.HELP", "GRACE.SHADOW", "ADDKEYCREDENTIALLINK"],
            },
        ]
    elif arch == "sessions_localadmin":
        checks += [
            {
                "id": "localadmin_dave",
                "type": "output_contains",
                "detector": "print_sessions_localadmin",
                "must_contain": ["DAVE.HELP", "LOCALADMIN"],
                "must_not_contain": ["GENERICALL"],
            },
            {
                "id": "canrdp_alice",
                "type": "output_contains",
                "detector": "print_sessions_localadmin",
                "must_contain": ["ALICE.LOW", "CANRDP"],
            },
        ]
    elif arch == "password_hygiene":
        checks += [
            {
                "id": "pne",
                "type": "output_contains",
                "detector": "print_password_never_expires",
                "must_contain": ["EVE.PNE"],
            },
            {
                "id": "pnr",
                "type": "output_contains",
                "detector": "print_password_not_required",
                "must_contain": ["FRANK.PNR"],
            },
            {
                "id": "laps_gap",
                "type": "output_contains",
                "detector": "print_laps_status",
                "must_contain": ["LAPS ENABLED", "NOT ENABLED"],
            },
            {
                "id": "laps_one_finding",
                "type": "finding_count",
                "category": "LAPS",
                "exact": 1,
                "run_detector": "print_laps_status",
            },
        ]
    else:
        # full lab: sample of high-signal checks
        checks += [
            {
                "id": "msol",
                "type": "output_contains",
                "detector": "print_dcsync_rights",
                "must_contain": ["MSOL_SYNC", "UNEXPECTED"],
            },
            {
                "id": "esc1",
                "type": "output_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_contain": ["ESC1"],
            },
        ]

    return checks


def write_files(out_dir: Path, files: dict, gt: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "ground_truth.json").write_text(
        json.dumps(gt, indent=2) + "\n", encoding="utf-8"
    )


def run_checks(G, gt: dict) -> List[Tuple[str, bool, str]]:
    results: List[Tuple[str, bool, str]] = []
    cache: Dict[str, str] = {}

    def out_for(detector: str) -> str:
        if detector not in cache:
            bb["global_findings"] = []
            cache[detector] = _capture(bb[detector], G).upper()
        return cache[detector]

    for check in gt.get("checks") or []:
        cid = check["id"]
        ctype = check["type"]
        try:
            if ctype == "output_contains":
                text = out_for(check["detector"])
                missing = [
                    s for s in check.get("must_contain") or [] if s.upper() not in text
                ]
                bad = [
                    s
                    for s in check.get("must_not_contain") or []
                    if s.upper() in text
                ]
                any_need = check.get("must_contain_any") or []
                any_ok = (not any_need) or any(s.upper() in text for s in any_need)
                ok = not missing and not bad and any_ok
                detail = (
                    f"missing={missing} forbidden={bad} any_ok={any_ok}"
                    if not ok
                    else "ok"
                )
                results.append((cid, ok, detail))
            elif ctype == "output_not_contains":
                text = out_for(check["detector"])
                hits = [
                    s for s in check.get("must_not_contain") or [] if s.upper() in text
                ]
                results.append((cid, not hits, f"unexpected={hits}" if hits else "ok"))
            elif ctype == "finding":
                bb["global_findings"] = []
                det = {
                    "DCSync": "print_dcsync_rights",
                    "ESC1-ESC8": "print_adcs_vulnerabilities",
                    "LAPS": "print_laps_status",
                }.get(check["category"], "print_dcsync_rights")
                _capture(bb[det], G)
                cats = [
                    f
                    for f in bb["global_findings"]
                    if f[1] == check["category"]
                    and check.get("must_contain", "").upper() in f[2].upper()
                ]
                results.append((cid, bool(cats), f"n={len(cats)}"))
            elif ctype == "finding_count":
                bb["global_findings"] = []
                _capture(bb[check["run_detector"]], G)
                n = sum(1 for f in bb["global_findings"] if f[1] == check["category"])
                ok = n == int(check["exact"])
                results.append((cid, ok, f"count={n} want={check['exact']}"))
            elif ctype == "rbcd_principal_min":
                rows = bb["collect_can_configure_rbcd"](G)
                summary = bb["summarize_can_configure_rbcd"](rows)
                needle = check["principal_contains"].upper()
                match = [s for s in summary if needle in s["principal"].upper()]
                ok = bool(match) and match[0]["count"] >= int(check["min_count"])
                results.append(
                    (
                        cid,
                        ok,
                        f"count={match[0]['count'] if match else 0} need>={check['min_count']}",
                    )
                )
            elif ctype == "rbcd_summary_principals":
                rows = bb["collect_can_configure_rbcd"](G)
                summary = bb["summarize_can_configure_rbcd"](rows)
                ok = len(summary) >= int(check["min_principals"])
                results.append((cid, ok, f"principals={len(summary)}"))
            elif ctype == "rbcd_pair":
                rows = bb["collect_can_configure_rbcd"](G)
                ok = any(
                    check["principal_contains"].upper() in r["principal"].upper()
                    and check["target_contains"].upper() in r["target"].upper()
                    for r in rows
                )
                results.append((cid, ok, "ok" if ok else "pair missing"))
            elif ctype == "broad_acl":
                rows = bb["collect_broad_principal_acls"](G)
                ok = any(
                    check["principal_contains"].upper() in r["principal"].upper()
                    and check["target_contains"].upper() in r["target"].upper()
                    for r in rows
                )
                results.append((cid, ok, "ok" if ok else "acl missing"))
            elif ctype == "dossier_impact":
                dossier = bb["build_compromise_dossier"](G, check["principal"])
                n = (dossier or {}).get("counts", {}).get("impact_edges", 0)
                ok = dossier is not None and n >= int(check["min_impact"])
                results.append((cid, ok, f"impact_edges={n}"))
            elif ctype == "predicate":
                if check.get("predicate") == "system_admins_not_default_priv":
                    name = f"SYSTEM ADMINISTRATORS@{DOMAIN}"
                    ok = not bb["_is_default_high_priv_name"](name)
                    results.append((cid, ok, "ok" if ok else "matched as high-priv"))
                elif check.get("predicate") == "helpdesk_not_expected_admin":
                    hd = None
                    for n, d in G.nodes(data=True):
                        if "CORP HELPDESK" in (d.get("name") or "").upper():
                            hd = n
                            break
                    ok = hd is not None and not bb["is_expected_admin_principal"](G, hd)
                    results.append((cid, ok, "ok" if ok else "helpdesk marked expected"))
                else:
                    results.append((cid, False, "unknown predicate"))
            else:
                results.append((cid, False, f"unknown type {ctype}"))
        except Exception as e:
            results.append((cid, False, f"exception: {e}"))
    return results


def run_one(
    scenario_idx: int, seed: int, archetype: str, work_root: Path, verbose: bool
) -> Dict[str, Any]:
    knobs = knobs_for_archetype(archetype, seed)
    label = f"s{scenario_idx:02d}-{archetype}-seed{seed}"
    out_dir = work_root / label

    files, _ = build_corpus()
    files, gt = apply_knobs_to_corpus(files, knobs)
    gt["seed"] = seed
    gt["scenario_index"] = scenario_idx
    write_files(out_dir, files, gt)

    t0 = time.time()
    # Suppress rich progress noise from load/build where possible
    nodes = bb["load_json_dir"](str(out_dir))
    G, _ = bb["build_graph"](nodes)
    checks = run_checks(G, gt)
    elapsed = time.time() - t0

    failed = [(c, d) for c, ok, d in checks if not ok]
    return {
        "label": label,
        "archetype": archetype,
        "seed": seed,
        "knobs": {k: v for k, v in knobs.items() if k != "label"},
        "path": str(out_dir),
        "checks_total": len(checks),
        "checks_passed": sum(1 for _, ok, _ in checks if ok),
        "checks_failed": len(failed),
        "failed": failed,
        "elapsed_sec": round(elapsed, 3),
        "ok": not failed,
        "stats": gt.get("stats"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run N distinct synthetic AD scenarios through BloodBash with validation."
    )
    ap.add_argument("--count", type=int, default=10, help="Scenarios to run (default 10)")
    ap.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Base seed (default random). Scenario i uses base_seed+i",
    )
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Keep corpora here (default: temp)",
    )
    ap.add_argument("--keep", action="store_true", help="Keep temp corpora")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument(
        "--list-archetypes",
        action="store_true",
        help="Print archetype list and exit",
    )
    args = ap.parse_args()

    if args.list_archetypes:
        for i, a in enumerate(ARCHETYPES, 1):
            print(f"  {i:2d}. {a}")
        return 0

    base_seed = args.seed if args.seed is not None else random.randint(1, 1_000_000)
    work_root = args.work_dir
    cleanup = False
    if work_root is None:
        work_root = Path(tempfile.mkdtemp(prefix="bloodbash-scenarios-"))
        cleanup = not args.keep
    else:
        work_root = work_root.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    print("=" * 72)
    print("BloodBash scenario battery (distinct archetypes)")
    print(f"  count={args.count}  base_seed={base_seed}")
    print(f"  archetypes={', '.join(ARCHETYPES)}")
    print(f"  work={work_root}")
    print("=" * 72)

    results: List[Dict[str, Any]] = []
    for i in range(1, args.count + 1):
        archetype = ARCHETYPES[(i - 1) % len(ARCHETYPES)]
        seed = base_seed + i
        print(f"\n[{i}/{args.count}] archetype={archetype}  seed={seed}", flush=True)
        try:
            r = run_one(i, seed, archetype, work_root, args.verbose)
        except Exception as e:
            r = {
                "label": f"s{i:02d}-{archetype}-seed{seed}",
                "archetype": archetype,
                "seed": seed,
                "ok": False,
                "checks_total": 0,
                "checks_passed": 0,
                "checks_failed": 1,
                "failed": [("setup", str(e))],
                "elapsed_sec": 0,
                "error": traceback.format_exc(),
            }
            if args.verbose:
                print(r.get("error"))
        results.append(r)
        status = "PASS" if r["ok"] else "FAIL"
        print(
            f"  {status}  {r['archetype']}  "
            f"checks={r['checks_passed']}/{r['checks_total']}  "
            f"{r.get('elapsed_sec', 0)}s  "
            f"computers={((r.get('stats') or {}).get('computers'))}"
        )
        if not r["ok"]:
            for c, d in (r.get("failed") or [])[:8]:
                print(f"    ✗ {c}: {d}")
        elif args.verbose:
            enabled = [
                k
                for k, v in (r.get("knobs") or {}).items()
                if v is True and k not in ("laps_mixed",)
            ]
            print(f"    planted: {', '.join(enabled) or '(baseline only)'}")

    n_pass = sum(1 for r in results if r["ok"])
    n_fail = len(results) - n_pass
    print("\n" + "=" * 72)
    print(f"SUMMARY: {n_pass}/{len(results)} scenarios passed")
    # Per-archetype breakdown
    by_arch: Dict[str, List[bool]] = {}
    for r in results:
        by_arch.setdefault(r.get("archetype") or "?", []).append(bool(r["ok"]))
    print("By archetype:")
    for arch, flags in by_arch.items():
        print(f"  {arch:24s}  {sum(flags)}/{len(flags)}")
    if n_fail:
        print("Failed:")
        for r in results:
            if not r["ok"]:
                print(f"  • {r['label']}")
                for c, d in (r.get("failed") or [])[:5]:
                    print(f"      {c}: {d}")
    print(f"Work dir: {work_root}")
    if cleanup:
        shutil.rmtree(work_root, ignore_errors=True)
        print("(temp removed; use --keep or --work-dir to retain)")
    else:
        report = work_root / "battery_report.json"
        report.write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"Report: {report}")
    print("=" * 72)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
