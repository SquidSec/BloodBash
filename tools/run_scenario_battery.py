#!/usr/bin/env python3
"""Generate N synthetic SharpHound scenarios, run BloodBash, validate accuracy.

Single entrypoint for regression against known-good synthetic AD corpora:

  python3 tools/run_scenario_battery.py
  python3 tools/run_scenario_battery.py --count 10 --seed 42
  python3 tools/run_scenario_battery.py --count 5 --keep

Each run:
  1. Builds a unique corpus (seed-varied) via generate_synthetic_sharphound
  2. Loads it into BloodBash (in-process)
  3. Runs detectors and checks ground-truth checks
  4. Prints PASS/FAIL per scenario and overall summary

Exit code 0 only if every scenario passes.
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

# Repo root on path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from generate_synthetic_sharphound import (  # noqa: E402
    DOMAIN,
    build_corpus,
    write_corpus,
)

# Load BloodBash once
bb: Dict[str, Any] = {}
with open(ROOT / "BloodBash.py", encoding="utf-8") as f:
    exec(f.read(), bb)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _capture(fn: Callable, *args, **kwargs) -> str:
    sio = StringIO()
    from rich.console import Console

    tc = Console(file=sio, width=160, force_terminal=False, legacy_windows=False)
    with patch.object(bb["console"], "print", side_effect=tc.print):
        fn(*args, **kwargs)
    return _strip_ansi(sio.getvalue())


def scenario_knobs(seed: int) -> Dict[str, Any]:
    """Derive feature toggles from seed (seed=0 → full lab, all features on)."""
    if seed == 0:
        return {
            "label": "canonical-full",
            "bulk_hosts": 40,
            "msol_dcsync": True,
            "esc1": True,
            "auth_users_gpo": True,
            "everyone_user_gw": True,
            "rbcd_configured": True,
            "alice_war_pentest": True,
            "helpdesk_bulk": True,
            "aws_bulk": True,
            "privileged_kerb": True,
            "asrep": True,
            "shadow_creds": True,
            "pne": True,
            "pnr": True,
            "laps_mixed": True,
            "localadmin_help": True,
        }
    rng = random.Random(seed)
    return {
        "label": f"variant-{seed}",
        "bulk_hosts": rng.randint(12, 55),
        "msol_dcsync": rng.random() < 0.85,
        "esc1": rng.random() < 0.8,
        "auth_users_gpo": rng.random() < 0.85,
        "everyone_user_gw": rng.random() < 0.8,
        "rbcd_configured": rng.random() < 0.75,
        "alice_war_pentest": rng.random() < 0.85,
        "helpdesk_bulk": rng.random() < 0.9,
        "aws_bulk": rng.random() < 0.9,
        "privileged_kerb": rng.random() < 0.8,
        "asrep": rng.random() < 0.8,
        "shadow_creds": rng.random() < 0.75,
        "pne": rng.random() < 0.7,
        "pnr": rng.random() < 0.7,
        "laps_mixed": True,
        "localadmin_help": rng.random() < 0.85,
    }


def apply_knobs_to_corpus(files: dict, gt: dict, knobs: Dict[str, Any]) -> Tuple[dict, dict]:
    """Mutate generated full corpus according to knobs; rebuild ground_truth checks."""
    # Start from full corpus (seed-independent base), then strip/disable features.
    users = files["users.json"]["data"]
    computers = files["computers.json"]["data"]
    groups = files["groups.json"]["data"]
    gpos = files["gpos.json"]["data"]
    domains = files["domains.json"]["data"]
    templates = files["certtemplates.json"]["data"]

    def find_user(sam_prefix: str):
        for u in users:
            n = (u.get("Properties") or {}).get("name", "")
            if sam_prefix.upper() in n.upper():
                return u
        return None

    def find_computer(name_part: str):
        for c in computers:
            n = (c.get("Properties") or {}).get("name", "")
            if name_part.upper() in n.upper():
                return c
        return None

    def find_group(name_part: str):
        for g in groups:
            n = (g.get("Properties") or {}).get("name", "")
            if name_part.upper() in n.upper():
                return g
        return None

    # --- DCSync MSOL ---
    if not knobs["msol_dcsync"]:
        dom = domains[0]
        dom["Aces"] = [
            a
            for a in dom.get("Aces") or []
            if "MSOL" not in str(a.get("PrincipalSID", ""))
            and not (
                a.get("PrincipalType") == "User"
                and any(
                    u["ObjectIdentifier"] == a.get("PrincipalSID")
                    and "MSOL" in (u.get("Properties") or {}).get("name", "").upper()
                    for u in users
                )
            )
        ]
        # also drop by matching msol user sid
        msol = find_user("MSOL_SYNC")
        if msol:
            sid = msol["ObjectIdentifier"]
            dom["Aces"] = [a for a in dom["Aces"] if a.get("PrincipalSID") != sid]

    # --- ESC1 ---
    if not knobs["esc1"]:
        templates[:] = [
            t
            for t in templates
            if "ESC1" not in (t.get("Properties") or {}).get("name", "").upper()
        ]

    # --- Auth Users GPO ---
    pam = None
    for g in gpos:
        if "PAMAGENT" in (g.get("Properties") or {}).get("name", "").upper():
            pam = g
            break
    if pam and not knobs["auth_users_gpo"]:
        pam["Aces"] = [
            a
            for a in pam.get("Aces") or []
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

    # --- RBCD configured / Alice WAR ---
    pentest = find_computer("PENTESTPC")
    if pentest:
        if not knobs["rbcd_configured"]:
            pentest["AllowedToAct"] = []
        if not knobs["alice_war_pentest"]:
            alice = find_user("ALICE.LOW")
            if alice:
                aid = alice["ObjectIdentifier"]
                pentest["Aces"] = [
                    a for a in (pentest.get("Aces") or []) if a.get("PrincipalSID") != aid
                ]

    # --- Bulk hosts count + who gets rights ---
    bulk = [c for c in computers if (c.get("Properties") or {}).get("name", "").startswith("HOST")]
    core = [c for c in computers if not (c.get("Properties") or {}).get("name", "").startswith("HOST")]
    # Base corpus has a fixed bulk pool; never demand more hosts than exist.
    want = min(int(knobs["bulk_hosts"]), len(bulk))
    knobs = dict(knobs)
    knobs["bulk_hosts"] = want
    bulk = bulk[:want]
    # strip rights based on knobs
    aws = find_group("AWS AD CONNECTORS")
    hd = find_group("CORP HELPDESK")
    aws_sid = aws["ObjectIdentifier"] if aws else None
    hd_sid = hd["ObjectIdentifier"] if hd else None
    for c in bulk:
        aces = list(c.get("Aces") or [])
        kept = []
        for a in aces:
            ps = a.get("PrincipalSID")
            if ps == aws_sid and not knobs["aws_bulk"]:
                continue
            if ps == hd_sid and not knobs["helpdesk_bulk"]:
                continue
            # default DA/EA aces always kept
            kept.append(a)
        c["Aces"] = kept
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

    # --- ASREP ---
    if not knobs["asrep"]:
        bob = find_user("BOB.ASREP")
        if bob:
            bob["Properties"]["dontreqpreauth"] = False

    # --- Shadow ---
    if not knobs["shadow_creds"]:
        grace = find_user("GRACE.SHADOW")
        if grace:
            grace["Aces"] = [
                a
                for a in (grace.get("Aces") or [])
                if a.get("RightName") != "AddKeyCredentialLink"
            ]

    # --- PNE / PNR ---
    if not knobs["pne"]:
        eve = find_user("EVE.PNE")
        if eve:
            eve["Properties"]["pwdneverexpires"] = False
    if not knobs["pnr"]:
        frank = find_user("FRANK.PNR")
        if frank:
            frank["Properties"]["passwordnotreqd"] = False

    # --- LocalAdmin help ---
    if not knobs["localadmin_help"]:
        ws01 = find_computer("WS01")
        if ws01:
            ws01["LocalGroups"] = [
                lg
                for lg in (ws01.get("LocalGroups") or [])
                if "ADMINISTRATOR" not in str(lg.get("Name", "")).upper()
                or not any(
                    "DAVE" in str(r).upper() or "1106" in str(r)
                    for r in (lg.get("Results") or [])
                )
            ]
            # simpler: clear helpdesk from local admins
            for lg in ws01.get("LocalGroups") or []:
                if "ADMINISTRATOR" in str(lg.get("Name", "")).upper():
                    dave = find_user("DAVE.HELP")
                    if dave:
                        lg["Results"] = [
                            r
                            for r in (lg.get("Results") or [])
                            if r.get("ObjectIdentifier") != dave["ObjectIdentifier"]
                        ]

    # refresh meta counts
    files["users.json"]["meta"]["count"] = len(users)
    files["computers.json"]["meta"]["count"] = len(computers)
    files["computers.json"]["data"] = computers
    files["groups.json"]["data"] = groups
    files["gpos.json"]["data"] = gpos
    files["domains.json"]["data"] = domains
    files["certtemplates.json"]["data"] = templates
    files["certtemplates.json"]["meta"]["count"] = len(templates)

    # rebuild ground-truth checks from knobs
    checks: List[Dict[str, Any]] = []
    if knobs["msol_dcsync"]:
        checks.append(
            {
                "id": "unexpected_dcsync",
                "type": "output_contains",
                "detector": "print_dcsync_rights",
                "must_contain": ["MSOL_SYNC", "Unexpected"],
            }
        )
        checks.append(
            {
                "id": "unexpected_dcsync_finding",
                "type": "finding",
                "category": "DCSync",
                "must_contain": "MSOL_SYNC",
            }
        )
    else:
        checks.append(
            {
                "id": "no_msol_dcsync",
                "type": "output_not_contains",
                "detector": "print_dcsync_rights",
                "must_not_contain": ["MSOL_SYNC@"],
            }
        )

    checks.append(
        {
            "id": "system_admins_not_default_priv",
            "type": "predicate",
            "predicate": "system_admins_not_default_priv",
        }
    )

    if knobs["helpdesk_bulk"]:
        checks.append(
            {
                "id": "helpdesk_rbcd_bulk",
                "type": "rbcd_principal_min",
                "principal_contains": "HELPDESK",
                "min_count": knobs["bulk_hosts"],
            }
        )
    if knobs["aws_bulk"]:
        checks.append(
            {
                "id": "aws_rbcd_bulk",
                "type": "rbcd_principal_min",
                "principal_contains": "AWS AD CONNECTORS",
                "min_count": knobs["bulk_hosts"],
            }
        )
    if knobs["alice_war_pentest"]:
        checks.append(
            {
                "id": "alice_pentest_rbcd",
                "type": "rbcd_pair",
                "principal_contains": "ALICE.LOW",
                "target_contains": "PENTESTPC",
            }
        )
    if knobs["rbcd_configured"]:
        checks.append(
            {
                "id": "rbcd_configured",
                "type": "output_contains",
                "detector": "print_rbcd",
                "must_contain": ["PENTESTPC", "RBCD configured"],
            }
        )
    if knobs["auth_users_gpo"]:
        checks.append(
            {
                "id": "auth_users_gpo",
                "type": "output_contains",
                "detector": "print_gpo_abuse",
                "must_contain": ["PAMAGENTINSTALL", "AUTHENTICATED USERS"],
                "must_not_contain": ["NO LINKS DETECTED"],
            }
        )
    if knobs["everyone_user_gw"]:
        checks.append(
            {
                "id": "everyone_mrios",
                "type": "broad_acl",
                "principal_contains": "EVERYONE",
                "target_contains": "MRIOS",
            }
        )
    if knobs["esc1"]:
        checks.append(
            {
                "id": "esc1",
                "type": "output_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_contain": ["ESC1", "ESC1-USERAUTH"],
            }
        )
    else:
        checks.append(
            {
                "id": "no_esc1_template",
                "type": "output_not_contains",
                "detector": "print_adcs_vulnerabilities",
                "must_not_contain": ["ESC1-USERAUTH"],
            }
        )
    if knobs["privileged_kerb"]:
        checks.append(
            {
                "id": "priv_kerb",
                "type": "output_contains",
                "detector": "print_privileged_roast_targets",
                "must_contain": ["SVC_SQL"],
            }
        )
    if knobs["asrep"]:
        checks.append(
            {
                "id": "asrep",
                "type": "output_contains",
                "detector": "print_as_rep_roastable",
                "must_contain": ["BOB.ASREP"],
            }
        )
    if knobs["pne"]:
        checks.append(
            {
                "id": "pne",
                "type": "output_contains",
                "detector": "print_password_never_expires",
                "must_contain": ["EVE.PNE"],
            }
        )
    if knobs["pnr"]:
        checks.append(
            {
                "id": "pnr",
                "type": "output_contains",
                "detector": "print_password_not_required",
                "must_contain": ["FRANK.PNR"],
            }
        )
    if knobs["shadow_creds"]:
        checks.append(
            {
                "id": "shadow",
                "type": "output_contains",
                "detector": "print_shadow_credentials",
                "must_contain_any": ["DAVE.HELP", "GRACE.SHADOW"],
            }
        )
    if knobs["localadmin_help"]:
        checks.append(
            {
                "id": "localadmin",
                "type": "output_contains",
                "detector": "print_sessions_localadmin",
                "must_contain": ["DAVE.HELP", "LocalAdmin"],
                "must_not_contain": ["GenericAll"],
            }
        )
    if knobs["alice_war_pentest"]:
        checks.append(
            {
                "id": "dossier_alice",
                "type": "dossier_impact",
                "principal": f"ALICE.LOW@{DOMAIN}",
                "min_impact": 1,
            }
        )
    checks.append(
        {
            "id": "laps_summary",
            "type": "output_contains",
            "detector": "print_laps_status",
            "must_contain": ["LAPS enabled"],
        }
    )

    gt = {
        "domain": DOMAIN,
        "knobs": knobs,
        "checks": checks,
        "stats": {
            "users": len(users),
            "computers": len(computers),
            "groups": len(groups),
            "bulk_hosts": want,
        },
    }
    return files, gt


def write_files(out_dir: Path, files: dict, gt: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "ground_truth.json").write_text(
        json.dumps(gt, indent=2) + "\n", encoding="utf-8"
    )


def run_checks(G, gt: dict) -> List[Tuple[str, bool, str]]:
    """Return list of (check_id, passed, detail)."""
    results: List[Tuple[str, bool, str]] = []
    bb["global_findings"] = []
    cache: Dict[str, str] = {}

    def out_for(detector: str) -> str:
        if detector not in cache:
            fn = bb[detector]
            bb["global_findings"] = []
            cache[detector] = _capture(fn, G).upper()
        return cache[detector]

    for check in gt.get("checks") or []:
        cid = check["id"]
        ctype = check["type"]
        try:
            if ctype == "output_contains":
                text = out_for(check["detector"])
                missing = [s for s in check.get("must_contain") or [] if s.upper() not in text]
                bad = [
                    s
                    for s in check.get("must_not_contain") or []
                    if s.upper() in text
                ]
                ok = not missing and not bad
                detail = f"missing={missing} forbidden_hit={bad}" if not ok else "ok"
                results.append((cid, ok, detail))
            elif ctype == "output_not_contains":
                text = out_for(check["detector"])
                hits = [s for s in check.get("must_not_contain") or [] if s.upper() in text]
                ok = not hits
                results.append((cid, ok, f"unexpected={hits}" if hits else "ok"))
            elif ctype == "finding":
                # ensure detector ran
                out_for(
                    {
                        "DCSync": "print_dcsync_rights",
                        "ESC1-ESC8": "print_adcs_vulnerabilities",
                    }.get(check.get("category", ""), "print_dcsync_rights")
                )
                cats = [
                    f
                    for f in bb["global_findings"]
                    if f[1] == check["category"]
                    and check.get("must_contain", "").upper() in f[2].upper()
                ]
                # re-run dcsync specifically for findings
                if check["category"] == "DCSync":
                    bb["global_findings"] = []
                    _capture(bb["print_dcsync_rights"], G)
                    cats = [
                        f
                        for f in bb["global_findings"]
                        if f[1] == "DCSync"
                        and check.get("must_contain", "").upper() in f[2].upper()
                    ]
                ok = bool(cats)
                results.append((cid, ok, f"findings={len(cats)}"))
            elif ctype == "rbcd_principal_min":
                rows = bb["collect_can_configure_rbcd"](G)
                summary = bb["summarize_can_configure_rbcd"](rows)
                needle = check["principal_contains"].upper()
                match = [s for s in summary if needle in s["principal"].upper()]
                ok = bool(match) and match[0]["count"] >= int(check["min_count"])
                detail = (
                    f"count={match[0]['count'] if match else 0} need>={check['min_count']}"
                )
                results.append((cid, ok, detail))
            elif ctype == "rbcd_pair":
                rows = bb["collect_can_configure_rbcd"](G)
                ok = any(
                    check["principal_contains"].upper() in r["principal"].upper()
                    and check["target_contains"].upper() in r["target"].upper()
                    for r in rows
                )
                results.append((cid, ok, "pair found" if ok else "pair missing"))
            elif ctype == "broad_acl":
                rows = bb["collect_broad_principal_acls"](G)
                ok = any(
                    check["principal_contains"].upper() in r["principal"].upper()
                    and check["target_contains"].upper() in r["target"].upper()
                    for r in rows
                )
                results.append((cid, ok, "acl found" if ok else "acl missing"))
            elif ctype == "dossier_impact":
                dossier = bb["build_compromise_dossier"](G, check["principal"])
                n = (dossier or {}).get("counts", {}).get("impact_edges", 0)
                ok = dossier is not None and n >= int(check["min_impact"])
                results.append((cid, ok, f"impact_edges={n}"))
            elif ctype == "predicate" and check.get("predicate") == "system_admins_not_default_priv":
                name = f"SYSTEM ADMINISTRATORS@{DOMAIN}"
                ok = not bb["_is_default_high_priv_name"](name)
                # helpdesk nested into system admins not expected admin
                hd = None
                for n, d in G.nodes(data=True):
                    if "CORP HELPDESK" in (d.get("name") or "").upper():
                        hd = n
                        break
                if hd is not None:
                    ok = ok and not bb["is_expected_admin_principal"](G, hd)
                results.append((cid, ok, "ok" if ok else "false positive high-priv"))
            else:
                results.append((cid, False, f"unknown check type {ctype}"))
        except Exception as e:
            results.append((cid, False, f"exception: {e}"))
    return results


def run_one(scenario_idx: int, seed: int, work_root: Path, verbose: bool) -> Dict[str, Any]:
    knobs = scenario_knobs(seed)
    label = f"scenario-{scenario_idx:02d}-seed-{seed}-{knobs['label']}"
    out_dir = work_root / label
    # Base full corpus then apply knobs
    files, _base_gt = build_corpus()
    files, gt = apply_knobs_to_corpus(files, _base_gt, knobs)
    gt["seed"] = seed
    gt["scenario_index"] = scenario_idx
    write_files(out_dir, files, gt)

    t0 = time.time()
    nodes = bb["load_json_dir"](str(out_dir))
    G, _ = bb["build_graph"](nodes)
    checks = run_checks(G, gt)
    elapsed = time.time() - t0

    failed = [(c, d) for c, ok, d in checks if not ok]
    passed = sum(1 for _, ok, _ in checks if ok)
    result = {
        "label": label,
        "seed": seed,
        "knobs": knobs,
        "path": str(out_dir),
        "checks_total": len(checks),
        "checks_passed": passed,
        "checks_failed": len(failed),
        "failed": failed,
        "elapsed_sec": round(elapsed, 3),
        "ok": not failed,
        "stats": gt.get("stats"),
    }
    if verbose and failed:
        for c, d in failed:
            print(f"      FAIL {c}: {d}")
    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate N synthetic scenarios, run BloodBash, validate accuracy."
    )
    ap.add_argument("--count", type=int, default=10, help="Number of scenarios (default 10)")
    ap.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Base seed (default: random). Scenario i uses seed+i (or seed 0 for first if --include-canonical)",
    )
    ap.add_argument(
        "--include-canonical",
        action="store_true",
        help="Force scenario 1 to use seed=0 (full canonical lab)",
    )
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Directory for generated corpora (default: temp dir)",
    )
    ap.add_argument(
        "--keep",
        action="store_true",
        help="Keep generated corpora (default: delete temp unless --work-dir)",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

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
    print("BloodBash synthetic scenario battery")
    print(f"  count={args.count}  base_seed={base_seed}  work={work_root}")
    print("=" * 72)

    results: List[Dict[str, Any]] = []
    for i in range(1, args.count + 1):
        if args.include_canonical and i == 1:
            seed = 0
        else:
            seed = base_seed + i
        print(f"\n[{i}/{args.count}] seed={seed} …", flush=True)
        try:
            r = run_one(i, seed, work_root, args.verbose)
        except Exception as e:
            r = {
                "label": f"scenario-{i:02d}-seed-{seed}",
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
                print(r["error"])
        results.append(r)
        status = "PASS" if r["ok"] else "FAIL"
        print(
            f"  {status}  checks={r['checks_passed']}/{r['checks_total']}  "
            f"time={r.get('elapsed_sec', 0)}s  "
            f"hosts={((r.get('stats') or {}).get('computers'))}"
        )
        if not r["ok"] and r.get("failed"):
            for c, d in r["failed"][:8]:
                print(f"    - {c}: {d}")

    # Summary
    n_pass = sum(1 for r in results if r["ok"])
    n_fail = len(results) - n_pass
    print("\n" + "=" * 72)
    print(f"SUMMARY: {n_pass}/{len(results)} scenarios passed")
    if n_fail:
        print("Failed scenarios:")
        for r in results:
            if not r["ok"]:
                print(f"  • {r['label']}  (seed={r['seed']})")
                for c, d in (r.get("failed") or [])[:5]:
                    print(f"      {c}: {d}")
    print(f"Work dir: {work_root}")
    if cleanup:
        shutil.rmtree(work_root, ignore_errors=True)
        print("(temp work dir removed; pass --keep or --work-dir to retain)")
    else:
        print("(corpora retained)")
    print("=" * 72)

    # Write machine-readable report next to work dir if kept
    if not cleanup:
        report = work_root / "battery_report.json"
        report.write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"Report: {report}")

    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
