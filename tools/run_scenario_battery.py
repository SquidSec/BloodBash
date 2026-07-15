#!/usr/bin/env python3
"""Run 10 realistic multi-hop engagement scenarios through BloodBash.

Each scenario is a composite attack chain (foothold → pivots → DA/DCSync)
drawn from common red-team patterns. Fictional domains only.

  python3 tools/run_scenario_battery.py
  python3 tools/run_scenario_battery.py --count 10 --seed 42 -v
  python3 tools/run_scenario_battery.py --list-profiles
  python3 tools/run_scenario_battery.py --keep --work-dir /tmp/bb-engagements

CI runs this with --count 10 --seed 42; exit 0 only if all checks pass.
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
from typing import Any, Callable, Dict, List, Tuple
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from generate_engagement_scenarios import (  # noqa: E402
    BUILDERS,
    ENGAGEMENT_SCENARIOS,
    build_engagement_scenario,
    list_scenarios,
)

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


def write_files(out_dir: Path, files: dict, gt: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in files.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (out_dir / "ground_truth.json").write_text(
        json.dumps(gt, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "SCENARIO.md").write_text(
        f"# {gt.get('title', gt.get('scenario_id'))}\n\n"
        f"**Domain:** `{gt.get('domain')}`  \n"
        f"**Foothold:** {gt.get('foothold')}  \n"
        f"**Seed:** {gt.get('seed')}\n\n"
        f"{gt.get('summary', '')}\n\n"
        f"## Attack notes\n\n"
        + "\n".join(f"- {n}" for n in (gt.get("notes") or []))
        + "\n",
        encoding="utf-8",
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
                results.append(
                    (cid, ok, f"missing={missing} forbidden={bad}" if not ok else "ok")
                )
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
                    "Kerberoastable": "print_kerberoastable",
                }.get(check["category"], "print_dcsync_rights")
                _capture(bb[det], G)
                cats = [
                    f
                    for f in bb["global_findings"]
                    if f[1] == check["category"]
                    and check.get("must_contain", "").upper() in f[2].upper()
                ]
                results.append((cid, bool(cats), f"n={len(cats)}"))
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
            else:
                results.append((cid, False, f"unknown type {ctype}"))
        except Exception as e:
            results.append((cid, False, f"exception: {e}"))
    return results


def run_one(
    idx: int, seed: int, scenario_meta: dict, work_root: Path, verbose: bool
) -> Dict[str, Any]:
    sid = scenario_meta["id"]
    label = f"s{idx:02d}-{sid}-seed{seed}"
    out_dir = work_root / label
    files, gt = build_engagement_scenario(sid, seed)
    write_files(out_dir, files, gt)

    t0 = time.time()
    nodes = bb["load_json_dir"](str(out_dir))
    G, _ = bb["build_graph"](nodes)
    checks = run_checks(G, gt)
    elapsed = time.time() - t0
    failed = [(c, d) for c, ok, d in checks if not ok]
    return {
        "label": label,
        "scenario_id": sid,
        "title": scenario_meta.get("title"),
        "domain": gt.get("domain"),
        "foothold": scenario_meta.get("foothold"),
        "summary": scenario_meta.get("summary"),
        "notes": gt.get("notes"),
        "seed": seed,
        "path": str(out_dir),
        "checks_total": len(checks),
        "checks_passed": sum(1 for _, ok, _ in checks if ok),
        "checks_failed": len(failed),
        "failed": failed,
        "elapsed_sec": round(elapsed, 3),
        "ok": not failed,
        "stats": gt.get("stats"),
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Multi-hop engagement scenario battery for BloodBash"
    )
    ap.add_argument("--count", type=int, default=10, help="Scenarios (default 10)")
    ap.add_argument("--seed", type=int, default=None, help="Base seed (default random)")
    ap.add_argument("--work-dir", type=Path, default=None)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument(
        "--list-profiles",
        action="store_true",
        help="List engagement scenarios and exit",
    )
    args = ap.parse_args()

    scenarios = list_scenarios()
    if args.list_profiles:
        for i, s in enumerate(scenarios, 1):
            print(f"{i:2d}. {s['id']}")
            print(f"    {s['title']}")
            print(f"    domain={s['domain']}  foothold={s['foothold']}")
            print(f"    {s['summary']}")
            print()
        return 0

    base_seed = args.seed if args.seed is not None else random.randint(1, 1_000_000)
    work_root = args.work_dir
    cleanup = False
    if work_root is None:
        work_root = Path(tempfile.mkdtemp(prefix="bloodbash-engagements-"))
        cleanup = not args.keep
    else:
        work_root = work_root.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    print("=" * 76)
    print("BloodBash multi-hop engagement scenario battery")
    print(f"  count={args.count}  base_seed={base_seed}")
    print(f"  work={work_root}")
    print("=" * 76)

    results: List[Dict[str, Any]] = []
    for i in range(1, args.count + 1):
        meta = scenarios[(i - 1) % len(scenarios)]
        seed = base_seed + i * 31
        print(f"\n[{i}/{args.count}] {meta['id']}", flush=True)
        print(f"  {meta['title']}")
        print(f"  domain={meta['domain']}  foothold={meta['foothold']}  seed={seed}")
        try:
            r = run_one(i, seed, meta, work_root, args.verbose)
        except Exception as e:
            r = {
                "label": f"s{i:02d}-{meta['id']}",
                "scenario_id": meta["id"],
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
            f"  {status}  checks={r['checks_passed']}/{r['checks_total']}  "
            f"graph={r.get('nodes')}n/{r.get('edges')}e  "
            f"users={((r.get('stats') or {}).get('users'))}  "
            f"computers={((r.get('stats') or {}).get('computers'))}  "
            f"{r.get('elapsed_sec', 0)}s"
        )
        if args.verbose and r.get("notes"):
            for n in r["notes"]:
                print(f"    • {n}")
        if not r["ok"]:
            for c, d in (r.get("failed") or [])[:10]:
                print(f"    ✗ {c}: {d}")

    n_pass = sum(1 for r in results if r["ok"])
    print("\n" + "=" * 76)
    print(f"SUMMARY: {n_pass}/{len(results)} scenarios passed")
    print("By scenario:")
    by: Dict[str, List[bool]] = {}
    for r in results:
        by.setdefault(r.get("scenario_id") or "?", []).append(bool(r["ok"]))
    for sid, flags in by.items():
        print(f"  {sid:42s}  {sum(flags)}/{len(flags)}")
    if n_pass < len(results):
        print("Failed:")
        for r in results:
            if not r["ok"]:
                print(f"  • {r.get('label')}")
                for c, d in (r.get("failed") or [])[:6]:
                    print(f"      {c}: {d}")
    print(f"Work dir: {work_root}")
    if cleanup:
        shutil.rmtree(work_root, ignore_errors=True)
        print("(temp removed; use --keep or --work-dir to retain)")
    else:
        report = work_root / "battery_report.json"
        report.write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"Report: {report}")
    print("=" * 76)
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
