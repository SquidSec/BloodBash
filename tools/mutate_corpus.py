#!/usr/bin/env python3
"""Mutate a SharpHound CE corpus to stress BloodBash ingest/detectors.

Examples:
  python3 tools/mutate_corpus.py --in testData/synthetic-corp-lab --out /tmp/mut --seed 1
  python3 tools/mutate_corpus.py --in testData/synthetic-corp-lab --out /tmp/mut --seed 2 \\
      --dup-aces --orphan-sids --null-aces --partial-drop certtemplates

Mutations are deterministic per seed. Never use on customer data inside the repo.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import shutil
from pathlib import Path
from typing import Any, Dict, List


def load_dir(src: Path) -> Dict[str, Any]:
    files = {}
    for p in src.glob("*.json"):
        if p.name == "ground_truth.json":
            continue
        files[p.name] = json.loads(p.read_text(encoding="utf-8"))
    return files


def mutate(
    files: Dict[str, Any],
    seed: int,
    *,
    dup_aces: bool = True,
    orphan_sids: bool = True,
    null_aces: bool = True,
    foreign_sids: bool = True,
    partial_drop: List[str] = None,
    alias_case: bool = True,
) -> Dict[str, Any]:
    rng = random.Random(seed)
    out = copy.deepcopy(files)
    partial_drop = partial_drop or []

    for name in list(out.keys()):
        stem = name.replace(".json", "").lower()
        if any(p.lower() in stem for p in partial_drop):
            del out[name]
            continue
        payload = out[name]
        data = payload.get("data")
        if not isinstance(data, list):
            continue
        for obj in data:
            if not isinstance(obj, dict):
                continue
            # Case-alias Properties keys occasionally
            if alias_case and rng.random() < 0.15 and isinstance(obj.get("Properties"), dict):
                props = obj["Properties"]
                if "name" in props and "Name" not in props and rng.random() < 0.5:
                    props["Name"] = props["name"]
            aces = obj.get("Aces")
            if aces is None:
                continue
            if not isinstance(aces, list):
                continue
            if null_aces and rng.random() < 0.1:
                aces.append(None)
                aces.append("not-a-dict")
            if dup_aces and aces and rng.random() < 0.2:
                aces.append(copy.deepcopy(aces[0]))
            if orphan_sids and rng.random() < 0.1:
                aces.append(
                    {
                        "PrincipalSID": f"S-1-5-21-999-{rng.randint(1,999)}-{rng.randint(1,999)}-{rng.randint(1000,9999)}",
                        "PrincipalType": "User",
                        "RightName": "GenericWrite",
                        "IsInherited": False,
                    }
                )
            if foreign_sids and rng.random() < 0.08:
                aces.append(
                    {
                        "PrincipalSID": f"S-1-5-21-111-222-333-{rng.randint(1000,9999)}",
                        "PrincipalType": "ForeignSecurityPrincipal",
                        "RightName": "GenericAll",
                        "IsInherited": True,
                    }
                )
            obj["Aces"] = aces
        if "meta" in payload and isinstance(payload["meta"], dict):
            payload["meta"]["count"] = len(data)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="src", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--dup-aces", action="store_true", default=True)
    ap.add_argument("--no-dup-aces", action="store_false", dest="dup_aces")
    ap.add_argument("--orphan-sids", action="store_true", default=True)
    ap.add_argument("--null-aces", action="store_true", default=True)
    ap.add_argument("--foreign-sids", action="store_true", default=True)
    ap.add_argument(
        "--partial-drop",
        nargs="*",
        default=[],
        help="Drop files whose names contain these tokens (e.g. certtemplates sessions)",
    )
    args = ap.parse_args()
    src = args.src.resolve()
    out = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    files = load_dir(src)
    mut = mutate(
        files,
        args.seed,
        dup_aces=args.dup_aces,
        orphan_sids=args.orphan_sids,
        null_aces=args.null_aces,
        foreign_sids=args.foreign_sids,
        partial_drop=args.partial_drop,
    )
    for name, payload in mut.items():
        (out / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote mutated corpus to {out} ({len(mut)} files, seed={args.seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
