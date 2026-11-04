#!/usr/bin/env python3
"""Parity harness for task lists.

Runs every shipped `.tasks` fixture over a fixed corpus, writes the results to a
JSON snapshot, and can diff a fresh run against a committed baseline. The point
is to catch silent output changes: a query that starts returning different rows,
a projection that drops a property, or a synthetic edge that disappears.

Usage:
    python3 tools/task_parity.py --corpus testData/synthetic-corp-lab --write
    python3 tools/task_parity.py --corpus testData/synthetic-corp-lab --check
    python3 tools/task_parity.py --corpus DIR --list DIR.tasks
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import BloodBash as bb  # noqa: E402

BASELINE_NAME = "task_parity_baseline.json"
MANIFEST_NAME = "parity_manifest.json"
DEFAULT_TASK_DIR = ROOT / "tasks"
DEFAULT_CORPUS = ROOT / "testData" / "synthetic-corp-lab"

# Rows are compared as counts plus a stable digest of the first N rows, so a
# baseline stays readable while still catching row-level drift.
DIGEST_ROWS = 5


def _stable_rows(rows):
    return [[str(cell) for cell in row] for row in rows]


def run_fixture(task_path: Path, projection) -> dict:
    specs = bb.parse_task_file(str(task_path))
    tasks = []
    for spec in specs:
        entry = {
            "title": spec.title,
            "format": spec.fmt,
            "line": spec.line_no,
            "status": "ok",
        }
        if not spec.ok:
            entry["status"] = "parse-error"
            entry["error"] = spec.error
            tasks.append(entry)
            continue
        if spec.is_sentinel:
            entry["sentinel"] = spec.query.strip().upper()
            tasks.append(entry)
            continue
        try:
            result = bb.execute_task_query(spec.query, projection)
        except bb.TaskQueryError as exc:
            entry["status"] = "query-error"
            entry["error"] = str(exc)
            tasks.append(entry)
            continue
        entry["columns"] = list(result.columns)
        entry["rows"] = result.row_count
        entry["sample"] = _stable_rows(result.rows[:DIGEST_ROWS])
        tasks.append(entry)
    return {"file": task_path.name, "tasks": tasks}


def load_manifest(task_dir: Path) -> dict:
    path = task_dir / MANIFEST_NAME
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def collect(task_dir: Path, default_corpus: Path) -> dict:
    """Run each fixture against its corpus.

    A fixture whose name starts with ``azure`` uses the Azure corpus when the
    manifest names one, because AD-only collections legitimately return zero
    rows for Entra labels.
    """
    manifest = load_manifest(task_dir)
    projections = {}

    def projection_for(corpus: Path):
        key = str(corpus)
        if key not in projections:
            nodes = bb.load_json_dirs([str(corpus)])
            G, _ = bb.build_graph(nodes)
            projections[key] = (bb.build_bloodhound_projection(G), G)
        return projections[key]

    fixtures_out = []
    for path in sorted(task_dir.glob("*.tasks")):
        corpus_name = manifest.get(path.name) or manifest.get("*")
        corpus = Path(corpus_name) if corpus_name else default_corpus
        if not corpus.is_absolute():
            corpus = ROOT / corpus
        projection, G = projection_for(corpus)
        entry = run_fixture(path, projection)
        entry["corpus"] = corpus.name
        entry["nodes"] = G.number_of_nodes()
        entry["edges"] = G.number_of_edges()
        fixtures_out.append(entry)
    return {"fixtures": fixtures_out}


def compare(baseline: dict, current: dict) -> list[str]:
    problems: list[str] = []
    base_by_file = {f["file"]: f for f in baseline.get("fixtures", [])}
    cur_by_file = {f["file"]: f for f in current.get("fixtures", [])}
    for name in sorted(set(base_by_file) - set(cur_by_file)):
        problems.append(f"{name}: fixture removed")
    for name in sorted(set(cur_by_file) - set(base_by_file)):
        problems.append(f"{name}: new fixture (update the baseline if intended)")
    for name in sorted(set(base_by_file) & set(cur_by_file)):
        base_tasks = {t["title"]: t for t in base_by_file[name]["tasks"]}
        cur_tasks = {t["title"]: t for t in cur_by_file[name]["tasks"]}
        for title in sorted(set(base_tasks) - set(cur_tasks)):
            problems.append(f"{name}: task removed: {title}")
        for title in sorted(set(cur_tasks) - set(base_tasks)):
            problems.append(f"{name}: task added: {title}")
        for title in sorted(set(base_tasks) & set(cur_tasks)):
            before, after = base_tasks[title], cur_tasks[title]
            if before.get("rows") != after.get("rows"):
                problems.append(
                    f"{name}: {title}: row count {before.get('rows')} -> {after.get('rows')}"
                )
            if before.get("columns") != after.get("columns"):
                problems.append(f"{name}: {title}: columns changed")
            if before.get("sample") != after.get("sample"):
                problems.append(f"{name}: {title}: sample rows changed")
            if before.get("status") != after.get("status"):
                problems.append(
                    f"{name}: {title}: status {before.get('status')} -> {after.get('status')}"
                )
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS), help="Collection directory or zip")
    parser.add_argument("--tasks", default=str(DEFAULT_TASK_DIR), help="Directory of .tasks fixtures")
    parser.add_argument("--baseline", default=None, help="Baseline JSON path")
    parser.add_argument("--write", action="store_true", help="Write the baseline from this run")
    parser.add_argument("--check", action="store_true", help="Compare this run against the baseline")
    args = parser.parse_args(argv)

    task_dir = Path(args.tasks)
    corpus = Path(args.corpus)
    if not task_dir.is_dir():
        print(f"task directory not found: {task_dir}", file=sys.stderr)
        return 2
    if not corpus.exists():
        print(f"corpus not found: {corpus}", file=sys.stderr)
        return 2

    baseline_path = Path(args.baseline) if args.baseline else task_dir / BASELINE_NAME
    current = collect(task_dir, corpus)

    if args.write:
        baseline_path.write_text(json.dumps(current, indent=2, sort_keys=False), encoding="utf-8")
        print(f"baseline written: {baseline_path}")
        return 0

    if args.check:
        if not baseline_path.is_file():
            print(f"baseline missing: {baseline_path}", file=sys.stderr)
            return 2
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        problems = compare(baseline, current)
        if problems:
            for line in problems:
                print(f"CHANGED: {line}")
            return 1
        print(f"parity ok: {len(current['fixtures'])} fixtures")
        return 0

    total = sum(len(f["tasks"]) for f in current["fixtures"])
    errors = sum(
        1 for f in current["fixtures"] for t in f["tasks"] if t["status"].endswith("error")
    )
    print(f"fixtures: {len(current['fixtures'])}  tasks: {total}  errors: {errors}")
    for fixture in current["fixtures"]:
        print(f"  {fixture['file']}: {len(fixture['tasks'])} task(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
