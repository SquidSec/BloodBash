# BloodBash operator runbook

Day-2 procedures. Each one follows Goal / Prerequisites / Steps / Verify / If it fails.

Replace `DIR` with the SharpHound or AzureHound directory or zip for your engagement. Use `python3 BloodBash.py` in place of `bloodbash` when running from a clone.

| Related | Purpose |
|---------|---------|
| [User guide](user-guide.md) | Feature reference |
| [Cookbook](cookbook.md) | Short recipes |
| [Docs index](README.md) | Catalog |

---

## Table of contents

1. [First contact with a collection](#first-contact-with-a-collection)
2. [Run day-0 triage](#run-day-0-triage)
3. [Run a full analysis](#run-a-full-analysis)
4. [Handle a fresh foothold](#handle-a-fresh-foothold)
5. [Answer "can they reach Domain Admin?"](#answer-can-they-reach-domain-admin)
6. [Build a client deliverable](#build-a-client-deliverable)
7. [Produce PlumHound-compatible CSVs](#produce-plumhound-compatible-csvs)
8. [Run a PlumHound task list](#run-a-plumhound-task-list)
9. [Re-run with different checks](#re-run-with-different-checks)
10. [Merge multi-domain collections](#merge-multi-domain-collections)
11. [Scope to one domain](#scope-to-one-domain)
12. [Wire into CI](#wire-into-ci)
13. [Retest after remediation](#retest-after-remediation)
14. [Add a custom detector](#add-a-custom-detector)
15. [Investigate a disputed finding](#investigate-a-disputed-finding)
16. [Recover from a stale cache](#recover-from-a-stale-cache)

---

## First contact with a collection

### Goal

Know what you have before you analyze it: domains, object counts, and whether the collection is trustworthy enough to draw conclusions from.

### Prerequisites

- Collector output on local disk, as a directory or `.zip`.
- BloodBash installed.

### Steps

```bash
# 1) What is in here?
bloodbash DIR --list-domains

# 2) Health check plus a fast triage pass
bloodbash DIR --quick-wins --verbose
```

### Verify

- `--list-domains` lists the expected domains or tenants.
- The collection health banner shows plausible object counts and a reliability ceiling.

### If it fails

| Symptom | Action |
|---------|--------|
| Zero objects | Confirm the path is the collection, not its parent. Run `--debug` |
| Wrong or missing domain | Use `--merge` for the other collections |
| Reliability ceiling is low | Note it in the report. Check ADCS presence and SID-only counts |

### See also

- [Collection health](user-guide.md#collection-health)
- [Input and ingest](user-guide.md#input-and-ingest)

---

## Run day-0 triage

### Goal

Get the findings that change the engagement plan, in under a minute on a typical collection.

### Prerequisites

- Collection health reviewed.

### Steps

```bash
bloodbash DIR
# identical:
bloodbash DIR --quick-wins
```

To scope to one domain:

```bash
bloodbash DIR --quick-wins --domain CORP.LOCAL
```

### Verify

- Findings table is populated and sorted by severity.
- Paths section names concrete principals.

### If it fails

| Symptom | Action |
|---------|--------|
| Too few findings | Triage is deliberately narrow. Move to full analysis |
| Run is slow | Confirm `--fast` is implied; check graph cache is warm |

### See also

- [Quick wins](user-guide.md#quick-wins)
- [Run a full analysis](#run-a-full-analysis)

---

## Run a full analysis

### Goal

Coverage suitable for a deliverable: every detector, plus inventory ladders.

### Prerequisites

- Triage reviewed, so you know what to expect.

### Steps

```bash
bloodbash DIR --all --fast --all-findings
```

Add inventory and a deliverable in one pass:

```bash
bloodbash DIR --all --fast --inventory \
  --report-pack ./reports --export-zip reports.zip --log-file ./run.log
```

### Verify

- Every detector section is present or explicitly reported as skipped (Azure on an AD-only collection).
- `reports/index.html` opens and links to each page.

### If it fails

| Symptom | Action |
|---------|--------|
| Inventory sections missing | `--inventory` is not implied by `--all` |
| Very long run | Keep `--fast`, and reuse the graph cache |

### See also

- [Full analysis](user-guide.md#full-analysis)
- [Inventory](user-guide.md#inventory)

---

## Handle a fresh foothold

### Goal

Answer "what can this principal do right now?" and produce shareable lists.

### Prerequisites

- The principal name, and the domain if the SAM is ambiguous.

### Steps

```bash
# 1) Console dossier
bloodbash DIR --from-user alice

# 2) Export the dossier
bloodbash DIR --from-user alice --from-user-export ./alice-dossier

# 3) Add live write rights if you have them
bloodbash DIR --from-user alice --writable-file ./alice-writable.json \
  --from-user-export ./alice-dossier
```

Several footholds at once:

```bash
bloodbash DIR --from-user alice,bob,svc_backup --from-user-export ./footholds
bloodbash DIR --from-user-file ./footholds.txt --from-user-export ./footholds
```

### Verify

- `./alice-dossier/summary.md` exists.
- `membership_effective.txt` and `paths_to_high_value.txt` are populated.
- `counts.csv` shows nonzero group and right counts where you expect them.

### If it fails

| Symptom | Action |
|---------|--------|
| "Found in multiple domains" | Qualify as `alice@corp.local` or add `--domain` |
| Dossier is thin | SharpHound maps a filtered ACE set. Import live rights with `--writable-file` |
| No paths to high value | Confirm the target set with `--all --fast`, or widen with `--deep-paths` |

### See also

- [Compromise dossier](user-guide.md#compromise-dossier)
- [Name matching](user-guide.md#name-matching)

---

## Answer "can they reach Domain Admin?"

### Goal

A yes or no with a concrete path, suitable for a script or a one-line answer to a stakeholder.

### Prerequisites

- The source principal.

### Steps

```bash
# Renders one path, or a "no path" panel. Exit 1 when there is no path.
bloodbash DIR --golden-path

# From a specific principal
bloodbash DIR --golden-path --from-user alice --domain CORP.LOCAL

# Scriptable: branch on the exit status, not the text
if bloodbash DIR --golden-path --from-user alice > /dev/null; then
  echo "path exists"
else
  echo "no path"
fi
```

For an arbitrary pair:

```bash
bloodbash DIR --path-from alice --path-to 'domain admins@corp.local'
```

### Verify

- A path panel renders with a copy-paste line, or a "no path" panel.
- Exit code is 0 with a path and 1 without.
- Each hop names a real relationship.

### If it fails

| Symptom | Action |
|---------|--------|
| No path where you expect one | Check hop limits; try `--path-mode deep --path-depth 16` |
| Path is all MemberOf | Use `--path-mode abuse` to prefer exploitable edges |
| Ambiguous source | Qualify the name |

### See also

- [Attack paths](user-guide.md#attack-paths)
- [Exit codes](user-guide.md#exit-codes)

---

## Build a client deliverable

### Goal

A navigable report pack plus a zip, with a run log for provenance.

### Prerequisites

- Full analysis complete.
- A destination directory.

### Steps

```bash
bloodbash DIR --all --fast --inventory --all-findings \
  --busiest-paths short --path-break \
  --report-pack ./deliverable \
  --export-zip deliverable.zip \
  --log-file ./deliverable/run.log
```

### Verify

- `deliverable/index.html` opens with no broken links.
- `deliverable/manifest.json` lists every file.
- `deliverable/csv/` contains a CSV matching each HTML page.

### If it fails

| Symptom | Action |
|---------|--------|
| Zip is empty | `--export-zip` needs a pack in the same run |
| A page is blank | That dataset was empty for this collection. Check `manifest.json` |

### See also

- [Report pack](user-guide.md#report-pack)
- [CSV pack](user-guide.md#csv-pack)

---

## Produce PlumHound-compatible CSVs

### Goal

One CSV per report, plus an index, matching the shape PlumHound emits.

### Prerequisites

- None beyond a collection.

### Steps

```bash
bloodbash DIR --csv-pack ./ph-reports
bloodbash DIR --all --fast --csv-pack ./ph-full --export-zip ph-full.zip
```

### Verify

- `./ph-reports/index.csv` lists each file with a row count.
- Expected files exist: `users.csv`, `computers.csv`, `groups.csv`, `kerberoastable.csv`, `laps_not_enabled.csv`, `local_admins_users.csv`.

### If it fails

| Symptom | Action |
|---------|--------|
| A CSV is header-only | That dataset is genuinely empty |
| Need a different set | Write a `.tasks` list instead |

### See also

- [CSV pack](user-guide.md#csv-pack)
- [Run a PlumHound task list](#run-a-plumhound-task-list)

---

## Run a PlumHound task list

### Goal

Execute a `.tasks` file with no Neo4j and no BloodHound import.

### Prerequisites

- A `.tasks` file. PlumHound's own lists work.

### Steps

```bash
# 1) Validate first
bloodbash --tasks-validate ./my-list.tasks

# 2) Run
bloodbash DIR --tasks ./my-list.tasks --tasks-out ./task-reports

# 3) Optional: force a format, or fail on any error
bloodbash DIR --tasks ./my-list.tasks --tasks-format CSV
bloodbash DIR --tasks ./my-list.tasks --tasks-strict
```

### Verify

- `./task-reports/index.csv` shows `ok` and a row count per task.
- Each task's file exists.

### If it fails

| Symptom | Action |
|---------|--------|
| A task shows zero rows | The query matched nothing. Check the projection property first |
| A task shows an error | The index records the clause. See the supported subset |
| Validation exits 2 | The line is malformed. Check quoting and list-literal syntax |

### See also

- [Task query subset](user-guide.md#task-query-subset)
- [Projection limits](architecture.md#projection-limits)

---

## Re-run with different checks

### Goal

Ask a new question about the same collection without paying ingest cost again.

### Prerequisites

- One prior run against the same files.

### Steps

```bash
bloodbash DIR --dcsync              # first run: ingest + cache
bloodbash DIR --kerberoastable      # cache hit
bloodbash DIR --from-user alice     # cache hit
```

### Verify

- Output begins with a cache hit line naming the fingerprint.

### If it fails

| Symptom | Action |
|---------|--------|
| Cache miss every time | File mtimes changed, or the source set changed |
| Results look stale | `--rebuild-cache` |

### See also

- [Graph cache](user-guide.md#graph-cache)
- [Recover from a stale cache](#recover-from-a-stale-cache)

---

## Merge multi-domain collections

### Goal

One graph across several collections, so paths can cross domain boundaries.

### Prerequisites

- Each collection in its own directory or zip.

### Steps

```bash
bloodbash ./lowpriv.zip --merge ./da.zip --all --fast
bloodbash ./forest-root --merge ./child-a.zip ./child-b.zip --quick-wins
```

### Verify

- `--list-domains` on the merged run lists every domain.
- Paths can name principals from more than one domain.

### If it fails

| Symptom | Action |
|---------|--------|
| A domain is missing | Confirm the path is included in `--merge` |
| Duplicate objects | Expected when collections overlap; merging unions properties |

### See also

- [Input and ingest](user-guide.md#input-and-ingest)
- [Scope to one domain](#scope-to-one-domain)

---

## Scope to one domain

### Goal

Attribute findings and pathfinding to a single domain or tenant.

### Prerequisites

- Domain list from `--list-domains`.

### Steps

```bash
bloodbash DIR --list-domains
bloodbash DIR --all --domain CORP.LOCAL
bloodbash DIR --quick-wins --domain TTIG
```

### Verify

- Findings name only that domain.
- Exit code is 0.

### If it fails

| Symptom | Action |
|---------|--------|
| Exit 3 | The filter matched nothing. The message lists valid values |
| Netbios prefix not matching | Use the DNS name, or check the prefix spelling |

### See also

- [Domain filtering](user-guide.md#domain-filtering)
- [Exit codes](user-guide.md#exit-codes)

---

## Wire into CI

### Goal

Fail a pipeline on new high-severity findings, while tolerating known debt.

### Prerequisites

- A stored baseline JSON from an accepted run.
- A suppression file for accepted risk.

### Steps

```bash
# 1) Create the baseline once, after accepting current state
bloodbash DIR --all --export json
mv bloodbash.json baseline.json

# 2) Gate only on regressions
bloodbash DIR --all --fast \
  --baseline baseline.json \
  --suppress suppressions.yaml \
  --fail-on-severity 8 \
  --export sarif
```

`suppressions.yaml`:

```yaml
suppressions:
  - category: Kerberoastable
    contains: SVC_SQL
    expires: 2026-12-31
```

### Verify

- Exit code 2 when a new finding at or above the threshold appears.
- Exit code 0 when only baselined or suppressed findings remain.
- SARIF uploads and produces code-scanning results.

### If it fails

| Symptom | Action |
|---------|--------|
| Gate never trips | Confirm the threshold and that rows are not suppressed |
| Gate always trips | Rebaseline, or add a suppression with an expiry |
| Baseline rejected | It must be a BloodBash JSON export |

### See also

- [CI gating](user-guide.md#ci-gating)
- [Suppressions](user-guide.md#suppressions)
- [Baselines](user-guide.md#baselines)

---

## Retest after remediation

### Goal

Show what changed since the last assessment.

### Prerequisites

- A prior snapshot or baseline.

### Steps

```bash
# Snapshot approach
bloodbash DIR --all --snapshot
# ... after remediation ...
bloodbash DIR --all --snapshot --trend

# Baseline approach
bloodbash DIR --all --export json
# ... after remediation ...
bloodbash DIR --all --baseline baseline.json
```

### Verify

- Trend or diff names specific new and resolved findings.

### If it fails

| Symptom | Action |
|---------|--------|
| Trend needs two snapshots | Run `--snapshot` at least twice |
| Diff is empty | Confirm both runs used the same collection and domain |

### See also

- [Snapshots and trend](user-guide.md#snapshots-and-trend)
- [Baselines](user-guide.md#baselines)

---

## Add a custom detector

### Goal

A site-specific check that reports alongside built-in findings.

### Prerequisites

- Python familiarity.
- A directory for plugins.

### Steps

```python
# ./detectors/password_policy.py
def run(G, add_finding):
    hits = 0
    for _, d in G.nodes(data=True):
        if (d.get("type") or "").lower() != "user":
            continue
        if (d.get("props") or {}).get("minpwdlength") == 0:
            add_finding("Policy Check", f"{d.get('name')} has no minimum password length", score=6)
            hits += 1
    return hits
```

```bash
bloodbash DIR --all --plugins-dir ./detectors
```

### Verify

- The plugin name appears in run output when it loads.
- Its category appears in the findings table.

### If it fails

| Symptom | Action |
|---------|--------|
| Plugin skipped in yellow | It raised on import, or has no `run(G, add_finding)` |
| Findings missing | Check the return value and that `add_finding` is called |

### See also

- [Plugins](user-guide.md#plugins)

---

## Investigate a disputed finding

### Goal

Show the evidence behind one finding.

### Prerequisites

- The category name or finding number.

### Steps

```bash
bloodbash DIR --all --explain DCSync
bloodbash DIR --all --explain 12
bloodbash DIR --inspect 'DOMAIN ADMINS@CORP.LOCAL'
```

### Verify

- `--explain` prints contributing rows, the ATT&CK id, and matching edges.
- `--inspect` prints the node's properties and edges.

### If it fails

| Symptom | Action |
|---------|--------|
| Category not found | Names are case-sensitive; check the category table |
| Node not found | Qualify the domain |

### See also

- [Explain](user-guide.md#explain)
- [Finding categories](user-guide.md#finding-categories)

---

## Recover from a stale cache

### Goal

Get results that match the current collection.

### Prerequisites

- A new collection, or a suspicion that results are stale.

### Steps

```bash
bloodbash DIR --all --rebuild-cache
```

To bypass the cache entirely:

```bash
bloodbash DIR --all --no-cache
```

To relocate it:

```bash
bloodbash DIR --all --cache-dir /tmp/bb-cache
```

### Verify

- Output shows a cache build, not a cache hit.
- Findings reflect the new collection.

### If it fails

| Symptom | Action |
|---------|--------|
| Still stale | Confirm you are pointing at the new path; the fingerprint includes paths |
| Disk pressure | Prune old fingerprint databases under `~/.cache/bloodbash/` |

### See also

- [Graph cache](user-guide.md#graph-cache)

---

## See also

- [User guide](user-guide.md)
- [Cookbook](cookbook.md)
- [Architecture](architecture.md)
- [Deployment](deployment.md)

For authorized security testing only.
