# BloodBash architecture

How BloodBash ingests collector data, builds a graph, runs detectors, and projects the graph for task lists.

| Related | Purpose |
|---------|---------|
| [User guide](user-guide.md) | Feature reference |
| [Deployment](deployment.md) | Install and build |
| [Docs index](README.md) | Catalog |

---

## Design constraints

Four constraints shape every decision:

| Constraint | Consequence |
|------------|-------------|
| **No database server** | The graph lives in memory; persistence is a SQLite snapshot, not a query surface |
| **Read-only** | BloodBash never modifies a collection. Write clauses are rejected in task lists |
| **One file** | `BloodBash.py` holds the whole application so the PyInstaller binary stays simple |
| **Offline** | No network calls at runtime. Plugins are the only code loaded from disk |

---

## Pipeline

```text
paths (dir or zip)
   |
   v
[1] discover     walk nested folders, skip post-collection dirs
   |
   v
[2] parse        per-file JSON -> normalized node dicts + pending edges
   |
   v
[3] merge        union duplicate objects across collections (--merge)
   |
   v
[4] build        NetworkX MultiDiGraph, edges from Aces/Members/Links/ContainedBy
   |
   v
[5] cache        fingerprint -> SQLite (skip steps 1-4 next time)
   |
   v
[6] analyze      detectors -> add_finding(score, category, details)
   |
   v
[7] present      console table, exports, packs, gate
```

### 1. Discovery

`_collector_json_relpaths` walks the input directory, including nested folders, up to a bounded depth. It skips directories BloodHound CE writes after collection (processed output, reports) and dot-directories. Zips are extracted to a temporary directory first.

`_safe_extract_zip` rejects any member whose resolved path escapes the extraction root (Zip Slip).

### 2. Parse

`_parse_json_dir` reads each file, determines the object type, and normalizes properties.

Object type resolution order:

1. `meta.type` in the file
2. Filename inference (`_type_from_filename`), stripping a leading timestamp
3. Shape detection, for files without metadata

SharpHound CE property name aliases are accepted, so `lastLogonTimestamp` and `lastlogontimestamp` resolve to the same property. `_extract_node_props` lowercases keys into the internal property bag.

### 3. Merge

`--merge` unions several collections. `merge_collector_nodes` and `_union_collector_lists` combine objects that appear in more than one collection without discarding properties from either. This is what makes a low-priv plus DA merge produce one coherent graph.

### 4. Build

`build_graph` creates a `networkx.MultiDiGraph`. Nodes are keyed by object identifier, with a SHA-256 fallback when a collector omits one so IDs stay stable across runs.

Edge sources:

| Source | Edge |
|--------|------|
| `Aces[].RightName` | `PrincipalSID` -> object, labeled with the right |
| `Members[]` | member -> group, `MemberOf` |
| `AllowedToAct[]` | principal -> computer, `AddAllowedToAct` |
| `Sessions[]` / `LocalGroups[]` | `HasSession`, `LocalAdmin` |
| `Links[]` | container -> GPO, `GPLink` |
| `ContainedBy` | parent -> child, `Contains` |
| `Trusts[]` | domain -> domain, `TrustedDomain:<dir>:<type>` |

Legacy SharpHound encodes extended rights as `RightName=ExtendedRight` with the real right in `AceType` or `RightGuid`. The parser resolves that into the specific right (`GetChanges`, `GetChangesAll`, …).

`link_sid_only_principals` and `add_well_known_group_memberships` post-process the graph to connect SID-only placeholders and inject the well-known groups (Everyone, Authenticated Users, Domain Users, …) that collectors reference but do not always define.

### 5. Cache

`compute_collection_fingerprint` hashes the normalized source paths with each file's size and modification time. The fingerprint names the cache file: `~/.cache/bloodbash/graph-<fingerprint>.db`.

`graph_cache_is_valid` compares the stored fingerprint before loading. A mismatch triggers re-ingest. `--no-cache` bypasses read and write. `--db` supplies an explicit path that is still fingerprint-validated.

### 6. Analyze

Detectors call `add_finding(category, details, score)` into a module-level list. `collapse_findings` then caps high-volume hygiene categories and inserts a summary row for the remainder. Critical path categories are never collapsed.

Scoring is per-detector and additive in spirit: severity reflects blast radius and exploitability. Scores of 9 to 10 are domain compromise paths (DCSync, broad principal ACL on a GPO, privileged roast), 7 to 8 are high-impact but narrower, and lower scores are hygiene.

### 7. Present

The console table prints the top findings, or everything under `--all-findings`. Exports and packs read the same finding list, so console, JSON, SARIF, tickets, and report pack always agree.

---

## Graph and projection

The analysis graph is the source of truth. Task lists need a BloodHound-shaped view, so `build_bloodhound_projection` produces a separate read-only structure.

| Layer | Purpose | Mutated by |
|-------|---------|------------|
| Analysis graph | Detectors, pathfinding, exports | Ingest and post-processing only |
| Projection | Task-list queries | Never mutated |

The projection supplies:

- **Labels**: `User`, `Computer`, `Group`, `Domain`, `OU`, `GPO`, `CertificateTemplate`, `EnterpriseCA`, and the `AZ*` Entra labels.
- **Properties**: lowercased BloodHound names, plus `objectid` materialized from the node key, `highvalue`, `owned`, and `hasspn`.
- **Relationships**: the collector's names, plus BloodHound aliases (`LocalAdmin` also appears as `AdminTo`), derived `DCSync`, and `TrustedBy` split from `TrustedDomain:<dir>:<type>`.

Because the projection is derived, a detector fix never changes what a task list sees, and a task list can never corrupt the analysis graph.

---

## Projection limits

These are known differences from a real BloodHound Neo4j import. They are documented here so a parity question has an answer.

| Area | BloodBash today | BloodHound |
|------|-----------------|------------|
| Edge `isacl` | Not set on ACE edges | `true` on every ACE-derived edge |
| `Contains` | Not emitted from `ChildObjects` | Parent OU -> child object |
| `GPLink` direction | Container -> GPO | GPO -> OU/Domain/Site |
| `IsInherited` | Dropped | Preserved as `isinherited` |
| `lastlogontimestamp` sentinel | Raw collector value (may be `-11644473600`) | Normalized to `-1` |

Impact on real PlumHound lists, measured against a 2,154-user / 3,010-computer collection:

| Cause | Empty tasks |
|-------|-------------|
| `isacl` missing | 17 |
| `Contains` missing | 10 |
| `Owned *` without `--owned` | 20 (expected) |
| Password age window beyond data | 8 (expected) |
| `userpassword` not collected | 4 (expected) |
| `-1` sentinel mismatch | 4 |
| `GPLink` direction | 2 |
| Label predicate unsupported | 2 |

358 of 360 queries in PlumHound's shipped task files execute.

---

## Detector model

Detectors are plain functions over the graph. Each does its own filtering and calls `add_finding`.

| Property | Detail |
|----------|--------|
| Registration | Direct call from the run-mode dispatcher |
| State | Module-level finding list, reset per run |
| Deduplication | Per detector; `_edge_label_exists` and `_add_unique_edge` prevent duplicate edges |
| Output | Score, category, detail string |
| Extension | Plugins receive the same `add_finding` |

Quiet mode (`set_quiet_empty_sections`) suppresses empty sections under `--all` and `--quick-wins`, while selective flags print explicit "none found" lines so a requested check is never silently absent.

---

## Task engine

```text
.tasks file
   |
   v
parse_task_line -> TaskSpec (title, format, filename, query, ok/error)
   |
   v
build_bloodhound_projection (cached per run)
   |
   v
parse_cypher -> tokenize -> clause parser -> ParsedQuery
   |
   v
execute_task_query -> rows
   |
   v
write_task_csv / html / stdout -> index
```

The evaluator is a tree-walking interpreter, not a database planner. It supports the clause set in the [user guide](user-guide.md#task-query-subset) and raises `TaskQueryError` naming the offending clause for anything else. A failed task is recorded in the index and the list continues; `--tasks-strict` turns that into exit 2.

Notable engine details:

- **Number literals** accept scientific notation (`5.184e+6`), which real lists use for time windows.
- **Grouping keys** are made hashable, so `labels(t)` and `collect(x)` can be grouped on while the row keeps the real list value.
- **`datetime()`** with no argument returns the current time, so `datetime().epochSeconds` works in window predicates.

---

## Exports

All exporters read the same finding list and the same graph, so formats cannot drift from each other.

| Exporter | Reads |
|----------|-------|
| Console table | Collapsed findings |
| `--export md/json/html/csv/yaml` | Collapsed plus raw findings |
| `--export sarif` | Collapsed findings, ATT&CK rules |
| `--tickets` | Collapsed findings at or above threshold |
| `--report-pack` | Inventory datasets plus findings |
| `--csv-pack` | Inventory datasets |
| Task lists | Projection |

---

## Testing

| Layer | Location |
|-------|----------|
| Unit and integration | `test_*.py` at repo root |
| Fixtures | `testData/<feature>-tests/` |
| Synthetic lab with ground truth | `testData/synthetic-corp-lab/` |
| Engagement scenario battery | `tools/run_scenario_battery.py` |
| Task-list parity baseline | `tasks/task_parity_baseline.json` |

CI runs the pytest suite on Python 3.9 and 3.11 plus the 20-scenario battery, then reports a `test` status check for branch protection.

See [Deployment](deployment.md#development) for commands.

---

## See also

- [User guide](user-guide.md)
- [Deployment](deployment.md)
- [Glossary](glossary.md)
