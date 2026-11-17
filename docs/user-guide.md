# BloodBash User Guide

**Offline SharpHound and AzureHound analysis for Active Directory and Entra ID.**

**Authorized red team / penetration testing only.** BloodBash reads collector output you already have. It makes no network calls and never contacts a live domain.

**Source of truth:** [docs/user-guide.md](https://github.com/SquidSec/BloodBash/blob/main/docs/user-guide.md) on branch `main`.

| Related | Purpose |
|---------|---------|
| [Docs index](README.md) | Catalog and Diátaxis map |
| [Cookbook](cookbook.md) | Copy-paste recipes |
| [Operator runbook](operator-runbook.md) | Day-2 procedures |
| [Architecture](architecture.md) | How ingest, graph, and projection work |
| [Deployment](deployment.md) | Install and build |
| [Glossary](glossary.md) | Terms |

### What BloodBash does

BloodBash ingests SharpHound (AD) and AzureHound (Entra) JSON, builds an in-memory graph, runs detectors against it, and prints prioritized findings. It needs no Neo4j, no BloodHound install, and no database server.

| Capability | In BloodBash |
|------------|--------------|
| **Ingest** | SharpHound CE and legacy, AzureHound, zips, merged collections |
| **Graph** | NetworkX in memory; SQLite cache keyed by collection fingerprint |
| **Detect** | AD privilege, credentials, ADCS, delegation, GPO, trusts, Azure/Entra |
| **Paths** | Shortest, abuse-weighted, deep, golden path, busiest, path-break |
| **Report** | Console, Markdown, JSON, HTML, CSV, YAML, SARIF, GraphML, DOT |
| **Deliver** | Report pack, CSV pack, tickets, snapshots, zip |
| **Automate** | Profiles, plugins, watch mode, CI gate, baseline diff, Metasploit |

### Concepts primer

| Concept | Why it matters here |
|---------|---------------------|
| SharpHound | SpecterOps AD collector. Produces the `*_users.json`, `*_computers.json`, … files BloodBash reads |
| AzureHound | Entra ID collector. Produces `azurehound_example.json`-style output |
| BloodHound | Graph UI over Neo4j. BloodBash reproduces its labels and edge names without the database |
| ACL edge | A permission relationship (`GenericAll`, `WriteDacl`, …) parsed from a DACL |
| High-value target | A principal whose compromise matters: DA, EA, DCs, builtin Administrators |
| Owned | A principal you already control, supplied with `--owned` |
| Foothold | A principal you just compromised, analyzed with `--from-user` |
| Projection | Read-only BloodHound-shaped view of the graph used by task lists |
| Task list | PlumHound-format file of Cypher queries, one per line |

---

## Table of contents

1. [Overview](#overview)
2. [Install and first run](#install-and-first-run)
3. [Input and ingest](#input-and-ingest)
4. [Run modes](#run-modes)
5. [Quick wins](#quick-wins)
6. [Full analysis](#full-analysis)
7. [AD privilege and abuse checks](#ad-privilege-and-abuse-checks)
8. [Credential checks](#credential-checks)
9. [ADCS](#adcs)
10. [Delegation](#delegation)
11. [GPO checks](#gpo-checks)
12. [Trusts](#trusts)
13. [Sessions and local admin](#sessions-and-local-admin)
14. [Azure and Entra](#azure-and-entra)
15. [High-value targets](#high-value-targets)
16. [Attack paths](#attack-paths)
17. [Compromise dossier](#compromise-dossier)
18. [Owned principals](#owned-principals)
19. [Inspect](#inspect)
20. [Inventory](#inventory)
21. [Report pack](#report-pack)
22. [CSV pack](#csv-pack)
23. [Exports](#exports)
24. [SARIF](#sarif)
25. [Tickets](#tickets)
26. [GraphML and DOT](#graphml-and-dot)
27. [Snapshots and trend](#snapshots-and-trend)
28. [CI gating](#ci-gating)
29. [Suppressions](#suppressions)
30. [Baselines](#baselines)
31. [Explain](#explain)
32. [Profiles](#profiles)
33. [Plugins](#plugins)
34. [Watch mode](#watch-mode)
35. [Graph cache](#graph-cache)
36. [PlumHound task lists](#plumhound-task-lists)
37. [Task query subset](#task-query-subset)
38. [Metasploit module](#metasploit-module)
39. [Finding categories](#finding-categories)
40. [Exit codes](#exit-codes)
41. [CLI reference](#cli-reference)
42. [Troubleshooting](#troubleshooting)
43. [Authorized use reminder](#authorized-use-reminder)

---

## Overview

### What

BloodBash is an offline analyzer for SharpHound and AzureHound collection output. It builds a graph, finds AD and Entra attack paths and misconfigurations, and prints a prioritized findings table. Reports can be exported in eight formats and packaged into client deliverables.

### Why

BloodHound is the reference tool, but it requires Neo4j, an import step, and a running server. On an engagement you often want an answer in seconds from a zip on disk, inside a CI job, or on a host where you cannot stand up a database. BloodBash trades BloodHound's full graph UI for zero infrastructure and scriptable output.

### How

1. Collect with SharpHound or AzureHound on an authorized target.
2. Point BloodBash at the directory or zip.
3. Read the prioritized findings, or export a deliverable.
4. Optionally re-run different checks against the cached graph without re-ingesting.

### Example

```bash
bloodbash SampleSharphoundADData --quick-wins
```

### See also

- [Install and first run](#install-and-first-run)
- [Run modes](#run-modes)
- [Architecture](architecture.md)

---

## Install and first run

### What

Three ways to run: a standalone binary, `pipx`, or a source checkout.

### Why

The binary needs no Python. `pipx` keeps the install isolated. A checkout is what you need for development, plugins, or the test suite.

### How

```bash
# Standalone binary (no Python required)
curl -sL -o bloodbash \
  https://github.com/SquidSec/BloodBash/releases/latest/download/bloodbash-linux-x64
chmod +x bloodbash
./bloodbash DIR

# pipx
pipx install git+https://github.com/SquidSec/BloodBash

# Source checkout
git clone https://github.com/SquidSec/BloodBash.git
cd BloodBash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 BloodBash.py DIR
```

Dependencies are `networkx`, `rich`, `tqdm`, and `pyyaml`. Python 3.9 or newer.

### Example

```bash
bloodbash SampleSharphoundADData
```

With no check flags, a bare directory runs quick-wins triage. Use `--wizard` for an interactive picker on first run.

### Pitfalls

| Symptom | Check |
|---------|-------|
| `ModuleNotFoundError: networkx` | Dependencies are not installed for the interpreter you invoked |
| Binary will not execute | `chmod +x`, and confirm the platform matches (linux-x64, windows-x64) |
| No output at all | The path has no collector JSON; run `--debug` to see what was parsed |

### See also

- [Deployment](deployment.md)
- [Input and ingest](#input-and-ingest)

---

## Input and ingest

### What

BloodBash accepts a directory or a `.zip`. It walks nested folders, reads every collector JSON it recognizes, and merges additional collections with `--merge`.

### Why

Real collections arrive in inconsistent shapes: SharpHound zips unpack into a containing folder, operators unzip into `bloodhound/` subdirectories, and multi-domain engagements need several collections unioned into one graph.

### How

- The positional argument is a directory or zip. It defaults to `.`.
- `--merge PATH...` unions extra directories or zips into the same graph.
- Nested collector folders are walked (bounded depth). Post-collection folders that BloodHound CE writes next to data are skipped.
- Zips are extracted to a temporary directory. Zip Slip paths are rejected.
- Object type is inferred from the filename (`20240101_users.json` becomes users), with SharpHound CE property aliases accepted.

Recognized AD files include `users`, `computers`, `groups`, `gpos`, `ous`, `domains`, `containers`, `certtemplates`, `enterprisecas`, and related CE outputs. AzureHound output is detected by its OData shape.

### Example

```bash
# Directory
bloodbash ./sharpout --quick-wins

# Zip
bloodbash ./2024-collection.zip --all --fast

# Merge a low-priv and a DA collection into one graph
bloodbash ./lowpriv.zip --merge ./da.zip --all --fast

# Multi-domain forest
bloodbash ./forest-root --merge ./child-a.zip ./child-b.zip --quick-wins

# Confirm what is actually in the collection
bloodbash ./sharpout --list-domains
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Zero objects loaded | Path points at a parent folder, or files are not collector JSON |
| Only one domain analyzed | Use `--merge` for the other collections, or `--list-domains` to confirm |
| Domain filter returns nothing | Exit code is 3 and the message lists available domains |
| Collection health says reliability is low | Missing ADCS objects, SID-only principals, or thin session coverage |

### See also

- [Collection health](#collection-health)
- [Graph cache](#graph-cache)
- [Domain filtering](#domain-filtering)

---

## Run modes

### What

Six ways to drive a run: quick-wins (default), full analysis, profiles, selective flags, inventory, and task lists.

### Why

Different jobs need different depth. Day-0 triage wants speed and signal. A deliverable wants every module plus inventory. A targeted question wants one check.

### How

| Mode | Flag | Behaviour |
|------|------|-----------|
| Quick wins | *(default)* or `--quick-wins` | Curated high-signal set, implies `--fast` |
| Full analysis | `--all` | Every AD and Azure module; `--fast` auto-on for large graphs |
| Profile | `--profile NAME` | YAML-defined set of flags |
| Selective | individual flags | Only what you name |
| Inventory | `--inventory` | Structural, password-age, stale, privilege ladders |
| Tasks | `--tasks FILE` | PlumHound-format Cypher lists |

`--wizard` offers an interactive picker. `--verbose` adds a graph summary. `--debug` adds parse and build logging.

### Example

```bash
bloodbash DIR                      # quick wins
bloodbash DIR --all --fast         # full analysis
bloodbash DIR --profile adcs-heavy # profile
bloodbash DIR --dcsync --adcs      # selective
bloodbash DIR --inventory          # ladders
bloodbash DIR --wizard             # interactive
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Run is slow | Add `--fast`; large graphs auto-enable it under `--all` |
| Sections are missing from output | Empty sections are suppressed under `--all` and `--quick-wins`; selective flags print green "none found" lines |
| Want every finding listed | `--all-findings` prints the full table at end of run |

### See also

- [Quick wins](#quick-wins)
- [Full analysis](#full-analysis)
- [Profiles](#profiles)

---

## Quick wins

### What

A curated, high-signal detector set for day-0 triage. It is the default when you pass only a data path, and it implies `--fast`.

### Why

On first contact with a collection you want the findings that change the engagement plan: unexpected DCSync, certificate abuse, roastable privileged accounts, delegation, and the shortest routes to Domain Admin. Not a full inventory.

### How

| Area | Modules |
|------|---------|
| Privilege | DCSync (unexpected), ADCS, dangerous ACLs, interesting non-HV ACLs, RBCD and can-configure, unconstrained (DC vs non-DC), constrained, shadow credentials, LAPS plus readers, trusts |
| Credentials | Kerberoast, AS-REP, privileged roast, password in description, PasswordNotRequired |
| Ops | Sessions and local admin summary, collection health |
| Paths | Shortest paths to high-value targets, busiest short paths, path-break |

Empty sections stay quiet so the console remains readable.

### Example

```bash
bloodbash ./sharpout
bloodbash ./sharpout --quick-wins
bloodbash ./sharpout --quick-wins --domain CORP.LOCAL
bloodbash ./2024-collection.zip --quick-wins
bloodbash ./sharpout --profile quick-wins   # identical set
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Fewer findings than expected | Quick wins is deliberately narrow. Use `--all` |
| Paths section is shallow | `--fast` limits pathfinding; drop it or use `--deep-paths` |
| Want the full collapsed list | Add `--all-findings` |

### See also

- [Full analysis](#full-analysis)
- [Attack paths](#attack-paths)
- [Profiles](#profiles)

---

## Full analysis

### What

`--all` runs every AD and Azure module. `--fast` restricts pathfinding to top DA/EA-style targets and is enabled automatically on large graphs.

### Why

Deliverables and deep reviews need coverage beyond triage: every credential class, delegation variant, GPO risk, trust issue, and path metric.

### How

- `--all` enables all detectors. Empty AD sections are suppressed.
- Inventory modules stay opt-in even under `--all`; add `--inventory`.
- `--fast` limits pathfinding scope. It is not a full skip.
- Azure checks are skipped automatically when the collection has no Entra objects.

### Example

```bash
bloodbash ./sharpout --all
bloodbash ./sharpout --all --fast
bloodbash ./sharpout --all --inventory
bloodbash ./sharpout --all --fast --all-findings
bloodbash ./sharpout --all --fast --csv-pack ./ph-full --export-zip ph-full.zip
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Inventory sections absent | Add `--inventory`; it is not implied by `--all` |
| Azure checks say skipped | The collection is AD-only; that is expected |
| Very long run | Add `--fast`, and rely on the graph cache for repeat runs |

### See also

- [Inventory](#inventory)
- [Graph cache](#graph-cache)

---

## AD privilege and abuse checks

### What

Detectors for privilege escalation through AD permissions and configuration: DCSync rights, dangerous ACLs, broad-principal ACLs, RBCD, delegation, SID history, and GPO abuse.

### Why

These are the misconfigurations that convert a low-privilege foothold into domain compromise. They are also the most common findings in real engagements.

### How

| Flag | Detects |
|------|---------|
| `--dcsync` | Principals holding GetChanges **and** GetChangesAll on a domain, excluding expected DA/EA/DC holders |
| `--dangerous-permissions` | Dangerous rights on high-value objects, non-default principals only |
| `--rbcd` | RBCD configured, plus principals who can configure it via `AllowedToAct` |
| `--unconstrained-delegation` | Unconstrained delegation, split into DC and non-DC sections |
| `--constrained-delegation` | Constrained delegation targets |
| `--shadow-credentials` | `AddKeyCredentialLink` paths |
| `--sid-history` | SID history abuse candidates |
| `--gpo-abuse` | Non-default write rights on GPOs, flagged when linked to sensitive OUs |

DCSync requires both rights on the same target. Nested DA/EA membership is treated as expected and filtered out of the unexpected list. Interesting non-high-value ACL abuse (ForceChangePassword, GenericAll, GenericWrite on users, computers, groups) is reported separately with bulk computer GenericWrite noise suppressed.

### Example

```bash
bloodbash DIR --dcsync --adcs --dangerous-permissions --verbose
bloodbash DIR --rbcd --unconstrained-delegation --constrained-delegation
bloodbash DIR --shadow-credentials --sid-history
bloodbash DIR --gpo-abuse --gpo-content-dir ./sysvol-gpo-xml
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| DCSync section empty but you expect hits | Both rights are required; check for partial replication in the section footer |
| Too many ACL rows | High-volume categories collapse; use `--all-findings` for the rest |
| RBCD can-configure skipped | Can-configure is skipped on large `--all --fast` runs; run `--rbcd` alone or add `--deep-analysis` |

### See also

- [Delegation](#delegation)
- [GPO checks](#gpo-checks)
- [Finding categories](#finding-categories)

---

## Credential checks

### What

Detectors for accounts whose credentials can be obtained offline or guessed: Kerberoastable, AS-REP roastable, privileged roast, passwords in descriptions, and password policy flags.

### Why

Roasting is the fastest path from an unauthenticated or low-privilege position to a usable credential. Password flags and description leaks are cheap wins for both attackers and defenders.

### How

| Flag | Detects |
|------|---------|
| `--kerberoastable` | Users with an SPN (`hasspn` or SPN list) |
| `--as-rep-roastable` | Users with DONT_REQ_PREAUTH |
| `--privileged-roast` | Roastable users nested into DA/EA/other privileged groups, or with AdminCount |
| `--password-descriptions` | Passwords stored in the description field |
| `--password-never-expires` | PasswordNeverExpires users |
| `--password-not-required` | PasswordNotRequired users |

Roast findings carry privilege-context tags: `[AdminCount]`, `[OWNED]`, and `[LASTLOG: …]` buckets. SharpHound's `sensitive` (NOT_DELEGATED) flag does **not** exclude an account from roast candidates.

### Example

```bash
bloodbash DIR --kerberoastable --as-rep-roastable
bloodbash DIR --privileged-roast
bloodbash DIR --password-descriptions --password-never-expires --password-not-required
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| No privileged roast hits | The account must be roastable **and** privileged. Check `--kerberoastable` alone first |
| PNE list is very long | Expected in most environments; the category collapses at 25 rows |

### See also

- [ADCS](#adcs)
- [Inventory](#inventory)
- [Finding categories](#finding-categories)

---

## ADCS

### What

Certificate Services misconfiguration checks: ESC1 through ESC8, plus ESC9 and ESC13 when the collector supplies the needed properties.

### Why

ADCS misconfigurations allow domain escalation by requesting a certificate as another principal. They are frequently the fastest route to Domain Admin and are invisible to ACL-only reviews.

### How

Templates are matched against SpecterOps ESC definitions. ESC10, ESC11, and ESC12 require registry or HTTP role data that SharpHound usually does not collect, so BloodBash reports them as needing additional data rather than guessing.

When the collection contains no certificate objects, the section prints a soft message instead of an empty table.

### Example

```bash
bloodbash DIR --adcs
bloodbash DIR --all --fast
bloodbash DIR --profile adcs-heavy --path-break --busiest-paths short \
  --report-pack ./adcs-paths --export-zip adcs-paths.zip
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| "No ADCS data" message | The collection has no `certtemplates` or `enterprisecas` files |
| ESC8 never fires | Needs the CA's web enrollment role data, which is often absent |
| Reliability ceiling says low | Missing ADCS objects is one of the causes reported by collection health |

### See also

- [Collection health](#collection-health)
- [Profiles](#profiles)

---

## Delegation

### What

Checks for Kerberos delegation abuse: unconstrained, constrained, and resource-based constrained delegation.

### Why

Unconstrained delegation lets a compromised host capture any authenticating user's TGT, including domain controllers. Constrained and RBCD allow impersonation against named services. All three turn a single host or account into lateral movement.

### How

| Flag | Reports |
|------|---------|
| `--unconstrained-delegation` | Hosts with unconstrained delegation, split DC vs non-DC |
| `--constrained-delegation` | Accounts with `allowedtodelegate` targets |
| `--rbcd` | Configured RBCD, plus principals who can configure it (`AllowedToAct`) |

DC vs non-DC matters: domain controllers legitimately hold unconstrained delegation, so listing them as findings is noise.

### Example

```bash
bloodbash DIR --unconstrained-delegation
bloodbash DIR --constrained-delegation
bloodbash DIR --rbcd
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Constrained delegation empty | The collector must emit `allowedtodelegate`; many default runs do not |
| All DCs listed | DCs are separated into their own section by design |
| Can-configure missing | Skipped on large `--all --fast` runs; run `--rbcd` alone |

### See also

- [AD privilege and abuse checks](#ad-privilege-and-abuse-checks)
- [Finding categories](#finding-categories)

---

## GPO checks

### What

Group Policy abuse detection from ACLs, and optional content parsing from exported GPO XML.

### Why

Write access to a linked GPO is code execution on every machine in scope. GPO Preferences files can also contain `cPassword` values, which are decryptable with a published key.

### How

- `--gpo-abuse` finds non-default principals with write rights on GPOs, flagged when the GPO is linked to a sensitive OU.
- `--gpo-parsing` analyzes GPO metadata.
- `--gpo-content-dir DIR` parses exported GPO XML for scheduled tasks, scripts, and `cPassword`.

### Example

```bash
bloodbash DIR --gpo-abuse
bloodbash DIR --gpo-parsing
bloodbash DIR --gpo-abuse --gpo-content-dir ./sysvol-gpo-xml
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Content section empty | `--gpo-content-dir` must point at exported XML, not the collector JSON |
| Only one GPO flagged | Correct when only one has non-default write rights; check `--all-findings` |

### See also

- [AD privilege and abuse checks](#ad-privilege-and-abuse-checks)
- [Finding categories](#finding-categories)

---

## Trusts

### What

Domain trust analysis: trust direction, transitivity, and SID filtering state.

### Why

A trust with SID filtering disabled allows SID history injection across the boundary. Forest trusts and bidirectional trusts expand the blast radius of a single compromised domain.

### How

`--trust` reports trust relationships and flags SID-filtering abuse candidates. Trusts are read from the domain object's `Trusts[]` array and projected as `TrustedBy` edges for task lists.

### Example

```bash
bloodbash DIR --trust
bloodbash DIR --all --trust
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| No trusts reported | Single-domain collection with no trust data collected |

### See also

- [High-value targets](#high-value-targets)
- [Task lists](#plumhound-task-lists)

---

## Sessions and local admin

### What

Session, local admin, RDP, and DCOM summaries, plus collection health metrics for session coverage.

### Why

Session data shows where privileged credentials are exposed. Local admin rights show lateral movement potential. Coverage metrics tell you whether absence of findings means clean or means uncollected.

### How

`--sessions` prints HasSession, AdminTo/LocalAdmin, CanRDP, and ExecuteDCOM summaries. The collection health banner always reports edge counts for these categories so you can judge reliability.

### Example

```bash
bloodbash DIR --sessions
bloodbash DIR --sessions --verbose
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Session counts look low | Default SharpHound sessions are limited; check the collection health banner |
| No CanRDP edges | Some collectors skip RDP rights unless requested |

### See also

- [Collection health](#collection-health)
- [Compromise dossier](#compromise-dossier)

---

## Azure and Entra

### What

Entra ID checks: privileged roles, app and service principal credential control, MFA disable, guest access, and service principal abuse rights.

### Why

Entra misconfigurations grant cloud control without touching AD. A service principal with credential-add rights can be escalated to persistent access, and a guest with a privileged role bypasses assumptions about tenant boundaries.

### How

| Flag | Detects |
|------|---------|
| `--azure-privileged-roles` | Principals holding privileged directory roles |
| `--azure-app-secrets` | App/SP credential control paths |
| `--azure-mfa-bypass` | Explicit MFA disable signals |
| `--azure-guest-access` | Guest users |
| `--azure-sp-abuse` | Service principal abuse rights |

Azure checks are skipped automatically when the collection has no Entra objects.

### Example

```bash
bloodbash ./azureout --azure-privileged-roles
bloodbash ./azureout --azure-app-secrets --azure-sp-abuse
bloodbash ./azureout --azure-mfa-bypass --azure-guest-access
bloodbash SampleAzurehoundData --azure-privileged-roles --azure-guest-access --all-findings
bloodbash ./azureout --azure-privileged-roles --domain <tenantId>
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| "No Azure/Entra objects" | The collection is AD-only; point at AzureHound output |
| Tenant filter matches nothing | Use the tenant ID shown by `--list-domains` |

### See also

- [Input and ingest](#input-and-ingest)
- [Domain filtering](#domain-filtering)

---

## High-value targets

### What

The set of principals whose compromise matters, used as pathfinding targets and for scoring.

### Why

Pathfinding is only as useful as its targets. Including DC computers and builtin Administrators catches routes that a naive "Domain Admins only" query misses, while excluding workstation local-admin groups prevents flooding.

### How

The high-value set includes Domain Admins, Enterprise Admins, builtin Administrators, domain controller computers, and classic high-value names. Workstation `highvalue` flags on local admin groups are excluded. `--domain` narrows the set to one domain.

### Example

```bash
bloodbash DIR --all --fast
bloodbash DIR --report-pack ./reports   # high_value.html lists the set
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Fewer targets than expected | Some are filtered by design; inspect `high_value.html` |
| Workstations treated as high value | That would indicate a naming collision; report it |

### See also

- [Attack paths](#attack-paths)
- [Finding categories](#finding-categories)

---

## Attack paths

### What

Graph pathfinding toward high-value targets, with several modes and two remediation views.

### Why

A finding tells you a misconfiguration exists. A path tells you whether it reaches Domain Admin, and in how many hops. Remediation views tell you which single edge removal breaks the most paths.

### How

| Flag | Purpose |
|------|---------|
| `--shortest-paths` | Paths to high-value targets |
| `--path-mode short\|abuse\|deep` | Edge weighting. `abuse` prefers FCP/AdminTo/session/ACL over pure MemberOf |
| `--path-depth N` | Hop limit |
| `--path-sources N` | Source principal cap |
| `--max-paths N` | Paths per target |
| `--indirect` | Include group-mediated paths |
| `--deep-paths` | Deeper hops, alternate paths, stepping stones |
| `--no-stepping-stones` | Suppress stepping-stone reporting |
| `--golden-path` | One path to Domain Admins, rendered as a panel, exit 1 if none |
| `--path-from` / `--path-to` | Arbitrary source to target |
| `--busiest-paths short\|all` | Rank principals on the most paths |
| `--path-break` | Edges to remove to break the most paths |

### Example

```bash
bloodbash DIR --shortest-paths
bloodbash DIR --shortest-paths --indirect --fast
bloodbash DIR --shortest-paths --path-mode abuse
bloodbash DIR --deep-paths
bloodbash DIR --path-mode deep --path-depth 16 --path-sources 400 --max-paths 20
bloodbash DIR --golden-path
bloodbash DIR --golden-path --from-user alice --domain CORP.LOCAL
bloodbash DIR --busiest-paths short --busiest-paths-top 10
bloodbash DIR --path-break --path-break-top 20
bloodbash DIR --path-from helpdesk --path-to 'domain admins@corp.local'
bloodbash DIR --path-from alice,bob --path-to 'domain admins,enterprise admins'
```

`--golden-path` prints a single path with a copy-paste line and exits 1 when there is no path, so the exit status is what scripts should branch on:

```bash
if bloodbash DIR --golden-path > /dev/null; then echo "path exists"; fi
```

Output looks like this:

```text
[FOOTHOLD]  svc_sql@CORP.LOCAL (User)
            |  GenericWrite
[  hop   ]  HELP DESK ADMINS@CORP.LOCAL (Group)
            |  GenericWrite
[JACKPOT ]  WORKSTATION BASELINE GPO@CORP.LOCAL (GPO)
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| "No path" for a principal that should reach DA | Check the hop limit, and whether `--fast` narrowed the target set |
| Ambiguous name error | The SAM exists in more than one domain; qualify it as `user@domain` or add `--domain` |
| Paths all look like MemberOf chains | Use `--path-mode abuse` to prefer exploitable edges |

### See also

- [High-value targets](#high-value-targets)
- [Domain filtering](#domain-filtering)
- [Compromise dossier](#compromise-dossier)

---

## Compromise dossier

### What

An outbound report for a principal you just compromised: what groups they are in, what they can reach, and what paths lead to high-value targets.

### Why

Immediately after landing a foothold, the question is "what can this principal do right now?" A dossier answers it in one command and exports a shareable set of lists.

### How

| Flag | Meaning |
|------|---------|
| `--from-user` / `--compromise USER` | Build the dossier. Comma-separated for several |
| `--from-user-file FILE` | Line-delimited footholds, merges with `--from-user` |
| `--from-user-export [DIR]` | Write txt, csv, json, and a `summary.md` |
| `--writable-file FILE` | Import bloodyAD `get writable` JSON, JSONL, or TSV |
| `--writable-all` | Include imported writes that already exist as SharpHound edges |

The dossier covers direct and effective membership, AdminTo/RDP/ACL counts, nested groups, automatic paths to high-value targets, and a bulk AdminTo host list.

Name matching rules apply to `--from-user`, `--owned`, `--path-from`, `--path-to`, `--inspect`, and `--golden-path`:

| You pass | What it matches |
|----------|-----------------|
| `alice` | That SAM in one domain. With `--domain`, only that domain. If the SAM exists in more than one domain, BloodBash lists the hits and stops |
| `alice@corp.local` or `CORP\alice` | That domain only. Also matches `userPrincipalName` and the domain in the distinguished name |
| object id | That node, exact |

### Example

```bash
bloodbash DIR --from-user alice
bloodbash DIR --compromise alice@corp.local
bloodbash DIR --from-user alice --from-user-export
bloodbash DIR --from-user alice --writable-file ./alice-writable.json
bloodbash DIR --from-user alice --from-user-export ./alice-dossier
bloodbash DIR --from-user alice,bob,svc_backup --from-user-export ./footholds
bloodbash DIR --from-user-file ./footholds.txt --from-user-export ./out
bloodbash DIR --from-user svc_sql --from-user-export ./svc-dossier --fast
```

Export layout per principal:

```text
compromise-alice/
  summary.md              README.txt           counts.csv
  membership_direct.txt   membership_effective.txt
  adminto_hosts.txt       adminto_hosts.csv
  paths_to_high_value.txt paths_to_high_value.csv
  dossier.json
  rights/
    AdminTo.txt  AdminTo.csv  CanRDP.txt  LocalAdmin.txt  GenericAll.txt  ...
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| "Found in multiple domains" | Qualify with `user@domain` or add `--domain` |
| Dossier is thin | SharpHound maps only a filtered ACE set; import live rights with `--writable-file` |
| Exports land in an unexpected place | With no DIR, the default is `compromise-<user>/` in the current directory |

### See also

- [Owned principals](#owned-principals)
- [Attack paths](#attack-paths)
- [Name matching](#name-matching)

---

## Owned principals

### What

The inbound view: given principals you control, find who can reach them and what they expose.

### Why

`--from-user` asks what your foothold can do. `--owned` asks the reverse, which is what you want when protecting loot or checking whether a compromised service account is reachable from elsewhere.

### How

| Flag | Meaning |
|------|---------|
| `--owned a,b` | Paths **to** these principals (inbound) |
| `--owned-file FILE` | Same, from a line-delimited file; `#` comments allowed |
| `--owned-inventory` | AdminTo and MemberOf inventory for the owned set |

`--owned` and `--owned-file` merge.

### Example

```bash
bloodbash DIR --owned alice --owned-inventory --shortest-paths
bloodbash DIR --owned-file ./owned.txt --owned-inventory
bloodbash DIR --owned alice --owned-file ./more-owned.txt
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Owned rows are empty in task lists | The `owned` property is only set when `--owned` is supplied to the run |

### See also

- [Compromise dossier](#compromise-dossier)
- [Task query subset](#task-query-subset)

---

## Inspect

### What

Dump every property and edge for one node.

### Why

When a finding references a principal, you want its raw data and relationships without opening a graph database.

### How

`--inspect NODE` prints properties and edges. It uses the same name matching rules as `--from-user`.

### Example

```bash
bloodbash DIR --inspect alice
bloodbash DIR --inspect 'DOMAIN ADMINS@CORP.LOCAL'
bloodbash DIR --from-user alice --inspect alice
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Node not found | Qualify the domain, or check `--list-domains` |

### See also

- [Name matching](#name-matching)

---

## Inventory

### What

Opt-in inventory ladders: password age, stale accounts, privileged group membership, structural objects, and owned-object inventory.

### Why

Hygiene findings are long lists. Ladders turn them into distributions you can put in a report, and structural inventory documents what the collection actually contains.

### How

| Flag | Produces |
|------|----------|
| `--inventory` | All of the below |
| `--password-age` | Password age buckets |
| `--stale-accounts` | Inactivity buckets |
| `--privilege-inventory` | Privileged group membership |
| `--owned-inventory` | AdminTo and MemberOf for owned principals |

A statistics dashboard with percentages prints under `--all` regardless of inventory flags.

### Example

```bash
bloodbash DIR --inventory
bloodbash DIR --stale-accounts --password-age --privilege-inventory
bloodbash DIR --owned alice --owned-inventory
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Ladders are empty | The collection may lack `pwdlastset` or `lastlogontimestamp` values |
| Buckets look off by years | Collector timestamps may use the FILETIME sentinel; see [Timestamps](#timestamps) |

### See also

- [Report pack](#report-pack)
- [Timestamps](#timestamps)

---

## Report pack

### What

A multi-page HTML site plus per-section CSVs and an `index.html`.

### Why

A single findings table is not a deliverable. A pack gives a client a navigable set of pages with matching data files, plus a manifest describing what was produced.

### How

`--report-pack DIR` writes:

```text
DIR/
  index.html
  findings.html        csv/findings.csv
  high_value.html      csv/high_value.csv
  password_age.html    csv/password_age.csv
  stale_accounts.html  csv/stale_accounts.csv
  privilege_inventory.html  csv/privilege_inventory.csv
  structural.html      csv/domains.csv
  owned_inventory.html csv/owned_inventory.csv
  busiest_paths.html   csv/busiest_paths.csv
  path_breaks.html     csv/path_breaks.csv
  manifest.json
```

Pages are self-contained with inline CSS and a sortable-table script. `--export-zip [FILE]` zips the pack.

### Example

```bash
bloodbash DIR --inventory --busiest-paths short --path-break \
  --report-pack ./reports --export-zip bloodbash-reports.zip --log-file ./bloodbash.log

bloodbash DIR --all --fast --all-findings \
  --report-pack ./nightly --export-zip nightly.zip --log-file nightly.log
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Some pages are missing | Pages with no data are still written; check `manifest.json` |
| Zip is empty | `--export-zip` needs a pack or CSV pack in the same run |

### See also

- [CSV pack](#csv-pack)
- [Exports](#exports)

---

## CSV pack

### What

A PlumHound-style multi-CSV inventory with an index, no HTML.

### Why

Spreadsheet-driven workflows and PlumHound migrations expect one CSV per report. This produces the same shape BloodBash's task lists emit.

### How

`--csv-pack DIR` writes one CSV per dataset plus `index.csv` and `README.txt`.

| CSV | Contents |
|-----|----------|
| `domains.csv` | AD domains |
| `domain_admins.csv` | Principals nested into DA/EA-style groups |
| `users.csv` / `computers.csv` / `groups.csv` | Core inventory |
| `kerberoastable.csv` / `asrep_roastable.csv` | Roast candidates with tags |
| `password_never_expires.csv` | PNE users |
| `laps_not_enabled.csv` | Computers without LAPS |
| `local_admins_users.csv` | User/group to computer AdminTo |
| `user_sessions.csv` | Computer to user sessions |
| `relationships_everyone.csv` and siblings | Edges from over-broad principals |
| `overprivileged_relationships.csv` | Combined over-broad edges |
| `computer_adminto_computer.csv` | Machine to machine AdminTo |
| `dual_privileged_and_local_admin.csv` | DA/EA members with AdminTo |
| `bulk_adminto_hosts.csv` | Principals ranked by AdminTo host count |
| `index.csv` | File to row count |

CSV cells are sanitized against spreadsheet formula injection.

### Example

```bash
bloodbash DIR --csv-pack ./ph-reports
bloodbash DIR --csv-pack ./ph-reports --export-zip ph-reports.zip
bloodbash DIR --all --fast --csv-pack ./ph-full --export-zip ph-full.zip
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| A CSV is header-only | That dataset is genuinely empty for this collection |
| Opening CSV in Excel mangles leading `=` | Sanitization prefixes such cells; use the file as generated |

### See also

- [Report pack](#report-pack)
- [PlumHound task lists](#plumhound-task-lists)

---

## Exports

### What

Single-file exports of high-value targets and prioritized findings.

### Why

Different consumers need different formats: Markdown for tickets, JSON for automation, HTML for sharing, CSV for spreadsheets, YAML for config-like review.

### How

| Flag | Output |
|------|--------|
| `--export md\|json\|html\|csv\|yaml` | Findings and HV targets |
| `--export-bh` | BloodHound-compatible graph JSON |
| `--export sarif` | SARIF 2.1.0 with ATT&CK taxa |
| `--dot [FILE]` | Graphviz DOT |
| `--graphml FILE` | GraphML for Gephi and yEd |

`--export` with no value defaults to `md`.

### Example

```bash
bloodbash DIR --all --export=md
bloodbash DIR --all --export=html
bloodbash DIR --all --export=csv
bloodbash DIR --all --export=json --export-bh --dot graph.dot
bloodbash DIR --all --export=yaml
bloodbash DIR --all --graphml graph.graphml
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| `--export` writes to an unexpected name | Output uses a `bloodbash.<ext>` prefix; pass `--domain` to scope it |
| JSON is huge | Use `--baseline` or `--fail-on-severity` for automation instead of full JSON |

### See also

- [SARIF](#sarif)
- [GraphML and DOT](#graphml-and-dot)
- [Baselines](#baselines)

---

## SARIF

### What

SARIF 2.1.0 output with MITRE ATT&CK taxa, for GitHub code scanning and DefectDojo.

### Why

Security teams already run SARIF consumers. Emitting SARIF lets BloodBash findings land in the same pipeline as code findings, with ATT&CK context attached.

### How

`--export sarif` writes one rule per finding category, one result per finding, with severity mapped from score and ATT&CK technique IDs as taxa and tags.

### Example

```bash
bloodbash DIR --all --export sarif
bloodbash DIR --all --export sarif --fail-on-severity 8
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Code scanning shows no rules | Confirm the workflow uploads the SARIF file and the path matches |
| Severity looks wrong | SARIF severity is derived from the numeric score |

### See also

- [CI gating](#ci-gating)
- [Finding categories](#finding-categories)

---

## Tickets

### What

One Markdown ticket per finding at or above a score threshold.

### Why

Remediation work needs per-item tracking. Tickets drop straight into Jira, GitHub Issues, or a shared folder with ATT&CK context and matching graph edges.

### How

`--tickets DIR` writes one `.md` per finding at or above `--ticket-min-score` (default 8).

### Example

```bash
bloodbash DIR --all --tickets ./tickets
bloodbash DIR --all --tickets ./tickets --ticket-min-score 6
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Few tickets | The threshold is 8 by default; lower it explicitly |
| Duplicate-looking tickets | Slugs are de-duplicated from category plus detail |

### See also

- [Explain](#explain)
- [Finding categories](#finding-categories)

---

## GraphML and DOT

### What

Graph exports for external visualization: GraphML for Gephi and yEd, DOT for Graphviz.

### Why

Some findings are easier to explain visually. Exporting the key subgraph lets an analyst draw the attack path in a tool the client already understands.

### How

`--graphml FILE` writes GraphML. `--dot [FILE]` writes DOT, defaulting to `bloodbash.dot`.

### Example

```bash
bloodbash DIR --all --graphml graph.graphml
bloodbash DIR --all --dot graph.dot
dot -Tpng graph.dot -o graph.png
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Graph is unreadable | Both exports are filtered to the key subgraph; use `--domain` to narrow further |

### See also

- [Exports](#exports)

---

## Snapshots and trend

### What

Save findings snapshots and compare the two most recent.

### Why

Recurring assessments need to show movement. A trend view answers "did last month's remediation work?" without re-reading two full reports.

### How

`--snapshot` saves a snapshot under `~/.cache/bloodbash/snapshots`. `--trend` compares the latest two and prints what appeared and what resolved.

### Example

```bash
bloodbash DIR --all --snapshot
# ... later, after remediation ...
bloodbash DIR --all --snapshot --trend
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Trend says it needs two snapshots | Run `--snapshot` at least twice |
| Snapshots in the wrong place | Override with `--cache-dir` |

### See also

- [Baselines](#baselines)
- [Graph cache](#graph-cache)

---

## CI gating

### What

`--fail-on-severity N` exits non-zero when any reported finding scores at or above N.

### Why

Turn BloodBash into a regression gate: accept known debt, fail only on new or worsened findings.

### How

- Exit code is `2` when the threshold is met.
- Suppressed rows and baseline-matched rows do not count.
- Combine with `--baseline` and `--suppress` to gate only on regressions.

### Example

```bash
# Fail the build on anything 8 or above
bloodbash DIR --all --fast --fail-on-severity 8

# Save a baseline, then gate only on new findings
bloodbash DIR --all --export json
bloodbash DIR --all --baseline baseline.json --fail-on-severity 8
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Gate passes when it should fail | Confirm the score threshold and that the finding is not suppressed |
| Gate fails on known debt | Add a baseline or suppression entry |

### See also

- [Baselines](#baselines)
- [Suppressions](#suppressions)
- [Exit codes](#exit-codes)

---

## Suppressions

### What

A YAML allowlist that hides accepted findings, optionally until an expiry date.

### Why

Known, accepted risk should not keep failing a gate. An expiry date forces re-review instead of permanent silence.

### How

```yaml
suppressions:
  - category: Kerberoastable
    contains: SVC_SQL
    expires: 2026-12-31
```

`--suppress FILE` applies it. Matching is by category plus a substring of the detail text.

### Example

```bash
bloodbash DIR --all --suppress suppressions.yaml
bloodbash DIR --all --suppress suppressions.yaml --fail-on-severity 8
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Expired entry still suppresses | Expiry is compared to the current date; check the format is `YYYY-MM-DD` |
| Everything suppressed | `contains` is a substring match; a short value matches widely |

### See also

- [CI gating](#ci-gating)
- [Baselines](#baselines)

---

## Baselines

### What

Diff a run against a previous JSON export and report new versus resolved findings.

### Why

A raw findings list mixes old and new. A baseline diff answers the question a retest actually asks: what changed since last time?

### How

`--baseline REPORT.json` reads a prior `--export json`, prints new and resolved findings, and hides known rows from the gate.

### Example

```bash
bloodbash DIR --all --export json          # save this as baseline.json
bloodbash DIR --all --baseline baseline.json --fail-on-severity 8
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Diff is empty | The two runs may be against different collections or domains |
| Baseline file rejected | It must be a BloodBash JSON export, not an arbitrary JSON file |

### See also

- [CI gating](#ci-gating)
- [Snapshots and trend](#snapshots-and-trend)

---

## Explain

### What

Show why a finding fired: the rows behind it, its ATT&CK technique, and the matching graph edges.

### Why

Findings are summaries. When a client disputes one, you need the underlying data and the exact edges that produced it.

### How

`--explain CATEGORY` or `--explain N` prints the contributing rows, the ATT&CK id, and matching edges.

### Example

```bash
bloodbash DIR --all --explain DCSync
bloodbash DIR --all --explain Kerberoastable
bloodbash DIR --all --explain 12
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Category not found | Category names are case-sensitive; see [Finding categories](#finding-categories) |

### See also

- [Finding categories](#finding-categories)

---

## Profiles

### What

YAML files that bundle flags into a named run mode.

### Why

Engagements repeat. A profile makes a standard run one flag, and keeps team members running the same set.

### How

Built-in profiles live in `profiles/`:

| Profile | Purpose |
|---------|---------|
| `quick` | Fast critical checks, inventory ladders, path remediation hints |
| `quick-wins` | Same set as `--quick-wins` |
| `adcs-heavy` | ADCS, privilege paths, inventory for certificate reviews |
| `hygiene` | Password age, stale accounts, roastables, never-expires |

A profile is a YAML map of CLI option names:

```yaml
name: my-engagement
description: Client-specific review
all: false
fast: true
verbose: true
checks:
  - dcsync
  - adcs
busiest_paths: short
path_break_top: 10
export: html
report_pack: bloodbash-report-pack
```

Keys map to flag names with `--` removed and `-` replaced by `_` (`path_break_top` is `--path-break-top`). `checks` is a list of check names without the leading `--`.

### Example

```bash
bloodbash DIR --profile quick
bloodbash DIR --profile quick-wins
bloodbash DIR --profile adcs-heavy
bloodbash DIR --profile hygiene
bloodbash DIR --profile ./my-engagement.yaml
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Unknown profile | Use a built-in name or a path that exists |
| Profile flags ignored | Explicit CLI flags override profile values |

### See also

- [Run modes](#run-modes)

---

## Plugins

### What

Load custom detector modules from a directory.

### Why

Site-specific checks should not require forking BloodBash.

### How

Every `*.py` in `--plugins-dir DIR` that exposes `run(G, add_finding)` is loaded and executed after built-in detectors. Files starting with `_` are skipped.

```python
# ./detectors/password_policy.py
def run(G, add_finding):
    for _, d in G.nodes(data=True):
        if (d.get("type") or "").lower() != "user":
            continue
        if (d.get("props") or {}).get("minpwdlength") == 0:
            add_finding("Policy Check", f"{d.get('name')} has no minimum password length", score=6)
    return 1
```

`add_finding(category, details, score)` is the same function used internally. Return the number of findings added.

### Example

```bash
bloodbash DIR --all --plugins-dir ./detectors
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Plugin skipped silently | It raised on import or has no `run`; the reason prints in yellow |
| Plugin findings missing from the gate | Plugins run before gating, so they are included; check the score |

### See also

- [Finding categories](#finding-categories)

---

## Watch mode

### What

Re-run analysis when collector files change.

### Why

During a long collection you can leave BloodBash running and get updated findings as new data lands.

### How

`--watch [DIR]` polls inputs every `--watch-interval` seconds (default 5). Ctrl-C stops it.

### Example

```bash
bloodbash DIR --watch
bloodbash DIR --watch --watch-interval 30
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Never re-runs | The file signature did not change; confirm the collector is writing into the watched path |
| High CPU | Raise `--watch-interval` |

### See also

- [Graph cache](#graph-cache)

---

## Graph cache

### What

An automatic SQLite cache of the built graph, keyed by a fingerprint of the collection files.

### Why

Ingest is the slow part. Re-running a different check should not re-parse a large collection.

### How

- First run ingests and writes `~/.cache/bloodbash/graph-<fingerprint>.db`.
- Later runs with the same source files load the cache and skip ingest.
- The fingerprint covers file paths, sizes, and modification times.
- `--rebuild-cache` forces re-ingest. `--no-cache` disables read and write.
- `--cache-dir DIR` relocates the cache. `--db FILE` uses an explicit SQLite path, still fingerprint-validated.

### Example

```bash
bloodbash DIR --dcsync              # builds and caches
bloodbash DIR --kerberoastable      # cache hit, only this check runs
bloodbash DIR --all --rebuild-cache # force re-ingest
bloodbash DIR --all --no-cache      # disable cache
bloodbash DIR --all --cache-dir /tmp/bb-cache
bloodbash DIR --all --db bloodbash.db
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Stale results after a new collection | Run `--rebuild-cache` |
| Cache misses every time | File mtimes change; the fingerprint includes them |
| Disk filling up | Old fingerprint databases accumulate; prune `~/.cache/bloodbash/` |

### See also

- [Snapshots and trend](#snapshots-and-trend)
- [Architecture](architecture.md)

---

## PlumHound task lists

### What

Read PlumHound `.tasks` files and run them without Neo4j or a BloodHound install.

### Why

PlumHound lists are widely shared and encode institutional knowledge. BloodBash runs them directly against its own graph.

### How

Each line is a four-element Python list literal:

```text
["Domains", "HTMLCSV", "Domains", "MATCH (n:Domain) RETURN n.name AS Domain"]
["Index", "HTML", "index", "REPORT-INDEX"]
```

| Field | Meaning |
|-------|---------|
| 1 | Report title |
| 2 | Format: `CSV`, `HTML`, `HTMLCSV`, `STDOUT`, `ZIP` |
| 3 | Output filename (extension added from the format when missing) |
| 4 | Query, or the `REPORT-INDEX` / `ZIP-TASKS` sentinel |

Blank lines and lines starting with `#` or `//` are ignored. The `HTLMCSV` typo found in some lists is accepted.

| Flag | Purpose |
|------|---------|
| `--tasks FILE...` | Run one or more lists |
| `--tasks-out DIR` | Output directory (default `task-reports/`) |
| `--tasks-format FMT` | Force one format for every task |
| `--tasks-strict` | Exit 2 when any task fails |
| `--tasks-validate FILE...` | Parse and list without running; exit 0 clean, 2 on errors |
| `--tasks-list` | List the example lists shipped in `tasks/` |

### Example

```bash
bloodbash --tasks-validate ./my-list.tasks
bloodbash --tasks-validate tasks/core.tasks tasks/azure.tasks
bloodbash DIR --tasks ./my-list.tasks
bloodbash DIR --tasks ./my-list.tasks --tasks-out ./task-reports
bloodbash DIR --tasks a.tasks b.tasks --tasks-out ./task-reports
bloodbash DIR --tasks ./my-list.tasks --tasks-out ./task-reports --export-zip tasks.zip
bloodbash DIR --tasks ./my-list.tasks --tasks-format CSV
bloodbash DIR --tasks ./my-list.tasks --tasks-strict
bloodbash DIR --all --fast --tasks ./my-list.tasks
bloodbash --tasks-list
```

Output layout:

```text
reports/
  index.csv        # title, format, row count, status, files, query
  index.html       # same, with links
  Domains.csv
  Domains.html
  pack.zip         # only when the list contains ZIP-TASKS
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Task reports zero rows | The query ran and matched nothing; check projection properties first |
| Task reports an error | The index records the error per task and the rest of the list continues |
| Filenames look mangled | Directory traversal and shell-unsafe characters are stripped by design |

### See also

- [Task query subset](#task-query-subset)
- [CSV pack](#csv-pack)
- [Projection limits](architecture.md#projection-limits)

---

## Task query subset

### What

The read-only Cypher subset BloodBash evaluates for task lists.

### Why

Task lists assume a Neo4j server. BloodBash implements enough of Cypher to run real lists natively, and rejects the rest with the offending clause named.

### How

| Area | Supported |
|------|-----------|
| Clauses | `MATCH`, `OPTIONAL MATCH`, `WHERE`, `WITH`, `RETURN`, `ORDER BY`, `LIMIT`, `UNWIND`, `UNION`, `UNION ALL` |
| Patterns | Single and multi-pattern, `,` joins, directed and undirected, relationship alternation `[:A\|B]`, variable length `*n..m`, property maps `{a: b}`, inline `WHERE` in a node pattern, `p =` path variables |
| Paths | `shortestPath((a)-[*..]->(b))` and `allShortestPaths(...)`, capped at 10 hops |
| Predicates | `=`, `<>`, `<`, `<=`, `>`, `>=`, `CONTAINS`, `STARTS WITH`, `ENDS WITH`, `IN`, `=~`, `IS [NOT] NULL`, `AND`, `OR`, `NOT`, `ANY`/`ALL`/`NONE`/`SINGLE`, `EXISTS(pattern)` |
| Aggregates | `count`, `count(DISTINCT …)`, `collect`, `sum`, `avg`, `min`, `max`, implicit grouping |
| Functions | `labels`, `type`, `head`, `last`, `size`, `length`, `keys`, `properties`, `toUpper`, `toLower`, `toInteger`, `toFloat`, `toString`, `coalesce`, `datetime({epochSeconds})`, `timestamp`, `range`, list indexing `x[0]` |

Number literals accept scientific notation (`5.184e+6`), which real task lists use for time windows.

Rejected by design:

- Write clauses (`CREATE`, `MERGE`, `SET`, `DELETE`, `REMOVE`). BloodBash only reads a collection.
- `CALL` and `LOAD CSV`. There is no procedure surface.
- `apoc.*`, `duration.*`, `split()`, `CASE`, map projection, list comprehensions, `reduce()`. These fail that one task with the clause named.

### Example

```text
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512'
RETURN DISTINCT u.name AS User
ORDER BY User
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| `expected ')', found ':'` | Label predicates such as `(u:User OR u:AZUser)` are unsupported |
| `unhashable type: 'list'` | Grouping on a list-valued column (`labels(t)`, `collect(x)`) crashed before this fix; rebuild from a checkout or a build that includes it |
| `datetime().epochSeconds` is null | `datetime()` with no argument returned a null value before this fix, breaking time-window predicates |

### See also

- [PlumHound task lists](#plumhound-task-lists)
- [Projection limits](architecture.md#projection-limits)

---

## Metasploit module

### What

A Metasploit auxiliary module that wraps the BloodBash CLI and reports findings into the Metasploit database.

### Why

Red teams already work inside `msfconsole`. This keeps BloodBash results in the same workflow and loot database.

### How

```bash
cp modules/auxiliary/analyzer/bloodbash_analyzer.rb \
  /opt/metasploit-framework/modules/auxiliary/analyzer/
# then in msfconsole: reload_all
```

```text
use auxiliary/analyzer/bloodbash_analyzer
set BLOODBASH_PATH /path/to/BloodBash/BloodBash.py
set JSON_DIR /path/to/collector_json_or.zip
set ALL_CHECKS true
run
```

Core options: `BLOODBASH_PATH`, `JSON_DIR`, `PYTHON`, `ALL_CHECKS`, `PROFILE`, `VERBOSE`, `FAST`, `DEBUG`, `ALL_FINDINGS`, `LOG_FILE`.

Check options mirror the CLI: `DCSYNC`, `ADCS`, `RBCD`, `SESSIONS`, `KERBEROASTABLE`, `AS_REP_ROASTABLE`, `SHADOW_CREDENTIALS`, `LAPS`, `GPO_ABUSE`, `SID_HISTORY`, `UNCONSTRAINED_DELEGATION`, `CONSTRAINED_DELEGATION`, `DANGEROUS_PERMISSIONS`, and the `AZURE_*` set.

Path and inventory options: `SHORTEST_PATHS`, `INDIRECT`, `DEEP_ANALYSIS`, `BUSIEST_PATHS`, `BUSIEST_PATHS_TOP`, `PATH_BREAK`, `PATH_BREAK_TOP`, `OWNED`, `FROM_USER`, `FROM_USER_EXPORT`, `PATH_FROM`, `PATH_TO`, `INSPECT`, `INVENTORY`, `PASSWORD_AGE`, `STALE_ACCOUNTS`, `PRIVILEGE_INVENTORY`, `OWNED_INVENTORY`.

Output options: `EXPORT`, `EXPORT_BH`, `DOT`, `REPORT_PACK`, `TASKS`, `TASKS_OUT`, `TASKS_FORMAT`, `TASKS_STRICT`, `EXPORT_ZIP`.

### Example

```text
use auxiliary/analyzer/bloodbash_analyzer
set BLOODBASH_PATH /path/to/BloodBash/BloodBash.py
set JSON_DIR /path/to/collector_json_or.zip
set FROM_USER alice
set FROM_USER_EXPORT true
set PASSWORD_NEVER_EXPIRES true
set KERBEROASTABLE true
set ALL_FINDINGS true
run
```

Point `BLOODBASH_PATH` at a standalone binary (non-`.py`) to skip the Python interpreter. Set `PYTHON` if `python3` is not on `PATH`.

### Pitfalls

| Symptom | Check |
|---------|-------|
| Module not listed | `reload_all` after copying, or check the modules path |
| "BloodBash not found" | `BLOODBASH_PATH` must be absolute |
| Interpreter errors | Set `PYTHON`, or point at the binary |

### See also

- [CLI reference](#cli-reference)
- [Deployment](deployment.md)

---

## Finding categories

### What

The category names findings are grouped under, with their ATT&CK mapping.

### Why

Category names are used by `--explain`, `--suppress`, `--fail-on-severity` reporting, SARIF rule ids, and tickets. They are stable identifiers.

### How

| Category | ATT&CK |
|----------|--------|
| DCSync | T1003.006 |
| Kerberoastable | T1558.003 |
| Privileged Kerberoastable | T1558.003 |
| AS-REP Roastable | T1558.004 |
| Privileged AS-REP Roastable | T1558.004 |
| ESC1-ESC8 | T1649 |
| Shadow Credentials | T1556.006 |
| RBCD | T1550.001 |
| Can Configure RBCD | T1098 |
| Constrained Delegation | T1558 |
| Unconstrained Delegation | T1558 |
| SID History Abuse | T1134.005 |
| Dangerous Permissions | T1098 |
| Broad Principal ACL | T1098 |
| GPO Abuse | T1484.001 |
| GPO Content | T1484.001 |
| Trust Abuse | T1484.002 |
| LAPS | T1552.006 |
| LAPS Readers | T1552.006 |
| Password in Description | T1552.001 |
| Password Never Expires | T1078 |
| Password Not Required | T1078 |
| Password Age | T1110 |
| Stale Accounts | T1078 |
| Sessions | T1021 |
| HasSession | T1021 |
| Shortest Paths | T1021 |
| Deep Paths | T1021 |
| Stepping Stones | T1021 |
| Path Break | T1021 |
| Owned Paths | T1021 |
| Arbitrary Paths | T1021 |
| Azure Privileged Roles | T1098.003 |
| Azure App Secrets | T1098.001 |
| Azure MFA Bypass | T1556.006 |
| Azure Guest Access | T1078.004 |
| Azure Service Principal Abuse | T1098.001 |

High-volume hygiene categories collapse to a summary row so the console stays readable. Caps:

| Category | Detail rows kept |
|----------|------------------|
| Password Not Required | 25 |
| Password Never Expires | 25 |
| LAPS Readers | 25 |
| Shadow Credentials | 40 |
| Dangerous Permissions | 40 |
| Kerberoastable | 30 |
| AS-REP Roastable | 30 |

Critical path categories are never collapsed.

### Example

```bash
bloodbash DIR --all --all-findings
bloodbash DIR --all --explain DCSync
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| A category is missing from the table | It collapsed; use `--all-findings` |
| Suppression does not match | Category names are case-sensitive |

### See also

- [Explain](#explain)
- [Suppressions](#suppressions)

---

## Exit codes

### What

The exit status contract for automation.

### Why

CI gates and scripts need reliable signals that distinguish "clean", "findings", and "bad input".

### How

| Code | Meaning |
|------|---------|
| 0 | Completed. Findings may exist; this is not a clean bill of health unless you gated |
| 1 | `--golden-path` found no path to Domain Admins |
| 2 | Gate tripped (`--fail-on-severity`), task failure under `--tasks-strict`, validation errors, or bad input (missing suppression file, bad baseline) |
| 3 | `--domain` filter matched nothing. Nothing was analyzed |
| 130 | Interrupted (Ctrl-C) |

Exit 3 is deliberately distinct from 0. A typo in `--domain` must not look like a clean result.

### Example

```bash
bloodbash DIR --all --fail-on-severity 8
case $? in
  0) echo "gate passed" ;;
  2) echo "findings at or above threshold" ;;
  3) echo "domain filter matched nothing" ;;
esac
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Script treats findings as success | Exit 0 means completed, not clean. Use `--fail-on-severity` |
| Gate passes unexpectedly | Confirm the threshold and that rows are not suppressed or baseline-matched |

### See also

- [CI gating](#ci-gating)
- [Domain filtering](#domain-filtering)

---

## CLI reference

### What

The complete flag surface, grouped as the help output groups it.

### Why

One place to look up a flag without reading `--help-advanced` output.

### How

**Input and run mode**

| Flag | Description |
|------|-------------|
| `DIR` | SharpHound/AzureHound directory or `.zip` (default `.`) |
| `--merge PATH...` | Union extra dirs or zips into one graph |
| `--quick-wins` | High-signal triage; also the default |
| `--all` | Full AD and Azure analysis |
| `--profile FILE\|name` | YAML profile: `quick`, `quick-wins`, `adcs-heavy`, `hygiene`, or a path |
| `--wizard` | Interactive mode picker |
| `--fast` | Limit heavy pathfinding |
| `--verbose` | Verbose graph summary |
| `--debug` | Verbose parse/build logging |
| `--all-findings` | Print the full findings table |
| `--list-domains` | List domains and tenants, then exit |
| `--domain X` | Filter to one AD domain or Azure tenant (case-insensitive) |

**AD privilege and abuse**

| Flag | Description |
|------|-------------|
| `--dcsync` | GetChanges + GetChangesAll, unexpected vs nested DA/EA |
| `--dangerous-permissions` | Dangerous ACLs on high-value objects |
| `--rbcd` | RBCD configured, plus can-configure |
| `--unconstrained-delegation` | Unconstrained delegation, DC vs non-DC |
| `--constrained-delegation` | Constrained delegation |
| `--shadow-credentials` | `AddKeyCredentialLink` |
| `--sid-history` | SID history abuse |
| `--gpo-abuse` | Weak GPO permissions |
| `--trust` | Domain trusts and SID filtering |

**Credentials**

| Flag | Description |
|------|-------------|
| `--kerberoastable` | SPN accounts |
| `--as-rep-roastable` | DONT_REQ_PREAUTH accounts |
| `--privileged-roast` | Roastable and privileged |
| `--password-descriptions` | Passwords in descriptions |
| `--password-never-expires` | PNE users |
| `--password-not-required` | PasswordNotRequired users |

**ADCS and GPO content**

| Flag | Description |
|------|-------------|
| `--adcs` | ESC1-ESC8, plus ESC9/ESC13 when data exists |
| `--gpo-parsing` | GPO metadata analysis |
| `--gpo-content-dir DIR` | Parse exported GPO XML |

**Sessions and inventory**

| Flag | Description |
|------|-------------|
| `--sessions` | LocalAdmin, RDP, DCOM, session summary |
| `--inventory` | All inventory modules |
| `--password-age` | Password age ladders |
| `--stale-accounts` | Inactivity ladders |
| `--privilege-inventory` | Privileged group membership |
| `--owned-inventory` | Inventory for owned principals |

**Azure and Entra**

| Flag | Description |
|------|-------------|
| `--azure-privileged-roles` | Privileged directory roles |
| `--azure-app-secrets` | App/SP credential control |
| `--azure-mfa-bypass` | MFA disable signals |
| `--azure-guest-access` | Guest users |
| `--azure-sp-abuse` | Service principal abuse |
| `--azure-entra-posture` | Entra posture checks |

**Paths**

| Flag | Description |
|------|-------------|
| `--shortest-paths` | Paths to high-value targets |
| `--path-mode short\|abuse\|deep` | Edge weighting |
| `--path-depth N` | Hop limit |
| `--path-sources N` | Source cap |
| `--max-paths N` | Paths per target |
| `--indirect` | Include group-mediated paths |
| `--deep-paths` | Deeper hops, alternates, stepping stones |
| `--no-stepping-stones` | Suppress stepping stones |
| `--golden-path` | One path to DA, rendered as a panel |
| `--path-from` / `--path-to` | Arbitrary paths |
| `--busiest-paths [short\|all]` | Rank principals by path count |
| `--busiest-paths-top N` | Top N (default 5) |
| `--path-break` | Edges to remove |
| `--path-break-top N` | Top N (default 15) |
| `--deep-analysis` | Slow nesting and cycle detection |

**Principals**

| Flag | Description |
|------|-------------|
| `--from-user` / `--compromise USER` | Outbound dossier |
| `--from-user-file FILE` | Line-delimited footholds |
| `--from-user-export [DIR]` | Export the dossier |
| `--writable-file FILE` | Import bloodyAD `get writable` |
| `--writable-all` | Include writes already present as edges |
| `--owned a,b` | Inbound paths to owned principals |
| `--owned-file FILE` | Same, from a file |
| `--inspect NODE` | Dump node properties and edges |

**Output and deliverables**

| Flag | Description |
|------|-------------|
| `--export {md,json,html,csv,yaml,sarif}` | Single-file report |
| `--export-bh` | BloodHound-compatible graph JSON |
| `--dot [FILE]` | Graphviz DOT |
| `--graphml FILE` | GraphML |
| `--report-pack DIR` | Multi-page HTML suite plus CSVs |
| `--csv-pack DIR` | PlumHound-style CSV pack |
| `--export-zip [FILE]` | Zip a pack |
| `--tickets DIR` | Markdown tickets |
| `--ticket-min-score N` | Ticket threshold (default 8) |
| `--log-file [FILE]` | Run log (default `bloodbash.log`) |
| `--no-animate` | Disable spinner animation |

**CI and automation**

| Flag | Description |
|------|-------------|
| `--fail-on-severity N` | Exit 2 when a finding scores at or above N |
| `--suppress FILE` | YAML suppression list |
| `--baseline REPORT.json` | Diff against a prior JSON export |
| `--explain CATEGORY\|N` | Explain why a finding fired |
| `--snapshot` | Save a findings snapshot |
| `--trend` | Compare the latest two snapshots |
| `--plugins-dir DIR` | Load plugin detectors |
| `--watch [DIR]` | Re-run when inputs change |
| `--watch-interval SEC` | Poll interval (default 5.0) |

**Cache**

| Flag | Description |
|------|-------------|
| `--db FILE` | Explicit SQLite graph path |
| `--cache-dir DIR` | Cache directory override |
| `--no-cache` | Disable cache read and write |
| `--rebuild-cache` | Force re-ingest |

**Tasks**

| Flag | Description |
|------|-------------|
| `--tasks FILE...` | Run task lists |
| `--tasks-out DIR` | Output directory |
| `--tasks-format FMT` | Force output format |
| `--tasks-strict` | Exit 2 on any task failure |
| `--tasks-validate FILE...` | Validate without running |
| `--tasks-list` | List shipped example lists |

**Help**

| Flag | Description |
|------|-------------|
| `-h`, `--help` | Start-here plus cheat sheet |
| `--help-advanced` | Full flag tables and examples |

### Example

```bash
bloodbash --help
bloodbash --help-advanced
```

### See also

- [Exit codes](#exit-codes)
- [Run modes](#run-modes)

---

## Collection health

### What

A banner printed on every run with object counts, edge coverage, and a reliability ceiling.

### Why

An empty section can mean "clean" or "not collected". Health metrics tell you which, before you draw conclusions from silence.

### How

Reports user, computer, group, GPO, and domain counts; HasSession, LocalAdmin/AdminTo, CanRDP, and trust edge counts; ADCS data presence; SID-only node count; and a reliability ceiling of low, medium, or high.

### Example

```text
Objects: users=2154 computers=3010 groups=450 gpos=99 domains=1
Edges: HasSession=157 LocalAdmin/AdminTo=4 CanRDP=0 trusts=0
ADCS data: no · SID-only nodes: 593 · Reliability ceiling: low
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Low ceiling | Missing ADCS objects, many SID-only principals, or thin session data |
| Zero CanRDP | The collector did not gather RDP rights |

### See also

- [Sessions and local admin](#sessions-and-local-admin)

---

## Domain filtering

### What

Restrict a run to one AD domain or Azure tenant.

### Why

Forest collections and merged engagements contain several domains. Filtering keeps findings attributable and pathfinding scoped.

### How

`--domain X` accepts a DNS name, a netbios prefix (`TTIG` matches `TTIG.INTERNAL`), the domain in the distinguished name, or an Azure `tenantId`. Matching is case-insensitive. `--list-domains` shows the available values.

If nothing matches, the run exits 3 and lists the domains present.

### Example

```bash
bloodbash DIR --list-domains
bloodbash DIR --all --domain CORP.LOCAL
bloodbash DIR --quick-wins --domain TTIG
bloodbash ./azureout --azure-privileged-roles --domain <tenantId>
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Exit 3 | The filter matched nothing; the message lists valid values |
| SAM resolves in the wrong domain | Add `--domain`, or qualify as `user@domain` |

### See also

- [Name matching](#name-matching)
- [Exit codes](#exit-codes)

---

## Name matching

### What

How BloodBash resolves the principal names you pass on the command line.

### Why

`alice` is ambiguous in a forest. Picking the first alphabetically would silently analyze the wrong account.

### How

| You pass | Behaviour |
|----------|-----------|
| `alice` | That SAM in one domain. With `--domain`, only that domain. If the SAM exists in more than one domain, BloodBash lists the hits and stops |
| `alice@corp.local` | That domain only. Also matches `userPrincipalName` and the distinguished-name domain |
| `CORP\alice` | Netbios-qualified, that domain only |
| Object id | Exact node |

Applies to `--from-user`, `--owned`, `--path-from`, `--path-to`, `--inspect`, and `--golden-path`.

### Example

```bash
bloodbash DIR --from-user 'udt@ttig.internal'
bloodbash DIR --from-user 'TTIG\udt'
bloodbash DIR --from-user udt --domain TTIG.INTERNAL
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| "Found in multiple domains" | Qualify the name or add `--domain` |
| Name not found | Confirm the SAM with `--list-domains` and a broad search |

### See also

- [Domain filtering](#domain-filtering)
- [Compromise dossier](#compromise-dossier)

---

## Timestamps

### What

How BloodBash interprets collector timestamps, and the sentinel values SharpHound may emit.

### Why

Several collectors emit `-11644473600` (FILETIME zero converted to Unix) instead of `-1` for "never". Age and staleness queries written for BloodHound expect `-1`, so raw values produce empty or wrong buckets.

### How

BloodBash reads the raw property. When writing task-list queries against a collection, account for both sentinels:

```text
WHERE n.lastlogontimestamp IN [-1, -11644473600] OR n.lastlogontimestamp IS NULL
```

### Example

```bash
bloodbash DIR --stale-accounts
bloodbash DIR --inventory --all-findings
```

### Pitfalls

| Symptom | Check |
|---------|-------|
| Stale buckets look empty | The collection may use `-11644473600` rather than `-1` |
| Password ages are absurd | A sentinel is being treated as a real timestamp |

### See also

- [Inventory](#inventory)
- [Task query subset](#task-query-subset)

---

## Troubleshooting

### What

Common failures and what to check first.

### Why

Most issues are input shape, interpreter, or expectations about what a flag includes.

### How

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `ModuleNotFoundError` | Wrong interpreter | Install `requirements.txt` for the interpreter you invoke |
| Zero objects loaded | Path is a parent folder or not collector JSON | Point at the collection directory or zip; run `--debug` |
| Exit 3 | `--domain` matched nothing | Check `--list-domains` |
| Empty sections under `--all` | Suppressed by design | Use selective flags or `--all-findings` |
| Gate passes unexpectedly | Exit 0 means completed | Add `--fail-on-severity` |
| Stale results | Cache hit on old files | `--rebuild-cache` |
| Task returns zero rows | Query matched nothing, or a property is not projected | Check [projection limits](architecture.md#projection-limits) |
| Slow runs | Ingest or deep pathfinding | `--fast`, and rely on the cache |

### Example

```bash
bloodbash DIR --debug --list-domains
bloodbash DIR --all --rebuild-cache --verbose
```

### See also

- [Exit codes](#exit-codes)
- [Collection health](#collection-health)
- [Architecture](architecture.md)

---

## Authorized use reminder

BloodBash is for **authorized** security testing and red teaming only. It analyzes data collected under an engagement agreement. Do not use it against domains you are not permitted to test. Never commit client BloodHound dumps or credentials to a repository.
