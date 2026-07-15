# BloodBash

<p align="center">
  <a href="https://squidoffense.com/">
    <img src="assets/squidsec-logo.png" alt="SquidSec logo" width="180">
  </a>
</p>

<p align="center">
  <strong>A SquidSec Open Source Project</strong><br>
  <a href="https://squidoffense.com/">SquidOffense.com</a> ·
  <a href="https://github.com/DotNetRussell/BloodBash">GitHub</a>
</p>

<p align="center">
  <a href="https://github.com/DotNetRussell/BloodBash/actions/workflows/run-tests.yml"><img src="https://github.com/DotNetRussell/BloodBash/actions/workflows/run-tests.yml/badge.svg" alt="Run Unit Tests"></a>
  <a href="https://github.com/DotNetRussell/BloodBash/actions/workflows/release-binaries.yml"><img src="https://github.com/DotNetRussell/BloodBash/actions/workflows/release-binaries.yml/badge.svg" alt="Build and Release Binaries"></a>
  <a href="https://github.com/DotNetRussell/BloodBash/releases/latest"><img src="https://img.shields.io/github/v/release/DotNetRussell/BloodBash?label=latest%20build" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
</p>

**BloodBash** is an open source offline SharpHound **and** AzureHound JSON analyzer, created and managed by **[SquidSec](https://squidoffense.com/)**. It builds a graph, surfaces AD/Entra attack paths and misconfigs, and prints prioritized findings — no Neo4j or BloodHound UI required.

| | |
|--|--|
| **Organization** | [SquidSec](https://squidoffense.com/) |
| **Website** | [https://squidoffense.com/](https://squidoffense.com/) |
| **App version** | **v1.4.0** |
| **Latest binary** | [![GitHub release](https://img.shields.io/github/v/release/DotNetRussell/BloodBash)](https://github.com/DotNetRussell/BloodBash/releases/latest) |
| **License** | [MIT](LICENSE) |
| **Runtime (source)** | Python 3.9+ |

Merges to `main` automatically build **Linux** and **Windows** binaries and publish a GitHub Release (tag `v1.4.0-build.N`).

---

## About SquidSec

BloodBash is built and maintained by **[SquidSec](https://squidoffense.com/)** for the security community — red teamers, pentesters, and defenders who need fast offline AD/Entra analysis without standing up BloodHound infrastructure.

- **Website:** [https://squidoffense.com/](https://squidoffense.com/)
- **Project:** [https://github.com/DotNetRussell/BloodBash](https://github.com/DotNetRussell/BloodBash)

---

## Download (no Python required)

Standalone **SquidSec** BloodBash executables — no Python, pip, or venv needed:

| Platform | Latest download |
|----------|-----------------|
| **Linux x64** | [bloodbash-linux-x64](https://github.com/DotNetRussell/BloodBash/releases/latest/download/bloodbash-linux-x64) |
| **Windows x64** | [bloodbash-windows-x64.exe](https://github.com/DotNetRussell/BloodBash/releases/latest/download/bloodbash-windows-x64.exe) |

- **All releases & version tags:** https://github.com/DotNetRussell/BloodBash/releases  
- **Latest release page:** https://github.com/DotNetRussell/BloodBash/releases/latest  

```bash
# Linux
curl -sL -o bloodbash \
  https://github.com/DotNetRussell/BloodBash/releases/latest/download/bloodbash-linux-x64
chmod +x bloodbash
./bloodbash /path/to/json --all
```

```powershell
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/DotNetRussell/BloodBash/releases/latest/download/bloodbash-windows-x64.exe" `
  -OutFile bloodbash.exe
.\bloodbash.exe C:\path\to\json --all
```

## Install (Python / source)

```bash
pipx install git+https://github.com/DotNetRussell/BloodBash
```

Or from a clone:

```bash
git clone https://github.com/dotnetrussell/bloodbash.git
cd bloodbash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Dependencies: `networkx`, `rich`, `tqdm`, `pyyaml`.

## Quick start

**Start with these 3** (point at a SharpHound/AzureHound directory or `.zip`):

```bash
# 1) Day-0 triage — default when you pass only the data path
python3 BloodBash.py /path/to/json
# same as:
python3 BloodBash.py /path/to/json --quick-wins

# 2) Just owned a user — outbound compromise dossier
python3 BloodBash.py ./sharpout --from-user alice --from-user-export

# 3) Full analysis (large env: add --fast)
python3 BloodBash.py /path/to/json --all --fast
```

```bash
# Binary / pipx
./bloodbash /path/to/json
bloodbash /path/to/json --from-user alice --from-user-export
```

Bare directory (no check flags) runs **quick-wins** triage. Use `--all` for every module, or `--wizard` for an interactive picker.

Sample data: `SampleSharphoundADData/` and `SampleAzurehoundData/`.

```bash
python3 BloodBash.py --help            # start-here + cheat sheet
python3 BloodBash.py --help-advanced   # full flag tables + all examples
```

More recipes: [docs/cookbook.md](docs/cookbook.md).

## What it finds

| Area | Checks |
|------|--------|
| **AD privilege** | DCSync (GetChanges+GetChangesAll; nested DA/EA treated as expected), dangerous ACLs on high-value objects, GPO abuse, RBCD (configured + *can configure*), constrained/unconstrained delegation (**DC vs non-DC** sections), SID history |
| **AD credentials** | Kerberoastable, AS-REP roastable (with **AdminCount / OWNED / LASTLOG** tags), **privileged roast** (`--privileged-roast`: roastable + nested DA/EA), shadow credentials, password in description, PasswordNeverExpires / PasswordNotRequired |
| **ADCS** | ESC1–ESC7 (+ ESC8/ESC9/ESC13 when collector props exist). ESC10–12 need registry/HTTP role data often absent from SharpHound |
| **Azure / Entra** | Privileged roles, app/SP credential *control* paths, explicit MFA disable, guest users, SP abuse rights |
| **Paths** | Shortest paths to high-value targets (limited set in `--fast`), owned principals (`--owned` = inbound), custom `--path-from` / `--path-to` |
| **Compromise dossier** | `--from-user` / `--compromise`: outbound membership, AdminTo/RDP/ACL counts, nested groups, auto paths to HV, txt/csv export including **bulk AdminTo host lists** |
| **Path remediation** | Busiest-path ranking (`--busiest-paths`), edge removal recommendations (`--path-break`) |
| **Inventory** | Password-age ladders, stale/inactive accounts, privilege groups, structural (domains/DCs/trusts), owned-object inventory, **stats dashboard with %** |
| **PlumHound-style CSV pack** | `--csv-pack DIR`: multi-CSV inventory (domains, DA, roastables, LAPS, Everyone/overpriv edges, computer AdminTo computer, dual priv+local admin, bulk AdminTo hosts) + `index.csv` |
| **Other** | LAPS coverage (`haslaps`) + **LAPS password readers** (`ReadLAPSPassword`), GPO XML (`--gpo-content-dir`), domain `Trusts[]` edges, group nesting, `--list-domains` |

Findings are scored and summarized in a **Prioritized Findings** table (use `--all-findings` for every row). Abuse panels suggest tools/commands per category.

This is an **offline heuristic analyzer** from SquidSec, not a full BloodHound CE replacement. Prefer validating against BloodHound CE on the same zip for path parity.

---

## Example commands

Replace `./sharpout` with your SharpHound/AzureHound directory or zip. Binary users can substitute `./bloodbash` or `bloodbash` for `python3 BloodBash.py`.

### Basics

```bash
# Help (tables + examples)
python3 BloodBash.py --help

# Default = quick wins (high-signal day-0 triage)
python3 BloodBash.py ./sharpout
python3 BloodBash.py ./sharpout --quick-wins
python3 BloodBash.py ./sharpout --quick-wins --domain CORP.LOCAL
python3 BloodBash.py ./2024-collection.zip --quick-wins

# Interactive picker
python3 BloodBash.py ./sharpout --wizard

# Full analysis
python3 BloodBash.py ./sharpout --all
python3 BloodBash.py ./sharpout --all --fast
python3 BloodBash.py ./2024-collection.zip --all --fast

# One domain / tenant only
python3 BloodBash.py ./sharpout --all --domain CORP.LOCAL
python3 BloodBash.py ./azureout --azure-privileged-roles --domain <tenantId>

# In-repo samples
python3 BloodBash.py SampleSharphoundADData --quick-wins
python3 BloodBash.py SampleSharphoundADData --all --fast --all-findings
python3 BloodBash.py SampleAzurehoundData --azure-privileged-roles --azure-guest-access --all-findings
```

### What `--quick-wins` runs

Curated high-signal set (implies `--fast`, verbose summary, full findings table). **Not** a full inventory/Azure dump:

| Area | Modules |
|------|---------|
| Privilege | DCSync (unexpected), ADCS, dangerous ACLs, RBCD + can-configure, unconstrained (DC vs non-DC), constrained, shadow creds, LAPS (+ readers) |
| Credentials | Kerberoast, AS-REP, **privileged roast**, password-in-description, PasswordNotRequired |
| Ops | Sessions / local admin summary |
| Paths | Shortest paths to HV, busiest short paths, path-break |

Equivalent profile: `--profile quick-wins` (see `profiles/quick-wins.yaml`).

### Compromise dossier (newly owned / foothold user)

**Outbound** view: “I just compromised this principal — what can they do?”

| Flag | Meaning |
|------|---------|
| `--from-user` / `--compromise` | Build dossier (nested groups, rights, HV paths) |
| `--from-user-export [DIR]` | Write txt/csv/json lists (default `compromise-<user>/`) |
| `--owned` | Different: paths **to** that principal (inbound) |

```bash
# Console dossier only
python3 BloodBash.py ./sharpout --from-user alice
python3 BloodBash.py ./sharpout --compromise alice@corp.local

# Console + export pack
python3 BloodBash.py ./sharpout --from-user alice --from-user-export
python3 BloodBash.py ./sharpout --from-user alice --from-user-export ./alice-dossier

# Multiple footholds (one subdir each under ./footholds)
python3 BloodBash.py ./sharpout --from-user alice,bob,svc_backup --from-user-export ./footholds

# Domain-scoped + full findings table
python3 BloodBash.py ./sharpout --from-user alice --domain CORP.LOCAL --from-user-export --all-findings

# Sample lab: SCOTT has LocalAdmin via Tier2Support and paths to DA
python3 BloodBash.py SampleSharphoundADData --from-user SCOTT --from-user-export ./scott-out --fast

# Pair with inspect / explicit path
python3 BloodBash.py ./sharpout --from-user alice --inspect alice
python3 BloodBash.py ./sharpout --path-from alice --path-to 'domain admins@corp.local'

# Inbound (who can reach my loot) — not the dossier
python3 BloodBash.py ./sharpout --owned alice --owned-inventory --shortest-paths
```

**Export layout** (per principal):

```text
compromise-alice/
  summary.md              README.txt           counts.csv
  membership_direct.txt   membership_effective.txt
  adminto_hosts.txt       adminto_hosts.csv    # bulk AdminTo/LocalAdmin host list
  paths_to_high_value.txt paths_to_high_value.csv
  dossier.json
  rights/
    AdminTo.txt  AdminTo.csv  CanRDP.txt  LocalAdmin.txt  GenericAll.txt  ...
```

### Attack paths & remediation

```bash
python3 BloodBash.py ./sharpout --shortest-paths
python3 BloodBash.py ./sharpout --shortest-paths --indirect --fast
python3 BloodBash.py ./sharpout --busiest-paths short --busiest-paths-top 10
python3 BloodBash.py ./sharpout --busiest-paths all --busiest-paths-top 5
python3 BloodBash.py ./sharpout --path-break --path-break-top 20
python3 BloodBash.py ./sharpout --busiest-paths short --path-break --fast \
  --report-pack ./path-reports --export-zip path-reports.zip
python3 BloodBash.py ./sharpout --path-from helpdesk --path-to 'domain admins@corp.local'
python3 BloodBash.py ./sharpout --path-from alice,bob --path-to 'domain admins,enterprise admins'
python3 BloodBash.py ./sharpout --deep-analysis
python3 BloodBash.py ./sharpout --inspect 'DOMAIN ADMINS@CORP.LOCAL'
```

### Selective AD checks

```bash
# Critical / common engagement set
python3 BloodBash.py ./sharpout --dcsync --adcs --dangerous-permissions --verbose
python3 BloodBash.py ./sharpout --dcsync --adcs --dangerous-permissions --all-findings

# Credentials (+ privilege-context tags on roast findings)
python3 BloodBash.py ./sharpout --kerberoastable --as-rep-roastable --password-descriptions
# High-priority: roastable users nested into DA/EA/…
python3 BloodBash.py ./sharpout --privileged-roast
python3 BloodBash.py ./sharpout --password-never-expires --password-not-required --password-age

# Delegation / RBCD (configured + who can configure AllowedToAct) / shadow creds
python3 BloodBash.py ./sharpout --unconstrained-delegation --constrained-delegation --rbcd
python3 BloodBash.py ./sharpout --shadow-credentials

# Sessions, LAPS (coverage + ReadLAPSPassword readers), SID history, GPO
python3 BloodBash.py ./sharpout --sessions --laps --sid-history
python3 BloodBash.py ./sharpout --gpo-abuse --gpo-parsing
python3 BloodBash.py ./sharpout --gpo-abuse --gpo-content-dir ./sysvol-gpo-xml
```

### Inventory, profiles, and deliverables

```bash
# List domains / tenants in a collection (then exit)
python3 BloodBash.py ./sharpout --list-domains

# Inventory modules (+ stats dashboard percentages under --all / deep paths)
python3 BloodBash.py ./sharpout --inventory
python3 BloodBash.py ./sharpout --stale-accounts --password-age --privilege-inventory
python3 BloodBash.py ./sharpout --owned alice --owned-inventory

# Built-in YAML profiles (see profiles/)
python3 BloodBash.py ./sharpout --profile quick
python3 BloodBash.py ./sharpout --profile quick-wins   # same set as --quick-wins
python3 BloodBash.py ./sharpout --profile adcs-heavy
python3 BloodBash.py ./sharpout --profile hygiene
python3 BloodBash.py ./sharpout --profile ./my-engagement.yaml

# Multi-page HTML report pack + zip
python3 BloodBash.py ./sharpout --inventory --busiest-paths short --path-break \
  --report-pack ./reports --export-zip bloodbash-reports.zip --log-file ./bloodbash.log

# PlumHound-style multi-CSV pack (task CSVs + index.csv; optional zip)
python3 BloodBash.py ./sharpout --csv-pack ./ph-reports
python3 BloodBash.py ./sharpout --csv-pack ./ph-reports --export-zip ph-reports.zip
python3 BloodBash.py ./sharpout --all --fast --csv-pack ./ph-full --export-zip ph-full.zip

# Single-file exports
python3 BloodBash.py ./sharpout --all --export=md
python3 BloodBash.py ./sharpout --all --export=html
python3 BloodBash.py ./sharpout --all --export=csv
python3 BloodBash.py ./sharpout --all --export=json --export-bh --dot graph.dot
python3 BloodBash.py ./sharpout --all --export=yaml

# SQLite graph cache
python3 BloodBash.py ./sharpout --all --db bloodbash.db
python3 BloodBash.py . --db bloodbash.db --from-user alice --from-user-export
```

### PlumHound-style CSV pack contents

`--csv-pack DIR` writes one CSV per inventory task plus `index.csv` / `README.txt` (no Neo4j):

| CSV | Description |
|-----|-------------|
| `domains.csv` | AD domains in the collection |
| `domain_admins.csv` | Principals nested into DA/EA-style groups |
| `users.csv` / `computers.csv` / `groups.csv` | Core object inventory |
| `kerberoastable.csv` / `asrep_roastable.csv` | Credential roast candidates (+ tags) |
| `password_never_expires.csv` | PNE users |
| `laps_not_enabled.csv` | Computers without LAPS |
| `local_admins_users.csv` | User/group → computer AdminTo/LocalAdmin |
| `user_sessions.csv` | HasSession computer ↔ user |
| `relationships_everyone.csv` (and Auth Users, Domain Users, …) | Edges from over-broad principals |
| `overprivileged_relationships.csv` | Combined Everyone/Auth/Domain Users/… edges |
| `computer_adminto_computer.csv` | Machine → machine AdminTo |
| `dual_privileged_and_local_admin.csv` | DA/EA members that also have AdminTo (tiering) |
| `bulk_adminto_hosts.csv` | Principals ranked by AdminTo host count |
| `index.csv` | Report index (file → row count) |

### Azure / Entra

```bash
python3 BloodBash.py ./azureout --azure-privileged-roles
python3 BloodBash.py ./azureout --azure-app-secrets --azure-sp-abuse
python3 BloodBash.py ./azureout --azure-mfa-bypass --azure-guest-access
python3 BloodBash.py ./azureout \
  --azure-privileged-roles --azure-app-secrets --azure-mfa-bypass \
  --azure-guest-access --azure-sp-abuse --all-findings --export=html

python3 BloodBash.py SampleAzurehoundData \
  --azure-privileged-roles --azure-guest-access --all-findings
```

### Combined engagement recipes

```bash
# Nightly full + deliverable
python3 BloodBash.py ./sharpout --all --fast --all-findings \
  --report-pack ./nightly --export-zip nightly.zip --log-file nightly.log

# Foothold day-0 then domain hygiene
python3 BloodBash.py ./sharpout --from-user alice --from-user-export ./dossiers
python3 BloodBash.py ./sharpout --profile hygiene --report-pack ./hygiene --export-zip hygiene.zip

# ADCS-focused with path remediation
python3 BloodBash.py ./sharpout --profile adcs-heavy --path-break --busiest-paths short \
  --report-pack ./adcs-paths --export-zip adcs-paths.zip
```

---

## Flags reference

### Report packs, profiles, dossier, deliverables (v1.4+)

| Flag | Purpose |
|------|---------|
| `--from-user` / `--compromise USER` | **Compromise dossier** (outbound): nested groups, AdminTo/RDP/ACL counts, paths to high-value |
| `--from-user-export [DIR]` | Export dossier txt/csv/json + **adminto_hosts** lists (default `compromise-<user>/`) |
| `--busiest-paths [short\|all]` | Rank principals on the most paths to high-value targets |
| `--path-break` | Recommend which relationships to remove to break the most attack paths |
| `--inventory` | Structural + password-age + stale + privilege inventories |
| `--password-age` / `--stale-accounts` / `--privilege-inventory` | Individual inventory modules |
| `--owned-inventory` | AdminTo / MemberOf inventory for `--owned` principals |
| `--report-pack DIR` | Multi-page HTML suite + `index.html` + per-section CSVs |
| `--csv-pack DIR` | **PlumHound-style multi-CSV pack** (inventory + overpriv + AdminTo reports + `index.csv`) |
| `--export-zip [FILE]` | Zip a `--report-pack` or `--csv-pack` directory into one deliverable |
| `--profile FILE\|name` | YAML analysis profile (`quick`, `adcs-heavy`, `hygiene`, or path) |
| `--log-file [FILE]` | Append-friendly run log (default `bloodbash.log`) |
| `--all-findings` | End of run: print a table of **every** finding (even if empty) |

### Other useful flags

| Flag | Purpose |
|------|---------|
| `--all` | Run every analysis module |
| `--quick-wins` | **High-signal day-0 triage** (also the **default** with no check flags; implies `--fast`) |
| `--wizard` | Interactive mode picker (quick-wins / full / dossier / profile) |
| `--help-advanced` | Full flag tables + all examples (short `--help` is start-here only) |
| `--fast` | Limit pathfinding to top DA/EA-style targets (not a full skip) |
| `--domain X` | Filter to one AD domain or Azure `tenantId` |
| `--list-domains` | List AD domains / Azure tenants in the collection and exit |
| `--owned a,b` | Paths **to** owned principals (inbound) |
| `--path-from` / `--path-to` | Arbitrary shortest paths |
| `--inspect NODE` | Dump props + edges for a node |
| `--indirect` | Include group-mediated paths/rights |
| `--deep-analysis` | Slow group nesting + cycle detection |
| `--privileged-roast` | Kerberoast/AS-REP users nested into DA/EA/other priv groups |
| `--gpo-content-dir DIR` | Parse GPO XMLs (tasks, scripts, cPassword) |
| `--export {md,json,html,csv,yaml}` | Write a report (high-value targets + prioritized findings) |
| `--export-bh` | BloodHound-style graph JSON |
| `--dot [FILE]` | Graphviz DOT export |
| `--db FILE` | Load/save graph in SQLite |
| `--debug` | Verbose parse/build logging |

Also included under `--all` / selective flags: privilege-context tags on roast findings; unexpected DCSync split; unconstrained DC vs non-DC; LAPS readers; can-configure RBCD; stats dashboard percentages.

Azure-only toggles: `--azure-privileged-roles`, `--azure-app-secrets`, `--azure-mfa-bypass`, `--azure-guest-access`, `--azure-sp-abuse`.

Run `python3 BloodBash.py --help` for start-here + cheat sheet, or `--help-advanced` for full flag tables and examples.

## SharpHound CE notes

Ingest understands modern collector output: group `Members`, `AllowedToAct` (RBCD), Sessions / LocalGroups, domain `Trusts[]`, SID history, CE property name aliases, and safe zip extraction. DCSync requires **GetChanges + GetChangesAll**. ADCS labels follow SpecterOps ESC1–ESC8 (+ ESC9/ESC13 candidates when flags exist).

## Metasploit module

Wraps the SquidSec BloodBash CLI (v1.4+) and reports findings into the Metasploit DB.
Options track the CLI: AD/Azure checks, inventory, busiest-paths / path-break,
`--from-user` compromise dossiers, profiles, report packs, exports, and `--db`.

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

```text
# Foothold dossier + hygiene (parity with CLI examples)
set FROM_USER alice
set FROM_USER_EXPORT
set PASSWORD_NEVER_EXPIRES true
set KERBEROASTABLE true
set ALL_FINDINGS true
run
```

Set `PYTHON` if `python3` is not on `PATH`. Point `BLOODBASH_PATH` at a standalone
binary (non-`.py`) to skip the Python interpreter. Domain filtering is case-insensitive
(matches CLI).
## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest test_bloodbash.py test_members_ingest.py \
  test_detection_variations.py test_compromise_dossier.py \
  test_synthetic_corpus.py -q
```

### Synthetic SharpHound corpus (high-entropy regression)

Public sample dumps are small and low-entropy. For detector regression we ship a
**synthetic SharpHound CE lab** (`testData/synthetic-corp-lab/`) with known
ground truth (unexpected DCSync, Auth Users GPO write, bulk can-configure RBCD,
ESC1, roast, LAPS mix, etc.). No real engagement data.

```bash
# Regenerate corpus + ground_truth.json
python3 tools/generate_synthetic_sharphound.py --out testData/synthetic-corp-lab

# Smoke BloodBash against it
python3 BloodBash.py testData/synthetic-corp-lab --all --fast --all-findings
python3 BloodBash.py testData/synthetic-corp-lab --from-user alice.low --fast

# 20 multi-hop engagement scenarios (classic + common debt paths)
python3 tools/run_scenario_battery.py
python3 tools/run_scenario_battery.py --count 20 --seed 42 -v
python3 tools/run_scenario_battery.py --list-profiles
python3 tools/run_scenario_battery.py --keep --work-dir /tmp/bb-engagements
```

CI (PR + main release) runs unit tests **and** `run_scenario_battery.py --count 20`
(20 engagement chains). Branch protection requires the **test** status check.

Accuracy helpers (no customer data):

```bash
# Mutate synthetic corpus (dup ACEs, orphan SIDs, null ACEs, partial drops)
python3 tools/mutate_corpus.py --in testData/synthetic-corp-lab --out /tmp/mut --seed 1
python3 BloodBash.py /tmp/mut --all --fast

# GPP / cPassword XML fixtures
python3 BloodBash.py testData/synthetic-corp-lab \
  --gpo-content-dir testData/gpo-xml-fixtures --gpo-parsing
```

### Local binary build

```bash
python3 -m venv .venv-build && source .venv-build/bin/activate
pip install -r requirements.txt -r requirements-build.txt
pyinstaller --onefile --console --name bloodbash-linux-x64 BloodBash.py
# → dist/bloodbash-linux-x64
```

CI (on every push to `main`) runs tests, builds Linux + Windows one-file binaries with PyInstaller, and publishes a Release with stable asset names for the `/releases/latest/download/...` links above.

## License & attribution

MIT — for **authorized** security testing and red teaming only.

**BloodBash** is an open source project created and managed by **[SquidSec](https://squidoffense.com/)**.
