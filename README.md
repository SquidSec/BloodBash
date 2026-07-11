# BloodBash

[![Run Unit Tests](https://github.com/dotnetrussell/bloodbash/actions/workflows/run-tests.yml/badge.svg)](https://github.com/dotnetrussell/bloodbash/actions/workflows/run-tests.yml)

Offline SharpHound **and** AzureHound JSON analyzer. Builds a graph, surfaces AD/Entra attack paths and misconfigs, and prints prioritized findings — no Neo4j or BloodHound UI required.

**v1.3.1** · Python 3.9+ · [MIT](LICENSE)

## Install

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

Point at a SharpHound/AzureHound output directory (or a `.zip` of those files):

```bash
# Full analysis (recommended)
python3 BloodBash.py /path/to/json --all

# After pipx install
bloodbash /path/to/json --all

# Common selective run
python3 BloodBash.py ./sharpout --adcs --dcsync --dangerous-permissions --verbose

# Large datasets: skip pathfinding
python3 BloodBash.py sharpout --all --fast

# Export + SQLite cache
python3 BloodBash.py . --all --export=html --export-bh --dot --db bloodbash.db
```

With no check flags, BloodBash runs a default pass (verbose summary + common checks).

Sample data lives in `SampleSharphoundADData/` and `SampleAzurehoundData/`.

## What it finds

| Area | Checks |
|------|--------|
| **AD privilege** | DCSync, dangerous ACLs, GPO abuse, RBCD, constrained/unconstrained delegation, SID history |
| **AD credentials** | Kerberoastable, AS-REP roastable, shadow credentials, password in description, PasswordNeverExpires / PasswordNotRequired |
| **ADCS** | ESC1–ESC8 style template/CA misconfigurations |
| **Azure / Entra** | Privileged roles, app secrets/certs, MFA gaps, guest access, service principal abuse |
| **Paths** | Shortest paths to high-value targets, owned principals (`--owned`), custom `--path-from` / `--path-to` |
| **Other** | LAPS status, GPO XML (`--gpo-content-dir`), trust/cross-tenant edges, group nesting |

Findings are scored and summarized in a **Prioritized Findings** table. Abuse panels suggest tools/commands per category.

## Useful flags

| Flag | Purpose |
|------|---------|
| `--all` | Run every analysis module |
| `--fast` | Skip heavy pathfinding |
| `--domain X` | Filter to one AD domain or Azure `tenantId` |
| `--owned a,b` | Paths involving owned principals |
| `--path-from` / `--path-to` | Arbitrary shortest paths |
| `--inspect NODE` | Dump props + edges for a node |
| `--indirect` | Include group-mediated paths/rights |
| `--deep-analysis` | Slow group nesting + cycle detection |
| `--gpo-content-dir DIR` | Parse GPO XMLs (tasks, scripts, cPassword) |
| `--export {md,json,html,csv,yaml}` | Write a report (all formats include high-value targets + prioritized findings) |
| `--export-bh` | BloodHound-style graph JSON |
| `--dot [FILE]` | Graphviz DOT export |
| `--db FILE` | Load/save graph in SQLite |
| `--debug` | Verbose parse/build logging |

Azure-only toggles: `--azure-privileged-roles`, `--azure-app-secrets`, `--azure-mfa-bypass`, `--azure-guest-access`, `--azure-sp-abuse`.

Run `python3 BloodBash.py --help` for the full list.

## SharpHound CE notes

Ingest understands modern collector output: group `Members`, `AllowedToAct` (RBCD), Sessions / LocalGroups, CE property name aliases, and safe zip extraction. DCSync requires **GetChanges + GetChangesAll**; ADCS labels follow SpecterOps ESC1–ESC8 definitions.

## Metasploit module

Wraps the CLI and reports findings into the Metasploit DB.

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

Set `PYTHON` if `python3` is not on `PATH`. Options mirror the CLI (Azure checks, exports, paths, `--db`, etc.).

## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest test_bloodbash.py -q
```

## License

MIT — for **authorized** security testing and red teaming only.
