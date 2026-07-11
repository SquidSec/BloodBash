# BloodBash

[![Run Unit Tests](https://github.com/DotNetRussell/BloodBash/actions/workflows/run-tests.yml/badge.svg)](https://github.com/DotNetRussell/BloodBash/actions/workflows/run-tests.yml)
[![Build and Release Binaries](https://github.com/DotNetRussell/BloodBash/actions/workflows/release-binaries.yml/badge.svg)](https://github.com/DotNetRussell/BloodBash/actions/workflows/release-binaries.yml)
[![Latest release](https://img.shields.io/github/v/release/DotNetRussell/BloodBash?label=latest%20build)](https://github.com/DotNetRussell/BloodBash/releases/latest)

Offline SharpHound **and** AzureHound JSON analyzer. Builds a graph, surfaces AD/Entra attack paths and misconfigs, and prints prioritized findings — no Neo4j or BloodHound UI required.

**Latest build:** [![GitHub release (latest by date)](https://img.shields.io/github/v/release/DotNetRussell/BloodBash)](https://github.com/DotNetRussell/BloodBash/releases/latest) · App version **v1.3.1** · Python 3.9+ (source) · [MIT](LICENSE)

Merges to `main` automatically build **Linux** and **Windows** binaries and publish a GitHub Release (tag `v1.3.1-build.N`).

## Download (no Python required)

Standalone executables — no Python, pip, or venv needed:

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

Point at a SharpHound/AzureHound output directory (or a `.zip` of those files):

```bash
# Binary (from Releases)
./bloodbash /path/to/json --all

# Full analysis from source (recommended when developing)
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
| **AD privilege** | DCSync (GetChanges+GetChangesAll), dangerous ACLs on high-value objects, GPO abuse, RBCD, constrained/unconstrained delegation (DCs noted but not scored), SID history |
| **AD credentials** | Kerberoastable, AS-REP roastable, shadow credentials (`AddKeyCredentialLink` + non-default ACL paths), password in description, PasswordNeverExpires / PasswordNotRequired |
| **ADCS** | ESC1–ESC7 (+ ESC8/ESC9/ESC13 when collector props exist). ESC10–12 need registry/HTTP role data often absent from SharpHound |
| **Azure / Entra** | Privileged roles, app/SP credential *control* paths, explicit MFA disable, guest users, SP abuse rights |
| **Paths** | Shortest paths to high-value targets (limited set in `--fast`), owned principals (`--owned`), custom `--path-from` / `--path-to` |
| **Other** | LAPS via `haslaps`, GPO XML (`--gpo-content-dir`), domain `Trusts[]` edges, group nesting |

Findings are scored and summarized in a **Prioritized Findings** table. Abuse panels suggest tools/commands per category.

This is an **offline heuristic analyzer**, not a full BloodHound CE replacement. Prefer validating against BloodHound CE on the same zip for path parity.

## Useful flags

| Flag | Purpose |
|------|---------|
| `--all` | Run every analysis module |
| `--fast` | Limit pathfinding to top DA/EA-style targets (not a full skip) |
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

Ingest understands modern collector output: group `Members`, `AllowedToAct` (RBCD), Sessions / LocalGroups, domain `Trusts[]`, SID history, CE property name aliases, and safe zip extraction. DCSync requires **GetChanges + GetChangesAll**. ADCS labels follow SpecterOps ESC1–ESC8 (+ ESC9/ESC13 candidates when flags exist).

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
python3 -m pytest test_bloodbash.py test_members_ingest.py -q
```

### Local binary build

```bash
python3 -m venv .venv-build && source .venv-build/bin/activate
pip install -r requirements.txt -r requirements-build.txt
pyinstaller --onefile --console --name bloodbash-linux-x64 BloodBash.py
# → dist/bloodbash-linux-x64
```

CI (on every push to `main`) runs tests, builds Linux + Windows one-file binaries with PyInstaller, and publishes a Release with stable asset names for the `/releases/latest/download/...` links above.

## License

MIT — for **authorized** security testing and red teaming only.
