# BloodBash deployment

Install paths, binary builds, CI workflows, and the Metasploit module.

| Related | Purpose |
|---------|---------|
| [User guide](user-guide.md) | Feature reference |
| [Architecture](architecture.md) | Design |
| [Docs index](README.md) | Catalog |

---

## Table of contents

1. [Requirements](#requirements)
2. [Standalone binary](#standalone-binary)
3. [pipx install](#pipx-install)
4. [Source checkout](#source-checkout)
5. [Local binary build](#local-binary-build)
6. [Release workflow](#release-workflow)
7. [CI workflows](#ci-workflows)
8. [Metasploit module](#metasploit-module)
9. [Development](#development)
10. [Repo hygiene](#repo-hygiene)

---

## Requirements

### Context

BloodBash runs offline. The only requirements are a Python interpreter or the standalone binary.

### Configuration

| Requirement | Detail |
|-------------|--------|
| Python | 3.9 or newer for source installs |
| Runtime dependencies | `networkx>=3.0`, `rich>=13.0`, `tqdm>=4.0`, `pyyaml>=6.0` |
| Build dependencies | `pyinstaller>=6.0` |
| Dev dependencies | `pytest>=7.0` |
| Network | None at runtime |

### Commands

```bash
cat requirements.txt
cat requirements-dev.txt
cat requirements-build.txt
```

### Verify

```bash
python3 -c "import networkx, rich, tqdm, yaml; print('deps ok')"
```

### See also

- [Source checkout](#source-checkout)

---

## Standalone binary

### Context

The released binaries need no Python, no pip, and no virtual environment. They are PyInstaller one-file executables built on every push to `main`.

### Configuration

Stable asset names are published so the `/releases/latest/download/...` URLs keep working:

| Platform | Asset |
|----------|-------|
| Linux x64 | `bloodbash-linux-x64` |
| Windows x64 | `bloodbash-windows-x64.exe` |

### Commands

```bash
# Linux
curl -sL -o bloodbash \
  https://github.com/SquidSec/BloodBash/releases/latest/download/bloodbash-linux-x64
chmod +x bloodbash
./bloodbash DIR --quick-wins
```

```powershell
# Windows
Invoke-WebRequest -Uri "https://github.com/SquidSec/BloodBash/releases/latest/download/bloodbash-windows-x64.exe" `
  -OutFile bloodbash.exe
.\bloodbash.exe C:\path\to\json --all
```

### Verify

```bash
./bloodbash --help
```

### See also

- [Release workflow](#release-workflow)

---

## pipx install

### Context

`pipx` keeps the install isolated and puts `bloodbash` on `PATH`.

### Configuration

The entry point is declared in `pyproject.toml` as `bloodbash = "BloodBash:main"`.

### Commands

```bash
pipx install git+https://github.com/SquidSec/BloodBash
bloodbash DIR
```

### Verify

```bash
which bloodbash
bloodbash --help
```

### See also

- [Requirements](#requirements)

---

## Source checkout

### Context

Use a checkout for development, plugins, or running the test suite.

### Configuration

A virtual environment keeps dependencies out of the system interpreter.

### Commands

```bash
git clone https://github.com/SquidSec/BloodBash.git
cd BloodBash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 BloodBash.py DIR --quick-wins
```

### Verify

```bash
python3 BloodBash.py --help
python3 -m pytest test_bloodbash.py -q
```

### If it fails

| Symptom | Action |
|---------|--------|
| `ModuleNotFoundError` | The venv is not active, or you invoked a different interpreter |
| Tests fail at collection | Install `requirements-dev.txt`, which includes pytest and runtime deps |

### See also

- [Development](#development)

---

## Local binary build

### Context

Reproduce the release artifact locally.

### Configuration

PyInstaller one-file, console mode.

### Commands

```bash
python3 -m venv .venv-build
source .venv-build/bin/activate
pip install -r requirements.txt -r requirements-build.txt
pyinstaller --onefile --console --name bloodbash-linux-x64 BloodBash.py
# -> dist/bloodbash-linux-x64
```

### Verify

```bash
./dist/bloodbash-linux-x64 SampleSharphoundADData --quick-wins
```

### If it fails

| Symptom | Action |
|---------|--------|
| Missing module at runtime | Add the module to the spec's hidden imports |
| Bare `pip` or `pyinstaller` rejected in CI | CI pins the interpreter and forbids bare invocations by design |

### See also

- [Release workflow](#release-workflow)

---

## Release workflow

### Context

Merges to `main` build Linux and Windows binaries and publish a GitHub Release.

### Configuration

- Tags follow `v<version>-build.<N>`.
- Asset names are stable, so the latest-download URLs never change.
- The release job retries transient API failures.

### Commands

```bash
# Check the current version and recent tags
grep '^version' pyproject.toml
git tag --sort=-creatordate | head -5
```

### Verify

- The release page shows both platform assets.
- `bloodbash --help` on the downloaded binary reports the expected version.

### See also

- [CI workflows](#ci-workflows)

---

## CI workflows

### Context

Three workflows live in `.github/workflows/`.

| Workflow | Purpose |
|----------|---------|
| `run-tests.yml` | Pytest matrix on Python 3.9 and 3.11, plus the scenario battery, then a `test` gate check |
| `release-binaries.yml` | Build and publish binaries on merge to `main` |
| `squidgate.yml` | PR security gate |

The `test` gate exists because matrix jobs report as `test (3.9)` and `test (3.11)`, which never satisfy a required check named `test`.

### Configuration

CI pins the build interpreter and forbids bare `pip` and `pyinstaller` invocations so a stray system install cannot influence a release.

### Commands

```bash
# Run the same suite locally
python3 -m pytest test_bloodbash.py test_members_ingest.py \
  test_detection_variations.py test_compromise_dossier.py \
  test_writable_file.py test_synthetic_corpus.py test_ludus_collections.py \
  test_real_data_reliability.py test_graph_cache.py test_owned_file.py \
  test_golden_path.py test_deep_paths.py test_repo_hygiene.py \
  test_ingest_edge_cases.py test_detector_fixes.py test_reporting_features.py \
  test_coverage_additions.py test_task_projection.py \
  test_task_projection_edges.py test_task_file_parser.py \
  test_task_result_writers.py test_task_query_evaluator.py \
  test_task_path_functions.py test_task_cli.py test_task_parity.py \
  test_release_smoke.py test_console_encoding.py test_release_workflow.py \
  test_version_consistency.py test_ci_pytest_suite.py -q

# Scenario battery
python3 tools/run_scenario_battery.py --count 20 --seed 42
```

### Verify

- All tests pass locally.
- The battery reports `SUMMARY: 20/20 scenarios passed`.

### See also

- [Development](#development)

---

## Metasploit module

### Context

`modules/auxiliary/analyzer/bloodbash_analyzer.rb` wraps the CLI and reports findings into the Metasploit database.

### Configuration

| Option | Purpose |
|--------|---------|
| `BLOODBASH_PATH` | Path to `BloodBash.py` or a standalone binary |
| `JSON_DIR` | Collection directory or zip |
| `PYTHON` | Interpreter, ignored when the path is a binary |

Remaining options mirror the CLI. See the [user guide](user-guide.md#metasploit-module) for the full list.

### Commands

```bash
cp modules/auxiliary/analyzer/bloodbash_analyzer.rb \
  /opt/metasploit-framework/modules/auxiliary/analyzer/
```

```text
msfconsole
reload_all
use auxiliary/analyzer/bloodbash_analyzer
set BLOODBASH_PATH /path/to/BloodBash/BloodBash.py
set JSON_DIR /path/to/collection.zip
set ALL_CHECKS true
run
```

### Verify

- The module appears under `auxiliary/analyzer/bloodbash_analyzer`.
- A run reports findings into the database.

### If it fails

| Symptom | Action |
|---------|--------|
| Module not listed | Run `reload_all`, or check the modules path |
| Interpreter error | Set `PYTHON`, or point `BLOODBASH_PATH` at the binary |

### See also

- [User guide - Metasploit module](user-guide.md#metasploit-module)

---

## Development

### Context

The repo is one application file plus a large pytest suite and supporting tools.

### Configuration

| Path | Contents |
|------|----------|
| `BloodBash.py` | The application |
| `test_*.py` | Pytest suite |
| `testData/` | Feature fixtures and the synthetic lab |
| `tools/` | Corpus generator, scenario battery, parity checker, mutator |
| `tasks/` | Shipped example task lists and the parity baseline |
| `profiles/` | Built-in YAML profiles |

### Commands

```bash
# Synthetic corpus regression
python3 tools/generate_synthetic_sharphound.py --out testData/synthetic-corp-lab
python3 BloodBash.py testData/synthetic-corp-lab --all --fast --all-findings

# Engagement battery
python3 tools/run_scenario_battery.py
python3 tools/run_scenario_battery.py --count 20 --seed 42 -v
python3 tools/run_scenario_battery.py --list-profiles
python3 tools/run_scenario_battery.py --keep --work-dir /tmp/bb-engagements

# Task-list parity
python3 tools/task_parity.py --corpus testData/synthetic-corp-lab --write
python3 tools/task_parity.py --corpus testData/synthetic-corp-lab --check

# Corpus mutation for robustness testing
python3 tools/mutate_corpus.py --in testData/synthetic-corp-lab --out /tmp/mut --seed 1
python3 BloodBash.py /tmp/mut --all --fast
```

### Verify

- `task_parity.py --check` prints `parity ok`.
- The battery prints a full pass summary.

### See also

- [CI workflows](#ci-workflows)
- [Architecture](architecture.md#testing)

---

## Repo hygiene

### Context

Engagement data and credentials must never enter the repository.

### Configuration

`.gitignore` excludes:

- `*_bloodhound.zip` and `*_BloodHound.zip` (client dumps)
- `*.conf` except `*.conf.example` (VPN and WireGuard configs)
- Generated lab artifacts under `ludus-env-data/`
- Local agent memory (`MEMORY.md`, `AGENTS.md`, `.agents/`)
- Standard Python build and cache output

### Commands

```bash
git status --short
git ls-files | grep -iE 'bloodhound\.zip|\.conf$' || echo "clean"
```

### Verify

- No client dumps or secrets are tracked.
- `test_repo_hygiene.py` passes.

### See also

- [Development](#development)

---

For authorized security testing only.
