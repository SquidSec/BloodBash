# BloodBash documentation

<p align="center">
  <a href="https://squidoffense.com/">
    <img src="../assets/squidsec-logo.png" alt="SquidSec" width="160">
  </a>
</p>

**[SquidSec](https://squidoffense.com/)** open source - [GitHub](https://github.com/SquidSec/BloodBash) - [Releases](https://github.com/SquidSec/BloodBash/releases/latest)

> **Authorized use only.** BloodBash analyzes collector output from engagements you are permitted to test. It never touches a live domain.

---

## How docs are organized (Diátaxis)

| Need | Doc type | Where |
|------|----------|-------|
| Learn by doing | Tutorial | [Root README](../README.md) - [Cookbook](cookbook.md) |
| Solve a job | How-to | [Operator runbook](operator-runbook.md) - [Cookbook](cookbook.md) |
| Look up a feature | Reference | [User guide](user-guide.md) - [CLI reference](user-guide.md#cli-reference) |
| Understand design | Explanation | [Architecture](architecture.md) - [Graph and projection](architecture.md#graph-and-projection) |
| Install or ship | Deployment | [Deployment](deployment.md) |

### Section templates (consistency)

**User guide** (every feature chapter):

```text
## Feature name
### What
### Why
### How
### Example
### Pitfalls          <- optional table
### See also
```

**Operator runbook** (every procedure):

```text
## Procedure name
### Goal
### Prerequisites
### Steps
### Verify
### If it fails
### See also
```

**Deployment** (every topic):

```text
## Topic
### Context
### Configuration
### Commands
### Verify
### See also
```

---

## Start here

| Audience | Start with |
|----------|------------|
| New user, day 0 | [Root README quick start](../README.md#quick-start) -> `bloodbash DIR` |
| Just landed a foothold | [Compromise dossier](user-guide.md#compromise-dossier) |
| Running a full engagement | [Operator runbook - full analysis](operator-runbook.md#run-a-full-analysis) |
| Building a client deliverable | [Report pack](user-guide.md#report-pack) - [CSV pack](user-guide.md#csv-pack) |
| Migrating from PlumHound | [Task lists](user-guide.md#plumhound-task-lists) - [Task query subset](user-guide.md#task-query-subset) |
| CI or automation | [CI gating](user-guide.md#ci-gating) - [Exit codes](user-guide.md#exit-codes) |
| Metasploit user | [Metasploit module](user-guide.md#metasploit-module) |
| Contributor | [Architecture](architecture.md) - [Development](deployment.md#development) |

---

## Catalog

### Users

| Document | Description |
|----------|-------------|
| [User guide](user-guide.md) | Every feature: checks, paths, dossiers, inventory, exports, task lists, plugins, CI |
| [Cookbook](cookbook.md) | Short copy-paste recipes, one per common job |
| [Operator runbook](operator-runbook.md) | Day-2 procedures: triage, foothold, deliverable, re-runs, troubleshooting |

### Design and delivery

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Ingest, graph model, projection, detector model, cache, task engine |
| [Deployment](deployment.md) | Install paths, binary build, CI workflows, Metasploit install |

### Reference

| Document | Description |
|----------|-------------|
| [CLI reference](user-guide.md#cli-reference) | Grouped flag tables for the whole surface |
| [Exit codes](user-guide.md#exit-codes) | What each exit status means in automation |
| [Task query subset](user-guide.md#task-query-subset) | Supported Cypher, clause by clause |
| [Finding categories](user-guide.md#finding-categories) | Category names, scores, ATT&CK mapping |
| [Glossary](glossary.md) | AD, BloodHound, and BloodBash terms |

---

## The three commands most people need

```bash
# 1) Day-0 triage. This is also the default when you pass only the data path.
bloodbash /path/to/sharpout

# 2) You just owned a user. Outbound compromise dossier.
bloodbash /path/to/sharpout --from-user alice --from-user-export

# 3) Full attack analysis. --fast is automatic on large graphs.
bloodbash /path/to/sharpout --all --fast
```

From a source checkout, `python3 BloodBash.py` is equivalent to `bloodbash`.

---

## Documentation conventions

- **`DIR`** is shorthand for a SharpHound or AzureHound directory or `.zip`.
- **`bloodbash`** means the installed entry point. Substitute `python3 BloodBash.py` when running from a clone.
- Commands assume an authorized engagement with data you collected yourself.
- Every command in these docs was executed against the shipped sample data (`SampleSharphoundADData/`, `SampleAzurehoundData/`) or the synthetic lab (`testData/synthetic-corp-lab/`).

---

## Related repositories

| Repository | What it is |
|------------|------------|
| [SquidSec/BloodBash](https://github.com/SquidSec/BloodBash) | This tool |
| [SquidSec/SquidC5](https://github.com/SquidSec/SquidC5) | SquidSec C5 platform |
| [SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound) | Collectors and reference graph schema |

For authorized security testing only.
