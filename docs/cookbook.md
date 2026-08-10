# BloodBash cookbook

Short recipes for common engagement tasks. Replace `DIR` with your SharpHound/AzureHound directory or zip.

## Start with these 3

```bash
# 1) Day-0 triage (default — same as --quick-wins)
python3 BloodBash.py DIR

# 2) Just owned a user
python3 BloodBash.py DIR --from-user alice --from-user-export

# 3) Full analysis
python3 BloodBash.py DIR --all --fast
```

Interactive first run: `python3 BloodBash.py DIR --wizard`

## Day-0 triage

```bash
python3 BloodBash.py DIR
python3 BloodBash.py DIR --quick-wins --domain CORP.LOCAL
python3 BloodBash.py DIR --profile quick-wins
```

Covers unexpected DCSync, ADCS, dangerous ACLs, RBCD, privileged roast, unconstrained (non-DC), shadow creds, LAPS readers, sessions, short paths + path-break.

## Compromise dossier (foothold)

Outbound: “what can this principal do?”

```bash
python3 BloodBash.py DIR --from-user alice
python3 BloodBash.py DIR --compromise alice@corp.local --from-user-export
python3 BloodBash.py DIR --from-user alice,bob,svc_backup --from-user-export ./footholds
# Line-delimited file (one principal per line; # comments ok)
python3 BloodBash.py DIR --from-user-file ./footholds.txt --from-user-export ./out
```

Inbound (who can reach them):

```bash
python3 BloodBash.py DIR --owned alice --owned-inventory
python3 BloodBash.py DIR --owned-file ./owned.txt --owned-inventory --shortest-paths
# Merge CLI + file
python3 BloodBash.py DIR --owned alice --owned-file ./more-owned.txt
```

## Full review / client deliverable

```bash
python3 BloodBash.py DIR --all --fast --all-findings
python3 BloodBash.py DIR --inventory --busiest-paths short --path-break \
  --report-pack ./reports --export-zip bloodbash-reports.zip
python3 BloodBash.py DIR --csv-pack ./ph-reports --export-zip ph-reports.zip
```

## Profiles

```bash
python3 BloodBash.py DIR --profile quick        # light set
python3 BloodBash.py DIR --profile quick-wins   # same as --quick-wins
python3 BloodBash.py DIR --profile hygiene      # password / stale / inventory lean
python3 BloodBash.py DIR --profile adcs-heavy
python3 BloodBash.py DIR --profile ./my-engagement.yaml
```

## Selective checks

```bash
python3 BloodBash.py DIR --dcsync --adcs --dangerous-permissions
python3 BloodBash.py DIR --kerberoastable --as-rep-roastable --privileged-roast
python3 BloodBash.py DIR --rbcd --unconstrained-delegation --shadow-credentials
python3 BloodBash.py DIR --laps --sessions
```

## Paths & remediation

```bash
python3 BloodBash.py DIR --shortest-paths --fast
# Multi-hop lateral (user→user→…→DA), not just short MemberOf
python3 BloodBash.py DIR --path-mode abuse --shortest-paths
python3 BloodBash.py DIR --deep-paths
python3 BloodBash.py DIR --path-mode deep --path-depth 16 --max-paths 20
# One path to Domain Admins only (plain text, no other output)
python3 BloodBash.py DIR --golden-path
python3 BloodBash.py DIR --golden-path --from-user alice
python3 BloodBash.py DIR --busiest-paths short --path-break
python3 BloodBash.py DIR --path-from helpdesk --path-to 'domain admins'
```

## Azure / Entra

```bash
python3 BloodBash.py AZURE_DIR --azure-privileged-roles --azure-guest-access
python3 BloodBash.py AZURE_DIR --azure-app-secrets --azure-sp-abuse --azure-mfa-bypass
```

## Graph cache (automatic)

```bash
# First run builds the graph and caches under ~/.cache/bloodbash/
python3 BloodBash.py DIR --dcsync
# Later runs with different checks reuse the same graph (no re-ingest)
python3 BloodBash.py DIR --kerberoastable --as-rep-roastable
python3 BloodBash.py DIR --from-user alice --from-user-export
# Force refresh after a new SharpHound zip
python3 BloodBash.py DIR --rebuild-cache --all --fast
# Opt out
python3 BloodBash.py DIR --no-cache --all
```

## Help

```bash
python3 BloodBash.py --help            # start-here + cheat sheet
python3 BloodBash.py --help-advanced   # every flag + examples
```

For authorized security testing / red teaming only.
