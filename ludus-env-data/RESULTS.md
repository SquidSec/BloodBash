# BloodBash accuracy RESULTS

## Pipeline
- Ludus lab.local 3-box (no rebuild between scenarios)
- ansible cleanup → plant → SharpHound `--RebuildCache` as domainadmin schtask
- BloodBash `--all --fast` per zip

## Collection integrity (users present in zip)
| ID | Planted principal in zip | BloodBash ground-truth hit |
|----|--------------------------|----------------------------|
| s01 HelpDesk FCP hopadmin | HOPADMIN **YES** | hopadmin seen; **FCP/HelpDesk ACE not clearly reported** |
| s02 Kerberoast svc_sql | SVC_SQL **YES** | **Kerberoastable SVC_SQL YES** |
| s03 AS-REP asrep_user | ASREP_USER **YES** | **AS-REP ASREP_USER YES** |
| s04 GenericAll → hopadmin | HOPADMIN (recollect) | see s04_bloodbash.txt |
| s05 FCP path_user + Admin HOP | PATH_USER **YES** | **PATH_USER LocalAdmin→HOP YES**; FCP edge weak/missing |

## Strong accuracy wins
- **s02**: BloodBash correctly flags kerberoastable `SVC_SQL@LAB.LOCAL`
- **s03**: BloodBash correctly flags AS-REP `ASREP_USER@LAB.LOCAL`
- **s05**: BloodBash sees `PATH_USER` LocalAdmin on `SS-HOP01`

## Gaps / BB or ACL collect issues
- **ForceChangePassword** / **HelpDesk** membership edges often missing or not surfaced in dossier the way planted
- **s01/s04 ACL edges** need deeper check (ACE may need domainuser collect or SH ACL method timing)
- Noise remains: LOCALUSER LocalAdmin on DC, CanRDP paths

## Artifacts
```
ludus-env-data/
  collections/s01.zip … s05.zip
  collections/s0N_bloodbash.txt
  scenarios/s0N_*.md          # intended config
  ansible/                    # plant/cleanup
  RESULTS.md
  README.md
```

## Root cause of earlier empty users
Plant PowerShell used `Get-ADUser -Identity X -ErrorAction SilentlyContinue` under Stop preference → script aborted **before New-ADUser**. Fixed with try/catch exists checks.

## s06–s13 (second batch)
### s06
- size: 32236
- users: ['KRBTGT@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'GUEST@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'ADMINISTRATOR@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'TGTGRP_USER@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `TGTGRP|BBTest_Priv|GenericAll`: **YES**

### s07
- size: 32038
- users: ['ADMINISTRATOR@LAB.LOCAL', 'GUEST@LAB.LOCAL', 'KRBTGT@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `GenericWrite|SS-HOP01`: **YES**

### s08
- size: 31837
- users: ['KRBTGT@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'GUEST@LAB.LOCAL', 'ADMINISTRATOR@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `AllowedToAct|RBCD|AllowedToDelegate`: **YES**

### s09
- size: 31833
- users: ['ADMINISTRATOR@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'GUEST@LAB.LOCAL', 'KRBTGT@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `Unconstrained|TrustedForDelegation`: **YES**

### s10
- size: 32056
- users: ['ADMINISTRATOR@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'KRBTGT@LAB.LOCAL', 'GUEST@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'DELEG_SVC@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `Constrained|DELEG_SVC|AllowedToDelegate`: **YES**

### s11
- size: 31820
- users: ['GUEST@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'KRBTGT@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'ADMINISTRATOR@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `GPO|Default Domain Policy|GenericAll`: **YES**

### s12
- size: 32101
- users: ['GUEST@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'ADMINISTRATOR@LAB.LOCAL', 'DCSYNC_USER@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'KRBTGT@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `DCSync|GetChanges|DCSYNC`: **YES**

### s13
- size: 31913
- users: ['GUEST@LAB.LOCAL', 'DOMAINUSER@LAB.LOCAL', 'LOCALUSER@LAB.LOCAL', 'KRBTGT@LAB.LOCAL', 'ADMINISTRATOR@LAB.LOCAL', 'DOMAINADMIN@LAB.LOCAL', 'SHADOW_TGT@LAB.LOCAL', 'IUSR@LAB.LOCAL', 'NETWORK SERVICE@LAB.LOCAL']
- `Shadow|KeyCredential|SHADOW_TGT|GenericWrite`: **YES**

