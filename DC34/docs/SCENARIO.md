# Scenario design

## Path
```
domainuser
  -> MemberOf HelpDesk
    -> ForceChangePassword hopadmin
      -> AdminTo HOP01
        -> (DA activity / session on HOP01)
          -> Domain Admins
```

## Flags
| Tier | Location | Meaning |
|------|----------|---------|
| 1 | BloodBash path proof | Graph skill |
| 2 | C:\Users\Public\Documents\flag_hop.txt on HOP01 | hopadmin control |
| 3 | C:\Users\Public\Documents\flag_da.txt on DC | DA |

## Planted by ansible/site.yml
- HelpDesk group + domainuser member
- hopadmin user
- HelpDesk ForceChangePassword on hopadmin
- hopadmin local Administrators on HOP01
- Scheduled task as domainadmin on HOP01 (session/logon artifact)
- Player README on FOOTHOLD
