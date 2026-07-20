# BloodBash CTF - Player brief

## Connect
1. Connect WireGuard (staff gives config).
2. **RDP** (not WinRM) to FOOTHOLD:

```text
Host: 10.X.10.30
User: CTF\domainuser
Pass: CtfStart123!
```

Lab test: `10.1.10.30` / `LAB\domainuser` / `password`

## Tools (already on FOOTHOLD)
Open **BloodBash-CTF** on the Desktop (or Public Desktop):

- `SharpHound.exe`
- `bloodbash.exe`
- `Collect-AD.bat`

## Collect and analyze (all on FOOTHOLD)
1. Double-click **Collect-AD.bat**.
2. Wait for SUCCESS (`bloodhound.zip` on the Desktop).
3. Analyze with the **on-box** BloodBash:

```text
cd Desktop\BloodBash-CTF
.\bloodbash.exe ..\bloodhound.zip --from-user domainuser --shortest-paths
.\bloodbash.exe ..\bloodhound.zip --from-user domainuser --from-user-export
```

Or open `bloodbash-out.txt` on the Desktop if Collect-AD.bat already ran BloodBash.

Note: `--from-user` and `--compromise` are the same flag. Use one username only:
```text
.\bloodbash.exe ..\bloodhound.zip --from-user domainuser
```

## Attack
Follow the graph to Domain Admin. Full commands: **docs/ATTACK-PATH.md**.

High level:
1. HelpDesk → ForceChangePassword on hopadmin  
2. Log into HOP as hopadmin  
3. Dump credentials (`impacket-secretsdump` from your attack box, or loot on HOP)  
4. Crack domain cached creds with **John the Ripper** (`--format=mscash2`) if needed  
5. Domain Admin on the DC  

## Flags
- FOOTHOLD desktop: start flag  
- HOP desktop: hopadmin flag  
- DC desktop: Domain Admin flag  

## Rules
Stay inside the range. Do not attack the infra or other players. Use the BloodBash that is already on the FOOTHOLD.
