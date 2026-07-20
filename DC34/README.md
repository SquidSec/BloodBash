# DEF CON 34 - BloodBash CTF pack (SquidSec)

Pack for the DefCon 34 CTF. Drop it on the Ludus host and run the playbooks.

## Structure
```
DC34/
  README.md
  ludus/
    defcon-ctf-range.yml      # CTF empty AD (ctf.local)
    simple-ad-3vm.yml         # lab variant (lab.local)
  ansible/
    site.yml                  # HelpDesk -> hopadmin path
    plant_collect_ui.yml      # SharpHound + bloodbash + Collect-AD.bat
    plant_flags.yml           # desktop flags
    reset_and_plant.yml       # runs all three
    inventory.yml
    group_vars/all.yml        # CTF creds/domain
    group_vars/lab-test.yml   # lab overrides
    files/Collect-AD.bat
    files/tools/              # SharpHound.exe + bloodbash.exe
  docs/
    PLAYER.md                 # player brief
    ATTACK-PATH.md            # full commands
    RUNBOOK.md                # operators
    SCENARIO.md               # design
```

## Deploy steps
1. Build templates: debian-12, win2022, win11  
2. `ludus range config set -f ludus/defcon-ctf-range.yml`  
3. `ludus range deploy` → SUCCESS  
4. Snapshot **clean**  
5. From a host that can reach range IPs:
   ```bash
   cd ansible
   ansible-playbook -i inventory.yml reset_and_plant.yml
   ```
   (uses `group_vars/all.yml`; for lab use `-e @group_vars/lab-test.yml`)  
6. Confirm FOOTHOLD Desktop has `BloodBash-CTF\` with SharpHound.exe, bloodbash.exe, Collect-AD.bat  
7. Players: RDP FOOTHOLD → Collect-AD.bat → on-box bloodbash.exe  
8. Reset: revert clean snapshot (or redeploy + plant)

## Player flow
RDP to FOOTHOLD, double-click Collect-AD.bat, then run bloodbash.exe on the zip right there on the machine. No need to copy the zip off to a laptop.

## Docs
| File | Audience |
|------|----------|
| docs/PLAYER.md | Players |
| docs/ATTACK-PATH.md | Full command path + John mscash2 |
| docs/RUNBOOK.md | Operators |
| docs/SCENARIO.md | Path design |

## Important
- **RDP for SharpHound**, not Evil-WinRM (network logon breaks SH LDAP).  
- **bloodbash.exe is on FOOTHOLD** — players use that.  
- `--from-user` / `--compromise` are the same flag; pass the username once.  
- No Kali / no debian-11 in the range.  

## Lab vs CTF
| | Lab | CTF |
|--|-----|-----|
| Domain | lab.local | ctf.local |
| Start | LAB\domainuser / password | CTF\domainuser / CtfStart123! |
| DA | password | CtfDA!ChangeMe |
| Range YAML | simple-ad-3vm.yml | defcon-ctf-range.yml |
