# Runbook

RDP to the foothold, double-click Collect-AD.bat to get the zip and bloodbash.exe on the box.

Do not tell players to use Evil-WinRM for SharpHound.

## Deploy
1. `ludus range config set -f ludus/defcon-ctf-range.yml`
2. `ludus range deploy` until SUCCESS
3. Snapshot clean
4. `ansible-playbook -i inventory.yml site.yml`
5. `ansible-playbook -i inventory.yml plant_collect_ui.yml`
6. Put SharpHound.exe on the Public Desktop under BloodBash-CTF\ (or bake it in)

## Why RDP
SharpHound LDAP fails under WinRM network logons. Use interactive RDP with the exe or bat file.

## Full attack commands
See **docs/ATTACK-PATH.md** for the steps with BloodBash, bloodyAD, secretsdump, and John mscash2.

## Tools on FOOTHOLD
The plant_collect_ui.yml playbook puts:
- SharpHound.exe
- bloodbash.exe (or pull from GitHub releases)
- Collect-AD.bat

Put the binaries in ansible/files/tools/ before you run the plant playbook.

Players run bloodbash.exe right on the FOOTHOLD. No copying the zip to their laptop.
