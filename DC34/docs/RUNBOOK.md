# Operator runbook

## Player flow (keep this)
RDP -> double-click Collect-AD.bat -> zip + bloodbash.exe on FOOTHOLD

Never instruct players to use Evil-WinRM for SharpHound.

## Deploy
1. `ludus range config set -f ludus/defcon-ctf-range.yml`
2. `ludus range deploy` until SUCCESS
3. Snapshot clean
4. `ansible-playbook -i inventory.yml site.yml`
5. `ansible-playbook -i inventory.yml plant_collect_ui.yml`
6. Copy SharpHound.exe into Public Desktop\BloodBash-CTF\ (or bake into role)

## Why RDP
SharpHound LDAP fails under WinRM network logons. Interactive RDP works with a plain exe run / the bat file.


## Full attack commands
See **docs/ATTACK-PATH.md** (includes BloodBash flags, bloodyAD, secretsdump, John the Ripper mscash2).


## Tools baked onto FOOTHOLD
`ansible/plant_collect_ui.yml` deploys:
- `files/tools/SharpHound.exe` (required in pack)
- `files/tools/bloodbash.exe` (or download from GitHub)
- `files/Collect-AD.bat`

Place binaries in `ansible/files/tools/` before running the plant playbook.


Players use **bloodbash.exe on FOOTHOLD**. Do not instruct them to copy the zip to a laptop.
