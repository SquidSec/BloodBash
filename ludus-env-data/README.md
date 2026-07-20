# ludus-env-data
BloodBash **accuracy** corpora (not Defcon CTF).

## Layout
```
ludus-env-data/
  README.md
  RESULTS.md                 # validation status
  scenarios/s0N_*.md         # ground truth per scenario
  collections/s0N.zip        # SharpHound zips
  collections/s0N_bloodbash.txt
  ansible/                   # cleanup + plant playbooks
```

## Run a scenario (no Ludus rebuild)
On Ludus host (reach 10.1.10.x):
```bash
cd ansible
ansible-playbook -i inventory.yml cleanup.yml
ansible-playbook -i inventory.yml scenarios/s02_kerberoast.yml
# then SharpHound with --RebuildCache as domainuser (RDP or schtask)
```

## BloodBash
```bash
bloodbash collections/s02.zip --all --fast
bloodbash collections/s01.zip --from-user domainuser --shortest-paths
```

| s06-s13 | ACL/RBCD/deleg/GPO/DCSync/shadow | collections/s06-s13.zip | scenarios/s06-s13.md |
