# s01_helpdesk_fcp
## Config
- Group HelpDesk; domainuser member
- User hopadmin
- HelpDesk ForceChangePassword on hopadmin
- hopadmin local Admin on HOP01
## BloodBash must see
- DOMAINUSER MemberOf HELPDESK
- ForceChangePassword HELPDESK/domainuser → HOPADMIN
- HOPADMIN AdminTo/LocalAdmin SS-HOP01 (if collected)
## Command
`bloodbash s01.zip --from-user domainuser --shortest-paths`
