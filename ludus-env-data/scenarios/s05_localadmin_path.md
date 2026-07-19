# s05_localadmin_path
## Config
- User path_user; domainuser ForceChangePassword on path_user
- path_user local Admin on HOP01
## BloodBash must see
- ForceChangePassword DOMAINUSER → PATH_USER
- PATH_USER LocalAdmin/AdminTo SS-HOP01
## Command
`bloodbash s05.zip --from-user domainuser --shortest-paths`
