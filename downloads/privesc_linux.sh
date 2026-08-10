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
