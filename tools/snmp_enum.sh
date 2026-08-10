#!/bin/bash

###########################################
# SNMP Enumeration Automation Script
# Based on OSCP methodology
###########################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "  _____ _   _ __  __ ____    _____                       "
echo " / ____| \ | |  \/  |  _ \  |  ___|_ __  _   _ _ __ ___  "
echo "| (___ |  \| | |\/| | |_) | | |__ | '_ \| | | | '_ \` _ \ "
echo " \___ \| . \` | |  | |  __/  |  __|| | | | |_| | | | | | |"
echo " ____) | |\  | |  | | |     | |___| |_| |  _  | | | | | |"
echo "|_____/|_| \_|_|  |_|_|     |______\__,_|_| |_|_| |_| |_|"
echo -e "${NC}"
echo -e "${YELLOW}[*] SNMP Enumeration Automation Tool${NC}"
echo ""

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -t, --target <IP>           Target IP address (required)
    -T, --targets <file>        File with multiple target IPs
    -c, --community <string>    Community string (default: public)
    -C, --community-file <file> Wordlist for community strings
    -v, --version <1|2c|3>      SNMP version (default: 2c)
    -w, --wordlist <file>       Custom community strings wordlist
    -o, --output <dir>          Output directory (default: ./snmp_results)
    -a, --all                   Run all enumeration techniques
    -q, --quick                 Quick scan (basic enumeration)
    -e, --extended              Extended enumeration (all OIDs)
    -h, --help                  Show this help message

EXAMPLES:
    # Quick scan with default community string
    $0 -t 10.10.10.92 -q

    # Full enumeration with custom community
    $0 -t 10.10.10.92 -c private -a

    # Bruteforce community strings
    $0 -t 10.10.10.92 -C /usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings.txt

    # Multiple targets
    $0 -T targets.txt -a

    # Extended enumeration with custom output
    $0 -t 10.10.10.92 -e -o /tmp/snmp_scan

EOF
    exit 0
}

# Default values
TARGET=""
TARGETS_FILE=""
COMMUNITY="public"
COMMUNITY_FILE=""
VERSION="2c"
OUTPUT_DIR="./snmp_results"
RUN_ALL=false
QUICK=false
EXTENDED=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -T|--targets)
            TARGETS_FILE="$2"
            shift 2
            ;;
        -c|--community)
            COMMUNITY="$2"
            shift 2
            ;;
        -C|--community-file)
            COMMUNITY_FILE="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -a|--all)
            RUN_ALL=true
            shift
            ;;
        -q|--quick)
            QUICK=true
            shift
            ;;
        -e|--extended)
            EXTENDED=true
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

# Validate required arguments
if [[ -z "$TARGET" && -z "$TARGETS_FILE" ]]; then
    echo -e "${RED}[-] Error: Target IP or targets file is required${NC}"
    show_help
fi

# Check dependencies
check_dependencies() {
    echo -e "${BLUE}[*] Checking dependencies...${NC}"
    local missing_deps=()

    command -v onesixtyone >/dev/null 2>&1 || missing_deps+=("onesixtyone")
    command -v snmpwalk >/dev/null 2>&1 || missing_deps+=("snmp")
    command -v snmpget >/dev/null 2>&1 || missing_deps+=("snmp")
    command -v snmpbulkwalk >/dev/null 2>&1 || missing_deps+=("snmp")

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing dependencies: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}[!] Install with: apt install snmp onesixtyone snmp-mibs-downloader${NC}"
        exit 1
    fi

    # Check SNMP MIBs configuration
    if grep -q "^mibs" /etc/snmp/snmp.conf 2>/dev/null; then
        echo -e "${YELLOW}[!] Warning: /etc/snmp/snmp.conf has uncommented 'mibs' line${NC}"
        echo -e "${YELLOW}[!] For better output, comment out all lines in /etc/snmp/snmp.conf${NC}"
    fi

    echo -e "${GREEN}[+] All dependencies satisfied${NC}"
}

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Bruteforce community strings
bruteforce_community() {
    local target="$1"
    local wordlist="$2"

    echo -e "${BLUE}[*] Bruteforcing community strings on $target...${NC}"

    if [[ -z "$wordlist" ]]; then
        # Try common locations for wordlists
        if [[ -f "/usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings.txt" ]]; then
            wordlist="/usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings.txt"
        elif [[ -f "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt" ]]; then
            wordlist="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
        else
            echo -e "${YELLOW}[!] No wordlist found. Using default communities: public, private, manager${NC}"
            echo -e "public\nprivate\nmanager" > "$OUTPUT_DIR/default_communities.txt"
            wordlist="$OUTPUT_DIR/default_communities.txt"
        fi
    fi

    onesixtyone "$target" -c "$wordlist" | tee "$OUTPUT_DIR/${target}_community_bruteforce.txt"

    # Extract found communities
    grep -oP '\[\K[^\]]+(?=\])' "$OUTPUT_DIR/${target}_community_bruteforce.txt" | sort -u > "$OUTPUT_DIR/${target}_found_communities.txt"

    if [[ -s "$OUTPUT_DIR/${target}_found_communities.txt" ]]; then
        echo -e "${GREEN}[+] Found community strings:${NC}"
        cat "$OUTPUT_DIR/${target}_found_communities.txt"
    else
        echo -e "${RED}[-] No community strings found${NC}"
    fi
}

# Basic SNMP walk
basic_snmpwalk() {
    local target="$1"
    local community="$2"
    local version="$3"

    echo -e "${BLUE}[*] Running basic snmpwalk on $target with community '$community'...${NC}"

    snmpwalk -v"$version" -c "$community" -t 10 "$target" 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_basic_walk.txt"

    if grep -q "Timeout" "$OUTPUT_DIR/${target}_${community}_basic_walk.txt"; then
        echo -e "${RED}[-] Timeout occurred. SNMP might not be available or community string is wrong${NC}"
    elif grep -q "No Such Object" "$OUTPUT_DIR/${target}_${community}_basic_walk.txt"; then
        echo -e "${YELLOW}[!] No Such Object. Try different OID or version${NC}"
    else
        echo -e "${GREEN}[+] Basic walk completed successfully${NC}"
    fi
}

# Full SNMP walk (from root OID)
full_snmpwalk() {
    local target="$1"
    local community="$2"
    local version="$3"

    echo -e "${BLUE}[*] Running full snmpwalk (OID 1) on $target...${NC}"

    snmpbulkwalk -v"$version" -c "$community" "$target" 1 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_full_walk.txt"

    echo -e "${GREEN}[+] Full walk completed. Output saved to ${target}_${community}_full_walk.txt${NC}"
}

# Extended MIB enumeration
extended_enum() {
    local target="$1"
    local community="$2"
    local version="$3"

    echo -e "${BLUE}[*] Running extended enumeration on $target...${NC}"

    # NET-SNMP-EXTEND-MIB (useful for RCE)
    echo -e "${YELLOW}[*] Enumerating NET-SNMP-EXTEND-MIB...${NC}"
    snmpwalk -v"$version" -c "$community" "$target" NET-SNMP-EXTEND-MIB::nsExtendObjects 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_extend_mib.txt"
}

# Specific OID enumeration
specific_oids() {
    local target="$1"
    local community="$2"
    local version="$3"

    echo -e "${BLUE}[*] Enumerating specific OIDs on $target...${NC}"

    # Local user account names (Windows)
    echo -e "${YELLOW}[*] Enumerating local user accounts (1.3.6.1.4.1.77.1.2.25)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.4.1.77.1.2.25 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_users.txt"

    # Installed software
    echo -e "${YELLOW}[*] Enumerating installed software (1.3.6.1.2.1.25.6.3.1.2)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.2.1.25.6.3.1.2 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_software.txt"

    # Listening ports
    echo -e "${YELLOW}[*] Enumerating listening ports (1.3.6.1.2.1.6.13.1.3)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.2.1.6.13.1.3 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_ports.txt"

    # Running processes
    echo -e "${YELLOW}[*] Enumerating running processes (1.3.6.1.2.1.25.4.2.1.2)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.2.1.25.4.2.1.2 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_processes.txt"

    # System information
    echo -e "${YELLOW}[*] Enumerating system information (1.3.6.1.2.1.1)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.2.1.1 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_sysinfo.txt"

    # Network interfaces
    echo -e "${YELLOW}[*] Enumerating network interfaces (1.3.6.1.2.1.2.2.1.2)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.2.1.2.2.1.2 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_interfaces.txt"

    # Routing table
    echo -e "${YELLOW}[*] Enumerating routing table (1.3.6.1.2.1.4.21.1.1)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.2.1.4.21.1.1 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_routes.txt"

    # Storage information
    echo -e "${YELLOW}[*] Enumerating storage (1.3.6.1.2.1.25.2.3.1.3)...${NC}"
    snmpwalk -v1 -c "$community" "$target" 1.3.6.1.2.1.25.2.3.1.3 2>&1 | tee "$OUTPUT_DIR/${target}_${community}_storage.txt"
}

# Generate summary report
generate_report() {
    local target="$1"
    local community="$2"

    echo -e "${BLUE}[*] Generating summary report...${NC}"

    cat > "$OUTPUT_DIR/${target}_${community}_REPORT.txt" << EOF
====================================
SNMP ENUMERATION REPORT
====================================
Target: $target
Community String: $community
SNMP Version: $VERSION
Scan Date: $(date)
====================================

SUMMARY OF FINDINGS:
EOF

    # Count users
    if [[ -f "$OUTPUT_DIR/${target}_${community}_users.txt" ]]; then
        user_count=$(grep -c "STRING:" "$OUTPUT_DIR/${target}_${community}_users.txt" 2>/dev/null || echo "0")
        echo "- User Accounts Found: $user_count" >> "$OUTPUT_DIR/${target}_${community}_REPORT.txt"
    fi

    # Count software
    if [[ -f "$OUTPUT_DIR/${target}_${community}_software.txt" ]]; then
        soft_count=$(grep -c "STRING:" "$OUTPUT_DIR/${target}_${community}_software.txt" 2>/dev/null || echo "0")
        echo "- Installed Software: $soft_count items" >> "$OUTPUT_DIR/${target}_${community}_REPORT.txt"
    fi

    # Count ports
    if [[ -f "$OUTPUT_DIR/${target}_${community}_ports.txt" ]]; then
        port_count=$(grep -c "INTEGER:" "$OUTPUT_DIR/${target}_${community}_ports.txt" 2>/dev/null || echo "0")
        echo "- Listening Ports: $port_count ports" >> "$OUTPUT_DIR/${target}_${community}_REPORT.txt"
    fi

    # Count processes
    if [[ -f "$OUTPUT_DIR/${target}_${community}_processes.txt" ]]; then
        proc_count=$(grep -c "STRING:" "$OUTPUT_DIR/${target}_${community}_processes.txt" 2>/dev/null || echo "0")
        echo "- Running Processes: $proc_count processes" >> "$OUTPUT_DIR/${target}_${community}_REPORT.txt"
    fi

    cat >> "$OUTPUT_DIR/${target}_${community}_REPORT.txt" << EOF

====================================
FILES GENERATED:
====================================
EOF

    ls -lh "$OUTPUT_DIR/${target}_${community}"* >> "$OUTPUT_DIR/${target}_${community}_REPORT.txt"

    echo -e "${GREEN}[+] Report saved to ${target}_${community}_REPORT.txt${NC}"
    cat "$OUTPUT_DIR/${target}_${community}_REPORT.txt"
}

# Main enumeration function
enumerate_target() {
    local target="$1"
    local community="$2"

    echo -e "${GREEN}"
    echo "===================================="
    echo "  Enumerating: $target"
    echo "  Community: $community"
    echo "===================================="
    echo -e "${NC}"

    if [[ "$QUICK" == true ]]; then
        basic_snmpwalk "$target" "$community" "$VERSION"
    elif [[ "$EXTENDED" == true ]]; then
        full_snmpwalk "$target" "$community" "$VERSION"
        extended_enum "$target" "$community" "$VERSION"
        specific_oids "$target" "$community" "$VERSION"
        generate_report "$target" "$community"
    elif [[ "$RUN_ALL" == true ]]; then
        basic_snmpwalk "$target" "$community" "$VERSION"
        full_snmpwalk "$target" "$community" "$VERSION"
        extended_enum "$target" "$community" "$VERSION"
        specific_oids "$target" "$community" "$VERSION"
        generate_report "$target" "$community"
    else
        basic_snmpwalk "$target" "$community" "$VERSION"
        specific_oids "$target" "$community" "$VERSION"
    fi
}

# Main execution
main() {
    check_dependencies

    # If community file provided, bruteforce first
    if [[ -n "$COMMUNITY_FILE" ]]; then
        if [[ -n "$TARGET" ]]; then
            bruteforce_community "$TARGET" "$COMMUNITY_FILE"
            # Use found communities
            if [[ -f "$OUTPUT_DIR/${TARGET}_found_communities.txt" ]]; then
                while IFS= read -r found_community; do
                    enumerate_target "$TARGET" "$found_community"
                done < "$OUTPUT_DIR/${TARGET}_found_communities.txt"
            fi
        elif [[ -n "$TARGETS_FILE" ]]; then
            while IFS= read -r target; do
                [[ -z "$target" || "$target" =~ ^# ]] && continue
                bruteforce_community "$target" "$COMMUNITY_FILE"
                if [[ -f "$OUTPUT_DIR/${target}_found_communities.txt" ]]; then
                    while IFS= read -r found_community; do
                        enumerate_target "$target" "$found_community"
                    done < "$OUTPUT_DIR/${target}_found_communities.txt"
                fi
            done < "$TARGETS_FILE"
        fi
    else
        # Use provided community string
        if [[ -n "$TARGET" ]]; then
            enumerate_target "$TARGET" "$COMMUNITY"
        elif [[ -n "$TARGETS_FILE" ]]; then
            while IFS= read -r target; do
                [[ -z "$target" || "$target" =~ ^# ]] && continue
                enumerate_target "$target" "$COMMUNITY"
            done < "$TARGETS_FILE"
        fi
    fi

    echo -e "${GREEN}"
    echo "===================================="
    echo "  ENUMERATION COMPLETE!"
    echo "  Results saved to: $OUTPUT_DIR"
    echo "===================================="
    echo -e "${NC}"
}

# Run main
main
