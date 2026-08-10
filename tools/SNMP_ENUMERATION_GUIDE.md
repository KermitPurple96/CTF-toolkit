# SNMP Enumeration Guide

## Overview

This guide covers SNMP (Simple Network Management Protocol) enumeration techniques commonly used in OSCP and penetration testing.

## Quick Reference

### Prerequisites

```bash
# Install required tools
sudo apt install snmp onesixtyone snmp-mibs-downloader

# Configure SNMP for better output
sudo sed -i 's/^mibs/#mibs/' /etc/snmp/snmp.conf
```

### Using the Automation Script

```bash
# Quick scan
./snmp_enum.sh -t 10.10.10.92 -q

# Full enumeration
./snmp_enum.sh -t 10.10.10.92 -a

# Bruteforce community strings
./snmp_enum.sh -t 10.10.10.92 -C /usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings.txt

# Extended enumeration with custom community
./snmp_enum.sh -t 10.10.10.92 -c private -e

# Multiple targets
./snmp_enum.sh -T targets.txt -a -o /tmp/snmp_results
```

## Manual Commands

### 1. Bruteforce Community Strings

```bash
# Single target
onesixtyone 10.10.10.92

# With custom wordlist
onesixtyone 10.10.10.92 -c /usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings.txt

# Network range
onesixtyone 192.168.1.0/24

# Multiple targets from file
onesixtyone -i targets.txt -c wordlist.txt
```

### 2. Basic SNMP Walk

```bash
# Default walk (starts at SNMPv2-SMI::mib-2)
snmpwalk -v2c -c public 10.10.10.92

# With timeout
snmpwalk -v1 -c public -t 10 10.10.10.92

# From root OID (recommended - don't miss anything)
snmpwalk -v2c -c public 10.10.10.92 1

# Faster with snmpbulkwalk
snmpbulkwalk -v2c -c public 10.10.10.92 1
```

### 3. Extended MIB Enumeration

⚠️ **Important for RCE:** NET-SNMP-EXTEND-MIB can be abused for RCE

```bash
snmpwalk -v2c -c public 10.10.10.92 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

Reference: https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/

### 4. Specific OID Enumeration

#### Windows User Accounts
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.4.1.77.1.2.25
```

#### Installed Software
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.25.6.3.1.2
```

#### Listening Ports (TCP)
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.6.13.1.3
```

#### Running Processes
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.25.4.2.1.2
```

#### System Information
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.1
```

#### Network Interfaces
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.2.2.1.2
```

#### Routing Table
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.4.21.1.1
```

#### Storage Information
```bash
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.25.2.3.1.3
```

### 5. SNMP Get (Specific Value)

```bash
snmpget -v1 -c public 10.10.10.92 [OID]
```

## Common OIDs Reference

| OID | Description |
|-----|-------------|
| 1.3.6.1.2.1.1 | System Information |
| 1.3.6.1.2.1.2.2.1.2 | Network Interfaces |
| 1.3.6.1.2.1.4.21.1.1 | Routing Table |
| 1.3.6.1.2.1.6.13.1.3 | TCP Listening Ports |
| 1.3.6.1.2.1.25.2.3.1.3 | Storage Information |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Processes |
| 1.3.6.1.2.1.25.6.3.1.2 | Installed Software |
| 1.3.6.1.4.1.77.1.2.25 | Windows User Accounts |
| NET-SNMP-EXTEND-MIB::nsExtendObjects | Extended Objects (RCE potential) |

## Common Community Strings

- public (most common)
- private
- manager
- community
- snmp
- mngt

## Wordlists

### SecLists Locations
```bash
find /usr/share/SecLists/Discovery/ -name *snmp*
```

- `/usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings.txt`
- `/usr/share/SecLists/Discovery/SNMP/snmp-onesixtyone.txt`

## Important Notes

### 1. SNMP MIBs Configuration

For clean output, comment out all lines in `/etc/snmp/snmp.conf`:

```bash
sudo nano /etc/snmp/snmp.conf
# Comment out: mibs :
```

Or install SNMP MIBs:
```bash
sudo apt install snmp-mibs-downloader
```

### 2. OID Structure

SNMP uses Object Identifiers (OIDs) in a tree structure:
- If no OID is provided, `snmpwalk` defaults to `SNMPv2-SMI::mib-2` (OID 2)
- **Always use OID `1`** to start from the root and avoid missing data
- OIDs never start from the absolute root by default

### 3. SNMP Versions

- **SNMPv1**: Basic, no encryption
- **SNMPv2c**: Community-based, no encryption
- **SNMPv3**: Supports authentication and encryption (rarely seen in CTFs)

### 4. Performance Tips

- Use `snmpbulkwalk` instead of `snmpwalk` for faster enumeration
- Increase timeout with `-t` flag for slow networks
- Use specific OIDs when you know what you're looking for

## OSCP Exam Tips

1. **Always try default community string first**: `public`
2. **Start with OID 1**: Don't miss data by using default OID 2
3. **Check for extended MIBs**: Potential RCE vector
4. **Look for user accounts**: Windows boxes often leak users via SNMP
5. **Enumerate running processes**: Can reveal installed software and services
6. **Check listening ports**: Map the attack surface
7. **Save all output**: You might need to grep through it later

## Example Workflow

```bash
# 1. Bruteforce community string
onesixtyone 10.10.10.92 -c /usr/share/SecLists/Discovery/SNMP/common-snmp-community-strings.txt

# 2. Full enumeration with found community (e.g., "public")
snmpbulkwalk -v2c -c public 10.10.10.92 1 > full_walk.txt

# 3. Check for extended MIBs (RCE potential)
snmpwalk -v2c -c public 10.10.10.92 NET-SNMP-EXTEND-MIB::nsExtendObjects

# 4. Enumerate users (Windows)
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.4.1.77.1.2.25

# 5. Enumerate software
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.25.6.3.1.2

# 6. Enumerate processes
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.25.4.2.1.2

# 7. Enumerate listening ports
snmpwalk -v1 -c public 10.10.10.92 1.3.6.1.2.1.6.13.1.3
```

## Troubleshooting

### Timeout Errors
```bash
# Increase timeout
snmpwalk -v2c -c public -t 30 10.10.10.92
```

### No Response
- Check if UDP port 161 is open: `nmap -sU -p 161 10.10.10.92`
- Try different SNMP versions: `-v1`, `-v2c`
- Verify community string with `onesixtyone`

### "No Such Object" Errors
- Try different OID (use `1` for root)
- Community string might be wrong
- SNMP version mismatch

## References

- [SNMP RCE via Extended MIBs](https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/)
- [HackTricks SNMP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
- [SNMP OID Reference](http://www.oid-info.com/)
