#!/bin/bash
# Download common CTF/OSCP tools for file transfer to targets
# Run from Kali or your attack machine

TOOLS_DIR="$(dirname "$0")"
cd "$TOOLS_DIR" || exit 1

echo "[*] Downloading tools to $TOOLS_DIR ..."

# === WINDOWS PRIVESC ===
echo "[+] Windows privesc tools..."

# PrintSpoofer (SeImpersonate -> SYSTEM)
curl -sLo PrintSpoofer64.exe "https://github.com/itm4n/PrintSpoofer/releases/latest/download/PrintSpoofer64.exe" && echo "  PrintSpoofer64.exe OK"

# GodPotato (Win10/11 potato)
curl -sLo GodPotato-NET4.exe "https://github.com/BeichenDream/GodPotato/releases/latest/download/GodPotato-NET4.exe" && echo "  GodPotato-NET4.exe OK"

# SharpUp (privesc audit)
curl -sLo SharpUp.exe "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/SharpUp.exe" && echo "  SharpUp.exe OK"

# Seatbelt (enumeration)
curl -sLo Seatbelt.exe "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Seatbelt.exe" && echo "  Seatbelt.exe OK"

# RunasCs (run as another user)
curl -sLo RunasCs.exe "https://github.com/antonioCoco/RunasCs/releases/latest/download/RunasCs.exe" && echo "  RunasCs.exe OK"

# winPEAS
curl -sLo winPEASx64.exe "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" && echo "  winPEASx64.exe OK"

# LaZagne (all credentials)
curl -sLo LaZagne.exe "https://github.com/AlessandroZ/LaZagne/releases/latest/download/LaZagne.exe" && echo "  LaZagne.exe OK"

# SharpHound (AD enumeration)
curl -sLo SharpHound.exe "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe" 2>/dev/null && echo "  SharpHound.exe OK"

# nc64.exe (netcat for windows)
curl -sLo nc64.exe "https://github.com/int0x33/nc.exe/raw/master/nc64.exe" && echo "  nc64.exe OK"

# chisel (port forwarding)
curl -sLo chisel_windows_amd64.exe "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_windows_amd64.gz" 2>/dev/null
if command -v gunzip &>/dev/null && [ -f chisel_windows_amd64.exe ]; then
    mv chisel_windows_amd64.exe chisel_windows_amd64.gz
    gunzip chisel_windows_amd64.gz 2>/dev/null
    mv chisel_windows_amd64 chisel_windows.exe 2>/dev/null
    echo "  chisel_windows.exe OK"
fi

# === LINUX PRIVESC ===
echo ""
echo "[+] Linux privesc tools..."

# linpeas
curl -sLo linpeas.sh "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh" && echo "  linpeas.sh OK"

# pspy64 (process monitor)
curl -sLo pspy64 "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" && echo "  pspy64 OK"

# chisel linux
curl -sLo chisel_linux_amd64.gz "https://github.com/jpillora/chisel/releases/latest/download/chisel_1.10.1_linux_amd64.gz" 2>/dev/null
if command -v gunzip &>/dev/null && [ -f chisel_linux_amd64.gz ]; then
    gunzip chisel_linux_amd64.gz 2>/dev/null
    mv chisel_linux_amd64 chisel_linux 2>/dev/null
    chmod +x chisel_linux
    echo "  chisel_linux OK"
fi

# linux-exploit-suggester
curl -sLo les.sh "https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh" && echo "  les.sh OK"

# linux-smart-enumeration
curl -sLo lse.sh "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" && echo "  lse.sh OK"

echo ""
echo "[*] Done! $(ls -1 *.exe *.sh *.elf 2>/dev/null | wc -l) tools downloaded."
echo "[*] Upload to target via: Serve tab in CTF-toolkit or python3 -m http.server"
