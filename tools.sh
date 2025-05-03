################## LINUX  #####################

wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_386
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
wget https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/impacket_linux_binaries.tar.gz
mkdir impacket
tar -xf impacket_linux_binaries.tar.gz -C impacket
rm impacket_linux_binaries.tar.gz

wget https://github.com/peass-ng/PEASS-ng/releases/download/20240526-eac1a3fa/linpeas_linux_amd64
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240526-eac1a3fa/linpeas_linux_386
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
wget https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl

wget https://raw.githubusercontent.com/KermitPurple96/rpcenum/master/rpcenum.sh
wget https://github.com/the-useless-one/pywerview/archive/refs/tags/v0.6.zip

# pivoting
https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_linux_amd64.tar.gz

# DNS dump
git clone https://github.com/dirkjanm/adidnsdump
git clone https://github.com/dirkjanm/krbrelayx

# spraying
git clone https://github.com/cube0x0/HashSpray.py
git clone https://github.com/Hackndo/sprayhound

# pkinit
git clone https://github.com/dirkjanm/PKINITtools
git clone https://github.com/grimlockx/ADCSKiller

#SCCM
wget https://github.com/garrettfoster13/sccmhunter/archive/refs/tags/v1.0.3.zip

################ WINDOWS ########################

wget https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/impacket_windows_binaries.zip
unzip impacket_windows_binaries.zip
mv dist impacket_ropnop
rm impacket_windows_binaries.zip

wget https://github.com/maaaaz/impacket-examples-windows/releases/download/v0.9.17/impacket-examples-windows-v0.9.17.zip
unzip impacket-examples-windows-v0.9.17.zip -d impacket

wget https://download.sysinternals.com/files/SysinternalsSuite.zip
unzip SysinternalsSuite.zip -d sysinternals
rm SysinternalsSuite.zip

git clone https://github.com/Flangvik/SharpCollection
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Certify.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpDump.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpRoast.exe
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe

wget https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip
unzip netcat-win32-1.11.zip
unzip netcat-win32-1.12.zip
rm netcat-win32-1.11.zip
rm netcat-win32-1.12.zip

git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack
git clone https://github.com/NetSPI/PowerUpSQL
git clone https://github.com/HarmJ0y/Misc-PowerShell
git clone https://github.com/antonioCoco/ConPtyShell
wget https://github.com/antonioCoco/ConPtyShell/releases/download/1.5/ConPtyShell.zip
wget https://github.com/samratashok/nishang/archive/refs/tags/v0.7.6.zip
git clone https://github.com/Kevin-Robertson/Invoke-TheHash
git clone https://github.com/leechristensen/Random
wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

## PRIV ESC
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240526-eac1a3fa/winPEASany.exe
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240526-eac1a3fa/winPEASx64.exe
wget https://github.com/peass-ng/PEASS-ng/releases/download/20240526-eac1a3fa/winPEASx86.exe

wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1
wget https://raw.githubusercontent.com/gladiatx0r/Powerless/master/Powerless.bat
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

# DUMP
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
wget https://github.com/gentilkiwi/kekeo/releases/download/2.2.0-20211214/kekeo.zip
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe

## AD
wget https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS.ps1
wget https://raw.githubusercontent.com/61106960/adPEAS/main/adPEAS-Light.ps1

#view
https://github.com/tevora-threat/SharpView/blob/master/Compiled/SharpView.exe
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1

## HOUNDS
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1
wget https://github.com/BloodHoundAD/SharpHound/releases/download/v2.5.1/SharpHound-v2.5.1.zip
https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe

## RCE
https://github.com/rasta-mouse/MiscTools
https://github.com/klezVirus/CheeseTools
wget https://raw.githubusercontent.com/HarmJ0y/Misc-PowerShell/master/Invoke-PsExec.ps1
wget https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1

# pivoting
https://sourceforge.net/projects/unix-utils/files/socat/1.7.3.2/socat-1.7.3.2-1-x86_64.zip/download
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_windows_amd64.zip

#pkinit
wget https://raw.githubusercontent.com/cfalta/PoshADCS/master/ADCS.ps1
wget https://github.com/bats3c/ADCSPwn/releases/download/ADCSPwn/ADCSPwn.exe

# SCCM
git clone https://github.com/PowerShellMafia/PowerSCCM
wget https://github.com/Mayyhem/SharpSCCM/releases/download/main/SharpSCCM.exe
