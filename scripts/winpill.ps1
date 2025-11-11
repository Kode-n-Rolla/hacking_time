#Requires -RunAsAdministrator

# Disclaimer
Write-Host "Extended Pillaging Script for Penetration Testing" -ForegroundColor Yellow
Write-Host "This script is intended for authorized penetration testing only." -ForegroundColor Yellow
Write-Host "Ensure you have explicit permission to run this on the target system." -ForegroundColor Yellow
Write-Host "Unauthorized use may violate laws and regulations." -ForegroundColor Yellow
Write-Host ""

# Check for administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Error: This script requires administrative privileges." -ForegroundColor Red
    exit
}

# Initialize script variables
$computerName = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$exportFolder = "C:\Pillaging_$computerName_$timestamp"
New-Item -ItemType Directory -Path $exportFolder -Force | Out-Null
Write-Host "Data will be exported to: $exportFolder" -ForegroundColor Green
Write-Host "Started at: $timestamp" -ForegroundColor Green
Write-Host ""

# Function to write output and export to CSV
function Write-And-Export {
    param (
        [string]$Section,
        [object]$Data,
        [string]$FileName,
        [switch]$NoDisplay
    )
    if (-not $NoDisplay) {
        Write-Host "=== $Section ===" -ForegroundColor Cyan
        $Data | Format-Table -AutoSize
    }
    $Data | Export-Csv -Path "$exportFolder\$FileName.csv" -NoTypeInformation -ErrorAction SilentlyContinue
}

# Function to handle errors gracefully
function Invoke-Safe {
    param (
        [scriptblock]$ScriptBlock,
        [string]$ErrorMessage
    )
    try {
        & $ScriptBlock
    } catch {
        Write-Host "Error: $ErrorMessage - $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Function to check if a directory is writable by Everyone or Authenticated Users
function Test-WritableDirectory {
    param ([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -in @("Everyone", "BUILTIN\Users", "NT AUTHORITY\Authenticated Users") -and
                $access.FileSystemRights -match "Write|FullControl|Modify") {
                return $true
            }
        }
        return $false
    } catch {
        return $false
    }
}

# === System Information ===
Write-Host "Collecting System Information..." -ForegroundColor Yellow
$systemInfo = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime
Write-And-Export -Section "System Information" -Data $systemInfo -FileName "SystemInfo"

$hardwareInfo = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfProcessors
Write-And-Export -Section "Hardware Information" -Data $hardwareInfo -FileName "HardwareInfo"

$hotfixes = Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy
Write-And-Export -Section "Installed Hotfixes" -Data $hotfixes -FileName "Hotfixes"

$services = Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName
Write-And-Export -Section "Services" -Data $services -FileName "Services"

# === Scheduled Tasks (Excluding Microsoft Standard Tasks) ===
Write-Host "Collecting Scheduled Tasks (Excluding Microsoft Standard Tasks)..." -ForegroundColor Yellow
$scheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } | 
    Select-Object TaskName, TaskPath, State, @{Name="Actions";Expression={$_.Actions | ForEach-Object { $_.Execute }}}
Write-And-Export -Section "Non-Microsoft Scheduled Tasks" -Data $scheduledTasks -FileName "CustomScheduledTasks"

# === Event Logs ===
Write-Host "Collecting Recent Security Event Logs..." -ForegroundColor Yellow
$eventLogs = Get-WinEvent -LogName "Security" -MaxEvents 200 -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id, LevelDisplayName, Message
Write-And-Export -Section "Recent Security Event Logs" -Data $eventLogs -FileName "EventLogs"

# === BIOS Information ===
$biosInfo = Get-CimInstance -ClassName Win32_BIOS | Select-Object Manufacturer, Name, SerialNumber, Version
Write-And-Export -Section "BIOS Information" -Data $biosInfo -FileName "BIOSInfo"

# === User and Group Information ===
Write-Host "Collecting User and Group Information..." -ForegroundColor Yellow
$localUsers = Get-LocalUser | Select-Object Name, Enabled, Description, LastLogon, PasswordLastSet
Write-And-Export -Section "Local Users" -Data $localUsers -FileName "LocalUsers"

$admins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass, PrincipalSource
Write-And-Export -Section "Administrators" -Data $admins -FileName "Administrators"

$passwordPolicy = Invoke-Safe -ScriptBlock { net accounts } -ErrorMessage "Failed to retrieve password policy"
if ($passwordPolicy) {
    Write-Host "=== Password Policy ===" -ForegroundColor Cyan
    Write-Host $passwordPolicy
    $passwordPolicy | Out-File "$exportFolder\PasswordPolicy.txt"
}

# === Network Configuration ===
Write-Host "Collecting Network Information..." -ForegroundColor Yellow
$netConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer
Write-And-Export -Section "Network Configuration" -Data $netConfig -FileName "NetConfig"

$tcpConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
Write-And-Export -Section "Active TCP Connections" -Data $tcpConnections -FileName "TCPConnections"

$arpCache = Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State
Write-And-Export -Section "ARP Cache" -Data $arpCache -FileName "ARPCache"

$shares = Get-SmbShare | Select-Object Name, Path, Description
Write-And-Export -Section "Shared Folders" -Data $shares -FileName "Shares"

# === Firewall Rules (Enhanced with TCP/UDP, Port, and DisplayName) ===
Write-Host "Collecting Firewall Rules..." -ForegroundColor Yellow
$firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } | ForEach-Object {
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
    if ($portFilter) {
        $protocol = $portFilter.Protocol
        $localPort = $portFilter.LocalPort -join ", "
    } else {
        $protocol = "N/A"
        $localPort = "N/A"
    }
    [PSCustomObject]@{
        DisplayName = $_.DisplayName
        Protocol    = $protocol
        LocalPort   = $localPort
        Direction   = $_.Direction
        Action      = $_.Action
        Profile     = $_.Profile
    }
}
Write-And-Export -Section "Enabled Firewall Rules" -Data $firewallRules -FileName "FirewallRules"

# === Process and Software Analysis ===
Write-Host "Collecting Process and Software Information..." -ForegroundColor Yellow
$processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, 
    @{Name="UserName";Expression={$_.GetOwner().User}}
Write-And-Export -Section "Running Processes" -Data $processes -FileName "Processes"

$autoruns = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
Write-And-Export -Section "Autorun Entries" -Data $autoruns -FileName "Autoruns"

$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
Write-And-Export -Section "Installed Software" -Data $software -FileName "Software"

if ([Environment]::Is64BitOperatingSystem) {
    $software32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    Write-And-Export -Section "Installed Software (32-bit)" -Data $software32 -FileName "Software32"
}

# === Privilege Escalation Checks ===
Write-Host "Performing Privilege Escalation Checks..." -ForegroundColor Yellow
$envVars = Get-ChildItem Env: | Select-Object Name, Value
Write-And-Export -Section "Environment Variables" -Data $envVars -FileName "EnvVars"

$systemPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$pathDirs = $systemPath -split ";"
$writablePathDirs = $pathDirs | Where-Object { $_ -and (Test-WritableDirectory $_) }
if ($writablePathDirs) {
    Write-Host "=== Writable PATH Directories ===" -ForegroundColor Cyan
    $writablePathDirs | ForEach-Object { Write-Host $_ }
    $writablePathDirs | Out-File "$exportFolder\WritablePathDirs.txt"
}

# === Saved Credentials Check ===
Write-Host "Checking for Saved Credentials..." -ForegroundColor Yellow
$savedCreds = cmdkey /list
if ($savedCreds -match "Target:") {
    Write-Host "=== Saved Credentials Found ===" -ForegroundColor Cyan
    $savedCreds | Where-Object { $_ -match "Target:" } | ForEach-Object { Write-Host $_ }
    $savedCreds | Out-File "$exportFolder\SavedCredentials.txt"
} else {
    Write-Host "No saved credentials found." -ForegroundColor Green
}

# === AlwaysInstallElevated Check ===
Write-Host "Checking for AlwaysInstallElevated..." -ForegroundColor Yellow
$alwaysInstallElevatedHKLM = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$alwaysInstallElevatedHKCU = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
$alwaysInstallElevated = $false
if ($alwaysInstallElevatedHKLM -and $alwaysInstallElevatedHKLM.AlwaysInstallElevated -eq 1) {
    Write-Host "AlwaysInstallElevated is enabled in HKLM." -ForegroundColor Red
    $alwaysInstallElevated = $true
}
if ($alwaysInstallElevatedHKCU -and $alwaysInstallElevatedHKCU.AlwaysInstallElevated -eq 1) {
    Write-Host "AlwaysInstallElevated is enabled in HKCU." -ForegroundColor Red
    $alwaysInstallElevated = $true
}

# === Sensitive File Search ===
Write-Host "Searching for Sensitive Files..." -ForegroundColor Yellow
$sensitiveFiles = @()
$drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root
foreach ($drive in $drives) {
    Get-ChildItem -Path $drive -Recurse -File -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -match "(password|cred|secret|key|config)\.(txt|doc|docx|xml|ini|conf)$" } | 
        ForEach-Object { 
            $sensitiveFiles += [PSCustomObject]@{
                Name = $_.Name
                FullPath = $_.FullName
                LastWriteTime = $_.LastWriteTime
                SizeKB = [math]::Round($_.Length / 1KB, 2)
            }
        }
}
if ($sensitiveFiles) {
    Write-And-Export -Section "Potentially Sensitive Files" -Data $sensitiveFiles -FileName "SensitiveFiles"
}

# === Interesting Files by Extension ===
Write-Host "Searching for Interesting Files by Extension..." -ForegroundColor Yellow
Write-Host "This may take a while depending on the number of files and directories." -ForegroundColor Yellow

# Define the list of file extensions to search for
$extensions = @(
    # Documents
    "*.docx", "*.doc", "*.pdf", "*.txt", "*.rtf", "*.odt",
    # Spreadsheets
    "*.xlsx", "*.xls", "*.csv", "*.ods",
    # Presentations
    "*.pptx", "*.ppt", "*.odp",
    # Databases
    "*.mdb", "*.accdb", "*.sqlite", "*.sqlite3", "*.db", "*.sql", "*.mdf", "*.ldf", "*.dbf", "*.fdb",
    # Configurations
    "*.conf", "*.ini", "*.xml", "*.json", "*.yaml", "*.cfg", "*.properties", "*.config", "*.env", "*.cnf",
    # Scripts and Source Code
    "*.ps1", "*.bat", "*.vbs", "*.sh", "*.cmd", "*.js", "*.py", "*.pl", 
    "*.c", "*.cpp", "*.java", "*.cs", "*.php", "*.go", "*.rb", "*.ts", "*.swift", "*.kt", "*.rs",
    # Backups
    "*.bak", "*.old", "*.backup",
    # Logs
    "*.log", "*.evt", "*.evtx",
    # Keys and Certificates
    "*.key", "*.pem", "*.wallet", "*.pfx", "*.cer", "*.crt", "*.p12", "*.jks",
    # Virtual Machines
    "*.vmdk", "*.vhd", "*.vhdx", "*.ova", "*.ovf", "*.qcow2",
    # Email
    "*.pst", "*.eml", "*.ost",
    # Archives
    "*.zip", "*.rar", "*.7z", "*.tar", "*.gz", "*.iso", "*.jar",
    # Memory Dumps
    "*.dmp", "*.dump", "*.mdmp", "*.hdmp",
    # Remote Desktop Files
    "*.rdp",
    # Password Managers
    "*.kdbx", "*.kwallet",
    # Mobile Apps
    "*.apk", "*.ipa",
    # VPN
    "*.ovpn", "*.pcf",
    # Packet Captures
    "*.pcap", "*.pcapng",
    # Security Tools
    "*.nessus", "*.burp"
)

# Define the directories to search in
$searchPaths = @("$env:SystemDrive\Users", "$env:SystemDrive\ProgramData")

# Initialize an array to hold the found files
$interestingFiles = @()

# Search for files in each specified path
foreach ($path in $searchPaths) {
    Write-Host "Searching in $path..." -ForegroundColor Green
    $files = Get-ChildItem -Path $path -Recurse -Include $extensions -File -ErrorAction SilentlyContinue | 
             Select-Object FullName, Length, LastWriteTime
    $interestingFiles += $files
}

# If interesting files are found, process and display
if ($interestingFiles) {
    # Sort files by LastWriteTime descending
    $interestingFiles = $interestingFiles | Sort-Object LastWriteTime -Descending

    # Create a summary grouped by file extension
    $summary = $interestingFiles | Group-Object { [System.IO.Path]::GetExtension($_.FullName) } | 
               Select-Object Name, Count

    # Display the summary in the console
    Write-Host "Summary of Interesting Files by Extension:" -ForegroundColor Cyan
    $summary | Format-Table -AutoSize

    # Display the first 20 files
    Write-Host "First 20 Interesting Files (sorted by LastWriteTime descending):" -ForegroundColor Cyan
    $interestingFiles | Select-Object -First 20 | Format-Table -Property FullName, LastWriteTime, Length -AutoSize

    # Export the full list to CSV
    $interestingFiles | Export-Csv -Path "$exportFolder\InterestingFiles.csv" -NoTypeInformation
    Write-Host "Full list of $($interestingFiles.Count) files exported to $exportFolder\InterestingFiles.csv" -ForegroundColor Green
} else {
    Write-Host "No interesting files found." -ForegroundColor Green
}

# === Summary of Key Findings ===
Write-Host "=== Summary of Key Findings ===" -ForegroundColor Cyan
$systemProcesses = $processes | Where-Object { $_.UserName -eq 'SYSTEM' }
Write-Host "Enabled Firewall Rules: $($firewallRules.Count)"
Write-Host "Non-Microsoft Scheduled Tasks: $($scheduledTasks.Count)"
Write-Host "Processes Running as SYSTEM: $($systemProcesses.Count)"
Write-Host "Writable PATH Directories: $($writablePathDirs.Count)"
Write-Host "Sensitive Files Found: $($sensitiveFiles.Count)"
Write-Host "Interesting Files Found: $($interestingFiles.Count)"
if ($savedCreds -match "Target:") {
    Write-Host "Saved Credentials Found: Yes" -ForegroundColor Red
} else {
    Write-Host "Saved Credentials Found: No" -ForegroundColor Green
}
if ($alwaysInstallElevated) {
    Write-Host "AlwaysInstallElevated Enabled: Yes" -ForegroundColor Red
} else {
    Write-Host "AlwaysInstallElevated Enabled: No" -ForegroundColor Green
}

# === Finalization ===
Write-Host "Pillaging complete. All data saved to $exportFolder" -ForegroundColor Green
Write-Host "Completed at: $(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')" -ForegroundColor Green
