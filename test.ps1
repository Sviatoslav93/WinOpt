# This script is designed to optimize Windows settings and install essential software.

# Initialize result log
$ResultLog = ""

# Function for enhanced logging
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    Switch ($Level) {
        'Info' { Write-Host -ForegroundColor DarkMagenta $logMessage }
        'Warning' { Write-Host -ForegroundColor Yellow $logMessage }
        'Error' { Write-Host -ForegroundColor Red $logMessage }
    }

    # Write to log file with retry logic
    $maxRetries = 5
    $retryDelay = 1
    $retry = 0
    $success = $false

    while (-not $success -and $retry -lt $maxRetries) {
        try {
            $stream = [System.IO.File]::AppendText("$logDir\WindowsSetupLog.txt")
            $stream.WriteLine($logMessage)
            $stream.Close()
            $success = $true
        }
        catch {
            $retry++
            if ($retry -lt $maxRetries) {
                Start-Sleep -Seconds $retryDelay
            }
        }
        finally {
            if ($stream) {
                $stream.Dispose()
            }
        }
    }
}

# Function to test and wait for network connectivity
function Test-NetworkConnectivity {
    param(
        [int]$MaxAttempts = 5,
        [int]$RetryDelaySeconds = 10
    )

    Write-Log "Testing network connectivity..." -Level Info
    $attempt = 1

    while ($attempt -le $MaxAttempts) {
        if (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet) {
            Write-Log "Network connectivity verified" -Level Info
            return $true
        }

        Write-Log "Network connectivity test failed (Attempt $attempt of $MaxAttempts)" -Level Warning
        if ($attempt -lt $MaxAttempts) {
            Write-Log "Retrying in $RetryDelaySeconds seconds..." -Level Info
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        $attempt++
    }

    Write-Log "Network connectivity test failed after $MaxAttempts attempts" -Level Error
    return $false
}

# Function to validate prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level Info

    # Check internet connectivity with retry
    if (-not (Test-NetworkConnectivity)) {
        Write-Log "No internet connection detected after multiple attempts" -Level Error
        return $false
    }

    # Check available disk space
    $drive = Get-PSDrive C
    if ($drive.Free / 1GB -lt 10) {
        Write-Log "Less than 10GB free space available on C: drive" -Level Warning
    }

    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "Script must be run as Administrator" -Level Error
        return $false
    }

    return $true
}

# Function to backup system settings
function Backup-SystemSettings {
    $backupPath = Join-Path $logDir "SystemSettingsBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $backupPath -Force

    Write-Log "Creating system settings backup..." -Level Info

    try {
        reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" "$backupPath\explorer_settings.reg" /y
        reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "$backupPath\search_settings.reg" /y
        Write-Log "System settings backed up to $backupPath" -Level Info
    }
    catch {
        $errorMessage = "Failed to backup settings: {0}" -f $_.Exception.Message
        Write-Log $errorMessage -Level Error
    }
}

# Function to cleanup temporary files
function Remove-TempFiles {
    Write-Log "Cleaning up temporary files..." -Level Info
    $tempFolders = @(
        "$env:TEMP",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\Prefetch"
    )

    foreach ($folder in $tempFolders) {
        try {
            Remove-Item -Path "$folder\*" -Force -Recurse -ErrorAction SilentlyContinue
            Write-Log "Cleaned up $folder" -Level Info
        }
        catch {
            $errorMessage = "Failed to clean {0}: {1}" -f $folder, $_.Exception.Message
            Write-Log $errorMessage -Level Warning
        }
    }
}

# Function to ensure directory exists
function Ensure-DirectoryExists {
    param (
        [string]$Path,
        [string]$Description
    )

    if (-not (Test-Path -Path $Path)) {
        try {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            Write-Log "Created $Description directory at: $Path" -Level Info
        } catch {
            Write-Log "Failed to create $Description directory at $Path" -Level Error
            throw
        }
    } else {
        Write-Log "$Description directory exists at: $Path" -Level Info
    }
}

# Create required directories
$logDir = "C:\Support\Logs"
$powerShellProfileDir = "$env:USERPROFILE\Documents\PowerShell"
$nvConfigDir = "$env:LOCALAPPDATA\nvim"
$wslTempDir = "$env:TEMP\WSLInstall"
$customConfigDir = "C:\Support\Config"

# Ensure all required directories exist
$directories = @(
    @{Path = $logDir; Description = "Logs"},
    @{Path = $powerShellProfileDir; Description = "PowerShell profile"},
    @{Path = $customConfigDir; Description = "Custom configuration"},
    @{Path = $wslTempDir; Description = "WSL installation temporary"},
    @{Path = "$env:LOCALAPPDATA\nvim-data"; Description = "Neovim data"}
)

foreach ($dir in $directories) {
    Ensure-DirectoryExists -Path $dir.Path -Description $dir.Description
}

Start-Transcript -Append -Path "$logDir\WindowsSetupLog.txt"

# Add legacy boot menu.
Write-Host -ForegroundColor DarkMagenta "Adding legacy boot menu."
bcdedit /set "{current}" bootmenupolicy legacy

# Set limit for restore points to 5%.
Write-Host -ForegroundColor DarkMagenta "Set limit for restore points to 5%."
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%

# Turning on system restore on C:\
Write-Host -ForegroundColor DarkMagenta "Turning on system restore on C:\"
Enable-ComputerRestore -Drive "$env:SystemDrive"

# Set system restore point creation frequency to 0 (disabled).
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F

# Validate prerequisites before proceeding
if (-not (Test-Prerequisites)) {
    Write-Log "Prerequisites check failed. Exiting script." -Level Error
    exit 1
}

# Backup current system settings
Backup-SystemSettings

# Create a restore point before applying the script
try {
    Write-Log "Creating system restore point..." -Level Info
    Checkpoint-Computer -Description "Before applying the script" -RestorePointType "MODIFY_SETTINGS"
    Write-Log "System restore point created successfully" -Level Info
}
    catch {
        Write-Log "Failed to create system restore point: $($_.Exception.Message)" -Level Error
        $continue = Read-Host "Do you want to continue without a restore point? (y/n)"
        if ($continue -ne 'y') {
            Write-Log "Script execution cancelled by user" -Level Info
            exit
        }
    }# Load configuration files
function Get-ConfigurationFile {
    param (
        [string]$ConfigName
    )
    # Get the directory where the script is located
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }

    # Config folder is in the same directory as the script
    $configPath = Join-Path $scriptDir "config\$ConfigName.json"

    if (Test-Path $configPath) {
        return Get-Content $configPath | ConvertFrom-Json
    }
    Write-Log "Configuration file not found: $configPath" -Level Error
    return $null
}

# appx packages removal
Write-Host -ForegroundColor DarkMagenta "Removing bloatware AppX packages"
$bloatwareConfig = Get-ConfigurationFile -ConfigName "bloatware"
if ($bloatwareConfig) {
    $Bloatware = $bloatwareConfig.bloatwarePackages | ForEach-Object { $_.name }
}

Write-Log "Starting bloatware removal..." -Level Info

$totalBloatware = $Bloatware.Count
$current = 0

foreach ($Bloat in $Bloatware) {
    $current++
    $percentComplete = [math]::Round(($current / $totalBloatware) * 100)
    Write-Progress -Activity "Removing bloatware" -Status "Removing $Bloat" -PercentComplete $percentComplete

    try {
        Get-AppxPackage -Name $Bloat -ErrorAction SilentlyContinue | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat -ErrorAction SilentlyContinue | Remove-AppxProvisionedPackage -Online
        Write-Log "Successfully removed $Bloat" -Level Info
    }
    catch {
        $errorMessage = "Failed to remove {0}: {1}" -f $Bloat, $_.Exception.Message
        Write-Log $errorMessage -Level Warning
    }
}

Write-Host  -ForegroundColor DarkMagenta "Завершуємо видаляти сміттєві застосунки"
$ResultLog += "`r`n" + "`r`n" + "Видалення сміттєвих застосунків завершено."

# Load system settings configuration
$systemConfig = Get-ConfigurationFile -ConfigName "system-settings"

# Configure power plan
Write-Host -ForegroundColor DarkMagenta "Configuring power plan"
powercfg.exe -change -monitor-timeout-ac $systemConfig.powerPlan.monitor.timeoutAC
powercfg.exe -change -monitor-timeout-dc $systemConfig.powerPlan.monitor.timeoutDC
powercfg.exe -change -disk-timeout-ac $systemConfig.powerPlan.disk.timeoutAC
powercfg.exe -change -disk-timeout-dc $systemConfig.powerPlan.disk.timeoutDC
powercfg.exe -change -standby-timeout-ac $systemConfig.powerPlan.standby.timeoutAC
powercfg.exe -change -standby-timeout-dc $systemConfig.powerPlan.standby.timeoutDC
powercfg.exe -change -hibernate-timeout-ac $systemConfig.powerPlan.hibernate.timeoutAC
powercfg.exe -change -hibernate-timeout-dc $systemConfig.powerPlan.hibernate.timeoutDC

# Setting up account security rules:
# This will prevent direct hacking of the PC using BruteForce.
Write-Host -ForegroundColor DarkMagenta "Set up account security rules"
Write-Host -ForegroundColor DarkMagenta "Configuring account lockout settings:"
net accounts /lockoutthreshold:$($systemConfig.security.accountLockout.threshold)
net accounts /lockoutduration:$($systemConfig.security.accountLockout.duration)
net accounts /lockoutwindow:$($systemConfig.security.accountLockout.window)

# Enabling simultaneous startup at user logon
Write-Host -ForegroundColor DarkMagenta "Enabling simultaneous startup at user logon"
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /V "Startupdelayinmsec" /T REG_DWORD /D 0 /F

# Show file extensions in Explorer
Write-Host -ForegroundColor DarkMagenta "Enabling file extensions in Explorer"
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "HideFileExt" /T REG_DWORD /D 0 /F

# Show hidden files in Explorer
Write-Host -ForegroundColor DarkMagenta "Showing hidden files in Explorer"
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "Hidden" /T REG_DWORD /D 1 /F

# Disable web search in Windows Search
Write-Host -ForegroundColor DarkMagenta "Disabling web search in Windows Search"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "BingSearchEnabled" /T REG_DWORD /D 0 /F
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /V "CortanaConsent" /T REG_DWORD /D 0 /F
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "DisableWebSearch" /T REG_DWORD /D 1 /F
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V "ConnectedSearchUseWeb" /T REG_DWORD /D 0 /F

# Configure Oh My Posh for PowerShell 7
Write-Log "Configuring Oh My Posh for PowerShell 7..." -Level Info

try {
    # Install PowerShell 7
    winget install --id Microsoft.PowerShell --source winget

    # Create PowerShell profile
    $profilePath = Join-Path $powerShellProfileDir "Microsoft.PowerShell_profile.ps1"
    if (!(Test-Path $profilePath)) {
        New-Item -ItemType File -Path $profilePath -Force
        Write-Log "Created new PowerShell profile at: $profilePath" -Level Info
    } else {
        Write-Log "PowerShell profile already exists at: $profilePath" -Level Info
    }
}
catch {
    Write-Log "Failed to configure Oh My Posh for PowerShell 7: $($_.Exception.Message)" -Level Error
}

try {
    Add-Content $profilePath 'oh-my-posh init pwsh --config \"$(scoop prefix oh-my-posh)\\themes\\pararussel.omparadox.omp.json\" | Invoke-Expression'
    Write-Log "Added Oh My Posh configuration to PowerShell profile" -Level Info

    # Install Oh My Posh
    Write-Log "Installing Oh My Posh..." -Level Info
    winget install JanDeDobbeleer.OhMyPosh --source winget --scope user --force
    Write-Log "Oh My Posh installation completed" -Level Info
} catch {
    Write-Log "Failed to configure Oh My Posh: $($_.Exception.Message)" -Level Error
}

# Install Scoop
Write-Host -ForegroundColor Green "Installing Scoop package manager"
try {
    # Since Scoop should not be installed as admin, we need to run it as the current user
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        Write-Log "Running Scoop installation as administrator is not recommended. Creating a scheduled task to install as user..." -Level Warning

        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser; irm get.scoop.sh | iex`""
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Limited
        $task = New-ScheduledTask -Action $action -Principal $principal
        Register-ScheduledTask -TaskName "Install Scoop" -InputObject $task | Out-Null
        Start-ScheduledTask -TaskName "Install Scoop"
        Start-Sleep -Seconds 30  # Give some time for the installation to complete
        Unregister-ScheduledTask -TaskName "Install Scoop" -Confirm:$false
    } else {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
        Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
    }

    # Verify Scoop installation
    if (!(Get-Command scoop -ErrorAction SilentlyContinue)) {
        throw "Scoop installation failed or not in PATH"
    }
    Write-Log "Scoop installed successfully" -Level Info
} catch {
    Write-Log "Failed to install Scoop: $($_.Exception.Message)" -Level Error
}

# Function to verify software installation
function Test-SoftwareInstallation {
    param([string]$SoftwareName)

    try {
        Write-Log "$SoftwareName successfully installed" -Level Info
        return $true
    }
    catch {
        Write-Log "$SoftwareName installation failed or not in PATH" -Level Error
        return $false
    }
}

# Install tools with Scoop
Write-Log "Installing tools with Scoop" -Level Info
try {
    scoop bucket add main
    scoop bucket add extras
    scoop bucket add versions
    scoop bucket add nerd-fonts
    Write-Log "Successfully added Scoop buckets" -Level Info
}
catch {
    $errorMessage = "Failed to add Scoop buckets: {0}" -f $_.Exception.Message
    Write-Log $errorMessage -Level Error
}

scoop install JetBrains-Mono
scoop install JetBrainsMono-NF-Mono

# Function to install software with progress and verification
function Install-SoftwarePackage {
    param(
        [string]$Name,
        [string]$Category,
        [string]$Installer = "scoop"
    )

    Write-Log "Installing $Name ($Category)..." -Level Info

    try {
        switch ($Installer) {
            "scoop" {
                scoop install $Name
                if (Test-SoftwareInstallation $Name) {
                    Write-Log "$Name installed successfully" -Level Info
                    return $true
                }
            }
            "winget" {
                winget install --id $Name --source winget --accept-source-agreements --accept-package-agreements
                Start-Sleep -Seconds 2  # Give time for installation to complete
                if (Get-Command $Name -ErrorAction SilentlyContinue) {
                    Write-Log "$Name installed successfully" -Level Info
                    return $true
                }
            }
        }
    }
    catch {
        Write-Log "Failed to install $Name : $($_.Exception.Message)" -Level Error
        return $false
    }

    Write-Log "Installation verification failed for $Name" -Level Warning
    return $false
}

# Read software packages from config
$toolsConfig = Get-ConfigurationFile -ConfigName "essential-tools"
$essentialTools = @()
$essentialTools += $toolsConfig.developmentTools
$essentialTools += $toolsConfig.utilities
$essentialTools += $toolsConfig.browsers
$essentialTools += $toolsConfig.development
$essentialTools += $toolsConfig.productivity

Write-Log "Installing essential tools..." -Level Info
$totalTools = $essentialTools.Count
$current = 0
$failedInstallations = @()

foreach ($tool in $essentialTools) {
    $current++
    $percentComplete = [math]::Round(($current / $totalTools) * 100)
    Write-Progress -Activity "Installing Essential Tools" -Status "Installing $($tool.Name)" -PercentComplete $percentComplete

    if (-not (Install-SoftwarePackage -Name $tool.Name -Category $tool.Category)) {
        $failedInstallations += $tool.Name
    }
}

# Install development tools
Write-Host -ForegroundColor Green "Installing development tools"
scoop install cmake
scoop install curl
scoop install ffmpeg
scoop install jq

# Install terminal emulators
Write-Host -ForegroundColor Green "Installing terminal emulators"
scoop install warp-terminal
scoop install wezterm

# Install additional utilities
Write-Host -ForegroundColor Green "Installing additional utilities"
scoop install bottom fzf fd ripgrep bat less ffmpeg pandoc poppler imagemagick resvg zoxide

# Install Yazi (a file manager)
Write-Host -ForegroundColor Green "Installing Yazi file manager"
scoop install yazi-nightly
$FilePath = "$env:USERPROFILE\scoop\apps\git\current\usr\bin\file.exe"
$env:YAZI_FILE_ONE = $FilePath


# Configure Neovim with custom config
Write-Host -ForegroundColor Green "Installing Neovim with custom configuration"
scoop install neovim-nightly
$nvConfigDir = "$env:LOCALAPPDATA\nvim"
if (Test-Path $nvConfigDir) { Remove-Item $nvConfigDir -Recurse -Force }
git clone https://github.com/Sviatoslav93/nvim-config $nvConfigDir

# Creating a weekly restore point task
$taskName = "Weekly restore point"
$taskDescription = "Creating a weekly restore point on Sunday at 11:11 AM"
$triggerTime = "11:11"
$checkpointDescription = "Weekly restore point"

# Create an action
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -Command `"Checkpoint-Computer -Description '$checkpointDescription' -RestorePointType 'MODIFY_SETTINGS'`""

# Create a trigger (weekly on Sunday at 11:11 AM)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $triggerTime

# Optionally: Specify user and password parameters
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Create the task
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription

# Register the task
Register-ScheduledTask -TaskName $taskName -InputObject $task

Write-Host  -ForegroundColor DarkMagenta "Завдання '$taskName' було успішно створено."

# Creating a task to run SuperF4 at user logon
$taskName = "SuperF4"
$taskDescription = "Автоматично запускає SuperF4"
$programPath = "$env:APPDATA\SuperF4\SuperF4.exe"

# Create the action
$action = New-ScheduledTaskAction -Execute $programPath

# Create a trigger for logon
$trigger = New-ScheduledTaskTrigger -AtLogOn

# Create a principal for the task without storing a password
$principal = New-ScheduledTaskPrincipal -UserId $env:UserName -LogonType Interactive -RunLevel Highest

# Create the settings for the task
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DisallowHardTerminate

# Create the task
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription

# Register the task with the option 'run only when user is logged on'
Register-ScheduledTask -TaskName $taskName -InputObject $task -User $env:UserName -RunLevel Highest

Write-Host  -ForegroundColor DarkMagenta "Завдання '$taskName' було успішно створено."

# Clean up temporary files
Remove-TempFiles

# Function to verify Windows features
function Test-WindowsFeatures {
    param(
        [string[]]$RequiredFeatures
    )

    $failedFeatures = @()
    foreach ($feature in $RequiredFeatures) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName $feature).State
            if ($state -ne 'Enabled') {
                $failedFeatures += $feature
                Write-Log "Windows feature '$feature' is not enabled" -Level Warning
            }
            else {
                Write-Log "Windows feature '$feature' is enabled" -Level Info
            }
        }
        catch {
            $errorMessage = "Failed to check Windows feature '{0}': {1}" -f $feature, $_.Exception.Message
            Write-Log $errorMessage -Level Error
            $failedFeatures += $feature
        }
    }
    return $failedFeatures
}

# Function to verify system configuration
function Test-SystemConfiguration {
    $results = @{
        Success  = $true
        Messages = @()
    }

    # Check power settings
    try {
        $powerPlan = powercfg /GetActiveScheme
        if ($powerPlan -notmatch 'Power Scheme GUID: ') {
            $results.Messages += "Power plan configuration might be incorrect"
            $results.Success = $false
        }
    }
    catch {
        $results.Messages += "Failed to verify power settings: $_"
        $results.Success = $false
    }

    # Check system restore configuration
    try {
        $restoreEnabled = (vssadmin list shadowstorage | Select-String -Pattern "Maximum Size:.*5%")
        if (-not $restoreEnabled) {
            $results.Messages += "System restore might not be configured correctly"
            $results.Success = $false
        }
    }
    catch {
        $results.Messages += "Failed to verify system restore settings: $_"
        $results.Success = $false
    }

    return $results
}

# Final system verification
Write-Log "Performing final system verification..." -Level Info

# Verify critical settings
$verificationChecks = @(
    @{ Test = { Test-Path "$env:USERPROFILE\scoop" }; Message = "Scoop installation" },
    @{ Test = { Test-Path "$env:LOCALAPPDATA\nvim" }; Message = "Neovim configuration" },
    @{ Test = { Get-Command docker -ErrorAction SilentlyContinue }; Message = "Docker installation" },
    @{ Test = { Test-Path "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" }; Message = "PowerShell profile" },
    @{ Test = { Get-Command wsl -ErrorAction SilentlyContinue }; Message = "WSL installation" }
)

# Verify Windows features
$requiredFeatures = @(
    "Microsoft-Windows-Subsystem-Linux",
    "VirtualMachinePlatform",
    "Containers-DisposableClientVM",
    "Microsoft-Hyper-V"
)

$failedFeatures = Test-WindowsFeatures -RequiredFeatures $requiredFeatures
if ($failedFeatures.Count -gt 0) {
    Write-Log "Some Windows features are not properly enabled: $($failedFeatures -join ', ')" -Level Warning
}

# Verify system configuration
$sysConfig = Test-SystemConfiguration
if (-not $sysConfig.Success) {
    foreach ($msg in $sysConfig.Messages) {
        Write-Log $msg -Level Warning
    }
}

$failedChecks = @()
foreach ($check in $verificationChecks) {
    if (-not (& $check.Test)) {
        $failedChecks += $check.Message
        Write-Log "Verification failed: $($check.Message)" -Level Warning
    }
    else {
        Write-Log "Verification passed: $($check.Message)" -Level Info
    }
}

# Stop creating the script log
Stop-Transcript

if ($failedChecks.Count -gt 0) {
    Write-Log "Some verifications failed. Please check the log file for details." -Level Warning
    Write-Log "Failed checks: $($failedChecks -join ', ')" -Level Warning
    $restart = Read-Host "Do you want to restart the computer anyway? (y/n)"
    if ($restart -ne 'y') {
        Write-Log "Restart cancelled by user" -Level Info
        exit
    }
}

Write-Log "Windows configuration completed successfully" -Level Info
Write-Log "System will restart in 10 seconds..." -Level Info
Start-Sleep -s 5
Write-Log "Restarting computer..." -Level Info
Start-Sleep -s 5
Restart-Computer
