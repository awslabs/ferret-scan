# Windows Troubleshooting Guide

## Overview

This guide provides solutions for common issues encountered when using Ferret Scan on Windows systems, including installation problems, runtime errors, and performance issues.

## Installation Issues

### Issue: "ferret-scan is not recognized as an internal or external command"

**Symptoms:**
- Command not found error when running `ferret-scan`
- PowerShell or Command Prompt cannot locate the executable

**Solutions:**

#### Check PATH Environment Variable
```powershell
# Check if ferret-scan is in PATH
$env:PATH -split ';' | Where-Object { Test-Path "$_\ferret-scan.exe" }

# If not found, check installation directory
Get-ChildItem -Path "C:\Program Files\ferret-scan" -Name "ferret-scan.exe" -ErrorAction SilentlyContinue
Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\ferret-scan" -Name "ferret-scan.exe" -ErrorAction SilentlyContinue
```

#### Add to PATH Manually
```powershell
# Add to user PATH (temporary - current session only)
$env:PATH += ";C:\Program Files\ferret-scan"

# Add to user PATH (permanent)
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
[Environment]::SetEnvironmentVariable("PATH", "$UserPath;C:\Program Files\ferret-scan", "User")

# Restart PowerShell/Command Prompt to apply changes
```

#### Verify Installation
```powershell
# Check if executable exists and is accessible
Test-Path "C:\Program Files\ferret-scan\ferret-scan.exe"
Get-Command ferret-scan -ErrorAction SilentlyContinue
```

### Issue: "Access is denied" during installation

**Symptoms:**
- Installation script fails with permission errors
- Cannot create directories in Program Files
- Registry access denied errors

**Solutions:**

#### Run as Administrator
```powershell
# Right-click PowerShell and select "Run as Administrator"
# Or use Start-Process
Start-Process PowerShell -Verb RunAs
```

#### Use User Installation
```powershell
# Install to user directory instead of system-wide
.\scripts\install-system-windows.ps1 -UserInstall
```

#### Check User Account Control (UAC)
```powershell
# Check UAC status
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

# Temporarily disable UAC (not recommended for production)
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
```

### Issue: PowerShell execution policy prevents script execution

**Symptoms:**
- "Execution of scripts is disabled on this system" error
- Installation script cannot run

**Solutions:**

#### Check Current Policy
```powershell
Get-ExecutionPolicy -List
```

#### Set Appropriate Policy
```powershell
# For current user only (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# For all users (requires Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Bypass for single script execution
PowerShell -ExecutionPolicy Bypass -File ".\scripts\install-system-windows.ps1"
```

## Runtime Issues

### Issue: Long path errors (paths > 260 characters)

**Symptoms:**
- "The specified path, file name, or both are too long" error
- Files in deep directory structures cannot be scanned

**Solutions:**

#### Enable Long Path Support (Windows 10 1607+)
```powershell
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Restart required
# Restart-Computer
```

#### Use UNC Path Format
```powershell
# Convert long paths to UNC format
ferret-scan scan "\\?\C:\very\long\path\to\directory"
```

#### Use Shorter Working Directory
```powershell
# Change to a shorter base directory
cd C:\
ferret-scan scan ".\long\path\relative\to\current\directory"
```

### Issue: "Access to the path is denied" during scanning

**Symptoms:**
- Permission errors when scanning system directories
- Cannot access certain files or folders

**Solutions:**

#### Run with Elevated Privileges
```powershell
# Run PowerShell as Administrator
Start-Process PowerShell -Verb RunAs

# Then run ferret-scan
ferret-scan scan "C:\Windows\System32"
```

#### Skip Inaccessible Files
```powershell
# Use error handling to continue on access errors
ferret-scan scan "C:\Windows" --continue-on-error
```

#### Check File Permissions
```powershell
# Check permissions on specific file/directory
Get-Acl "C:\path\to\file" | Format-List

# Grant read permissions if needed (as Administrator)
icacls "C:\path\to\file" /grant Users:R
```

### Issue: Antivirus software blocking execution

**Symptoms:**
- Ferret-scan executable deleted or quarantined
- Real-time protection alerts
- Scanning performance severely degraded

**Solutions:**

#### Add Antivirus Exclusions
```powershell
# Add exclusions for common antivirus software

# Windows Defender
Add-MpPreference -ExclusionPath "C:\Program Files\ferret-scan"
Add-MpPreference -ExclusionPath "$env:APPDATA\ferret-scan"
Add-MpPreference -ExclusionProcess "ferret-scan.exe"

# For other antivirus software, add exclusions through their management interface
```

#### Verify File Integrity
```powershell
# Check if executable is intact
Get-FileHash "C:\Program Files\ferret-scan\ferret-scan.exe" -Algorithm SHA256

# Re-download if hash doesn't match expected value
```

## Configuration Issues

### Issue: Configuration file not found or invalid

**Symptoms:**
- "Configuration file not found" errors
- YAML parsing errors
- Default settings not applied

**Solutions:**

#### Check Configuration Locations
```powershell
# Check configuration directory hierarchy
$ConfigDirs = @(
    $env:FERRET_CONFIG_DIR,
    "$env:APPDATA\ferret-scan",
    "$env:USERPROFILE\.ferret-scan",
    "$env:PROGRAMDATA\ferret-scan"
)

foreach ($dir in $ConfigDirs) {
    if ($dir -and (Test-Path $dir)) {
        Write-Host "Config directory found: $dir"
        Get-ChildItem $dir -Filter "*.yaml" -ErrorAction SilentlyContinue
    }
}
```

#### Validate Configuration File
```powershell
# Test configuration file syntax
ferret-scan scan . --config "$env:APPDATA\ferret-scan\config.yaml" --debug

# Use online YAML validator or PowerShell module
# Install-Module powershell-yaml
# $yaml = Get-Content "$env:APPDATA\ferret-scan\config.yaml" -Raw
# ConvertFrom-Yaml $yaml
```

#### Reset to Default Configuration
```powershell
# Copy default configuration
$InstallDir = "C:\Program Files\ferret-scan"
$ConfigDir = "$env:APPDATA\ferret-scan"

New-Item -ItemType Directory -Force -Path $ConfigDir
Copy-Item "$InstallDir\config.yaml" -Destination "$ConfigDir\config.yaml" -Force
```

### Issue: Environment variables not expanded

**Symptoms:**
- Paths with %APPDATA%, %USERPROFILE% not working
- Configuration references literal environment variable names

**Solutions:**

#### Use PowerShell Environment Variables
```powershell
# Instead of %APPDATA%, use $env:APPDATA in PowerShell
ferret-scan scan "$env:USERPROFILE\Documents"

# Or use cmd-style expansion
cmd /c "ferret-scan scan %USERPROFILE%\Documents"
```

#### Update Configuration File
```yaml
# Use forward slashes or escaped backslashes in YAML
platform:
  windows:
    temp_dir: "C:/Windows/Temp/ferret-scan"
    # Or use double backslashes
    config_dir: "C:\\Users\\%USERNAME%\\AppData\\Roaming\\ferret-scan"
```

## Performance Issues

### Issue: Slow scanning performance on Windows

**Symptoms:**
- Scanning takes significantly longer than expected
- High CPU or memory usage
- System becomes unresponsive during scans

**Solutions:**

#### Optimize Scanning Parameters
```powershell
# Reduce confidence levels to scan faster
ferret-scan scan . --confidence high --format json

# Disable preprocessors for faster scanning
ferret-scan scan . --enable-preprocessors=false

# Scan specific file types only
ferret-scan scan . --checks CREDIT_CARD,SSN --format text
```

#### Exclude Large Directories
```powershell
# Create suppressions file to exclude large directories
@"
# Suppress large system directories
- path: "C:/Windows/**"
  reason: "System directory - exclude from scans"
- path: "**/node_modules/**"
  reason: "Package dependencies - exclude from scans"
- path: "**/.git/**"
  reason: "Git repository data - exclude from scans"
"@ | Out-File "$env:APPDATA\ferret-scan\suppressions.yaml" -Encoding UTF8
```

#### Monitor Resource Usage
```powershell
# Monitor ferret-scan process
Get-Process ferret-scan | Select-Object Name, CPU, WorkingSet, VirtualMemorySize

# Use Performance Monitor for detailed analysis
# perfmon.exe
```

### Issue: Memory usage grows during large scans

**Symptoms:**
- Increasing memory consumption over time
- Out of memory errors on large directories
- System swap file usage increases

**Solutions:**

#### Process Files in Batches
```powershell
# Scan directories in smaller batches
$Directories = Get-ChildItem "C:\LargeDirectory" -Directory
foreach ($dir in $Directories) {
    ferret-scan scan $dir.FullName --format json --output "results_$($dir.Name).json"
    Start-Sleep 1  # Brief pause between scans
}
```

#### Increase Virtual Memory
```powershell
# Check current virtual memory settings
Get-WmiObject -Class Win32_PageFileUsage | Select-Object Name, AllocatedBaseSize, CurrentUsage

# Increase page file size through System Properties > Advanced > Performance > Settings > Advanced > Virtual Memory
```

## Network and Connectivity Issues

### Issue: Web UI not accessible

**Symptoms:**
- Cannot connect to http://localhost:8080
- "Connection refused" or "Site can't be reached" errors
- Web server fails to start

**Solutions:**

#### Check Port Availability
```powershell
# Check if port 8080 is in use
Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue

# Use alternative port
ferret-scan web --port 8081
```

#### Check Windows Firewall
```powershell
# Check firewall rules
Get-NetFirewallRule -DisplayName "*ferret*" -ErrorAction SilentlyContinue

# Add firewall rule if needed (as Administrator)
New-NetFirewallRule -DisplayName "Ferret Scan Web UI" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
```

#### Test Local Connectivity
```powershell
# Test if web server is running
Test-NetConnection -ComputerName localhost -Port 8080

# Check with curl or Invoke-WebRequest
Invoke-WebRequest -Uri "http://localhost:8080" -UseBasicParsing
```

## File System Issues

### Issue: UNC path handling problems

**Symptoms:**
- Cannot scan network drives
- "Path not found" errors for \\server\share paths
- Authentication failures for network resources

**Solutions:**

#### Map Network Drives
```powershell
# Map UNC path to drive letter
New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\server\share" -Credential (Get-Credential)

# Scan mapped drive
ferret-scan scan "Z:\" --recursive
```

#### Use Full UNC Paths
```powershell
# Ensure proper UNC path format
ferret-scan scan "\\server\share\directory" --format json

# Use IP address if DNS resolution fails
ferret-scan scan "\\192.168.1.100\share\directory"
```

#### Authenticate to Network Resource
```powershell
# Store credentials for network access
cmdkey /add:server /user:domain\username /pass:password

# Or use net use command
net use \\server\share /user:domain\username password
```

### Issue: Case sensitivity problems

**Symptoms:**
- Inconsistent results when scanning files with different case
- Configuration files not found due to case mismatch

**Solutions:**

#### Use Consistent Case
```powershell
# Windows is case-insensitive, but be consistent
ferret-scan scan "C:\Users\Username\Documents"  # Preferred
# Instead of: ferret-scan scan "c:\users\username\documents"
```

#### Check File System Type
```powershell
# Check if file system supports case sensitivity (rare on Windows)
fsutil.exe file queryCaseSensitiveInfo "C:\"
```

## Integration Issues

### Issue: Git pre-commit hook failures

**Symptoms:**
- Pre-commit hooks fail to execute
- Git commits blocked unexpectedly
- Hook script errors

**Solutions:**

#### Verify Git Hook Installation
```powershell
# Check if hooks are installed
Get-ChildItem ".git\hooks" -Filter "*pre-commit*"

# Verify hook is executable
Get-Content ".git\hooks\pre-commit"
```

#### Test Hook Manually
```powershell
# Run pre-commit hook manually
.\.git\hooks\pre-commit

# Or test ferret-scan pre-commit mode
ferret-scan scan . --pre-commit-mode
```

#### Fix Hook Permissions
```powershell
# Ensure hook script has execute permissions
icacls ".git\hooks\pre-commit" /grant Users:RX
```

### Issue: PowerShell profile integration problems

**Symptoms:**
- Custom functions not available
- Tab completion not working
- Profile errors on startup

**Solutions:**

#### Check Profile Location
```powershell
# Check if profile exists
Test-Path $PROFILE
Get-Content $PROFILE

# Create profile if it doesn't exist
if (!(Test-Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force
}
```

#### Reload Profile
```powershell
# Reload PowerShell profile
. $PROFILE

# Or restart PowerShell session
```

#### Debug Profile Errors
```powershell
# Check for syntax errors in profile
powershell.exe -NoProfile -Command ". '$PROFILE'"
```

## Diagnostic Tools and Commands

### System Information Collection
```powershell
# Collect system information for troubleshooting
$DiagInfo = @{
    "OS Version" = (Get-WmiObject Win32_OperatingSystem).Caption
    "PowerShell Version" = $PSVersionTable.PSVersion
    "Ferret-scan Version" = & ferret-scan --version 2>$null
    "Installation Path" = (Get-Command ferret-scan -ErrorAction SilentlyContinue).Source
    "Config Directory" = "$env:APPDATA\ferret-scan"
    "PATH Variable" = $env:PATH -split ';' | Where-Object { $_ -like "*ferret*" }
    "Long Path Support" = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -ErrorAction SilentlyContinue).LongPathsEnabled
}

$DiagInfo | Format-Table -AutoSize
```

### Log Collection
```powershell
# Enable debug logging
$env:FERRET_DEBUG = "1"
ferret-scan scan . --debug --output debug-output.json 2>&1 | Tee-Object debug-log.txt

# Collect Windows Event Logs
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='ferret-scan'} -MaxEvents 50 -ErrorAction SilentlyContinue
```

### Performance Monitoring
```powershell
# Monitor ferret-scan performance
$Process = Start-Process ferret-scan -ArgumentList "scan", ".", "--format", "json" -PassThru
while (!$Process.HasExited) {
    $Process.Refresh()
    Write-Host "CPU: $($Process.TotalProcessorTime.TotalSeconds)s, Memory: $([math]::Round($Process.WorkingSet64/1MB, 2))MB"
    Start-Sleep 2
}
```

## Getting Help

### Documentation Resources
- [Windows Installation Guide](../WINDOWS_INSTALLATION.md)
- [Windows Usage Guide](../user-guides/README-Windows-Usage.md)
- [Configuration Reference](../configuration.md)

### Diagnostic Information to Include
When reporting issues, please include:

1. **System Information:**
   - Windows version and build number
   - PowerShell version
   - Ferret-scan version
   - Installation method used

2. **Error Details:**
   - Complete error messages
   - Steps to reproduce
   - Expected vs actual behavior

3. **Environment:**
   - Installation directory
   - Configuration file contents
   - Environment variables
   - Antivirus software in use

4. **Logs:**
   - Debug output (`--debug` flag)
   - Windows Event Logs
   - PowerShell error records

### Command to Generate Diagnostic Report
```powershell
# Generate comprehensive diagnostic report
$ReportPath = "$env:TEMP\ferret-scan-diagnostics.txt"

@"
Ferret Scan Windows Diagnostic Report
Generated: $(Get-Date)
=====================================

System Information:
$(Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber | Format-List | Out-String)

PowerShell Version:
$($PSVersionTable | Format-List | Out-String)

Ferret-scan Installation:
Installation Path: $((Get-Command ferret-scan -ErrorAction SilentlyContinue).Source)
Version: $(& ferret-scan --version 2>$null)

Configuration:
Config Directory: $env:APPDATA\ferret-scan
Config Exists: $(Test-Path "$env:APPDATA\ferret-scan\config.yaml")

Environment Variables:
FERRET_CONFIG_DIR: $env:FERRET_CONFIG_DIR
FERRET_DEBUG: $env:FERRET_DEBUG
PATH (ferret-scan entries): $($env:PATH -split ';' | Where-Object { $_ -like "*ferret*" } | Out-String)

System Settings:
Long Path Support: $((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -ErrorAction SilentlyContinue).LongPathsEnabled)
Execution Policy: $(Get-ExecutionPolicy)

Recent Errors:
$(Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -like "*ferret*" } | Format-List | Out-String)
"@ | Out-File $ReportPath -Encoding UTF8

Write-Host "Diagnostic report saved to: $ReportPath"
```

---

**Note**: This troubleshooting guide is specific to Windows systems. For general troubleshooting that applies to all platforms, see the main documentation.