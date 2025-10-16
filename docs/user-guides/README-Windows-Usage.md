# Windows Usage Guide

## Overview

This comprehensive guide covers using Ferret Scan on Windows systems, including command-line usage, PowerShell integration, GUI workflows, and Windows-specific features.

## Getting Started

### Basic Command Structure

Ferret Scan follows standard Windows command-line conventions:

```powershell
# Basic syntax
ferret-scan <command> [options]

# Common examples
ferret-scan scan C:\path\to\scan
ferret-scan web --port 8080
ferret-scan --help
```

### Windows Path Conventions

Ferret Scan supports all Windows path formats:

```powershell
# Absolute paths with drive letters
ferret-scan scan "C:\Users\Username\Documents"
ferret-scan scan "D:\Projects\MyApp"

# UNC paths (network shares)
ferret-scan scan "\\server\share\documents"
ferret-scan scan "\\192.168.1.100\shared\files"

# Relative paths
ferret-scan scan ".\current\directory"
ferret-scan scan "..\parent\directory"

# Environment variable expansion
ferret-scan scan "$env:USERPROFILE\Documents"
ferret-scan scan "$env:APPDATA\MyApp\data"
```

### Command Prompt vs PowerShell

#### Command Prompt (cmd.exe)
```batch
REM Use Windows-style environment variables
ferret-scan scan "%USERPROFILE%\Documents"
ferret-scan scan "%APPDATA%\MyApp"

REM Escape special characters with quotes
ferret-scan scan "C:\Program Files\MyApp"
```

#### PowerShell (Recommended)
```powershell
# Use PowerShell environment variables
ferret-scan scan "$env:USERPROFILE\Documents"
ferret-scan scan "$env:APPDATA\MyApp"

# PowerShell supports both forward and back slashes
ferret-scan scan "C:/Users/Username/Documents"
ferret-scan scan "C:\Users\Username\Documents"
```

## Common Usage Patterns

### Document Scanning

#### Scan User Documents
```powershell
# Scan user's Documents folder
ferret-scan scan "$env:USERPROFILE\Documents" --recursive --format json

# Scan specific document types
ferret-scan scan "$env:USERPROFILE\Documents" --recursive --format text | Where-Object { $_ -match "\.(docx?|pdf|xlsx?)$" }

# Scan with specific checks
ferret-scan scan "$env:USERPROFILE\Documents" --checks CREDIT_CARD,SSN,EMAIL --confidence high
```

#### Scan Downloads Directory
```powershell
# Quick scan of Downloads
ferret-scan scan "$env:USERPROFILE\Downloads" --format json --output downloads-scan.json

# Scan with preprocessors for document analysis
ferret-scan scan "$env:USERPROFILE\Downloads" --enable-preprocessors --format text
```

### Development Workflows

#### Project Directory Scanning
```powershell
# Scan current project
cd C:\Projects\MyApp
ferret-scan scan . --recursive --format gitlab-sast --output security-report.json

# Exclude common development directories
ferret-scan scan . --recursive --format json | Where-Object { $_.filename -notmatch "(node_modules|\.git|bin|obj)" }

# Pre-commit scanning
ferret-scan scan . --pre-commit-mode --format text
```

#### Source Code Analysis
```powershell
# Scan source files only
ferret-scan scan "C:\Projects\MyApp\src" --recursive --checks SECRETS,IP_ADDRESS --format json

# Scan configuration files
ferret-scan scan "C:\Projects\MyApp" --recursive --format text | Where-Object { $_.filename -match "\.(config|json|yaml|xml)$" }
```

### Enterprise Scenarios

#### Network Share Scanning
```powershell
# Authenticate to network share first
net use \\fileserver\documents /user:domain\username

# Scan network share
ferret-scan scan "\\fileserver\documents" --recursive --format json --output network-scan.json

# Batch scan multiple shares
$Shares = @("\\server1\share1", "\\server2\share2", "\\server3\share3")
foreach ($share in $Shares) {
    $outputFile = "scan-$(($share -replace '\\', '-').Trim('-')).json"
    ferret-scan scan $share --format json --output $outputFile
}
```

#### System Directory Analysis
```powershell
# Scan system directories (requires Administrator)
ferret-scan scan "C:\Windows\System32\config" --format json --confidence high

# Scan program files for embedded secrets
ferret-scan scan "C:\Program Files" --checks SECRETS --recursive --format text

# Scan temporary directories
ferret-scan scan "$env:TEMP" --recursive --format json --output temp-scan.json
```

## PowerShell Integration

### Custom Functions

Add these functions to your PowerShell profile (`$PROFILE`):

```powershell
# Quick scan function
function Invoke-FerretScan {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path,
        [string]$Format = "text",
        [string]$Checks = "all",
        [string]$Confidence = "high,medium",
        [switch]$Recursive,
        [string]$Output
    )
    
    $args = @("scan", $Path, "--format", $Format, "--checks", $Checks, "--confidence", $Confidence)
    
    if ($Recursive) { $args += "--recursive" }
    if ($Output) { $args += @("--output", $Output) }
    
    & ferret-scan @args
}

# Scan multiple directories
function Invoke-BatchScan {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Paths,
        [string]$Format = "json",
        [string]$OutputDir = ".\scan-results"
    )
    
    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force
    }
    
    foreach ($path in $Paths) {
        $safeName = ($path -replace '[\\/:*?"<>|]', '-').Trim('-')
        $outputFile = Join-Path $OutputDir "scan-$safeName.json"
        
        Write-Host "Scanning: $path" -ForegroundColor Green
        ferret-scan scan $path --format $Format --output $outputFile
    }
}

# Pipeline-friendly scan
function Scan-Files {
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string[]]$Files,
        [string]$Format = "json"
    )
    
    process {
        foreach ($file in $Files) {
            if (Test-Path $file) {
                ferret-scan scan $file --format $Format
            }
        }
    }
}

# Aliases for convenience
Set-Alias -Name fs -Value ferret-scan
Set-Alias -Name scan -Value Invoke-FerretScan
Set-Alias -Name bscan -Value Invoke-BatchScan
```

### Pipeline Integration

```powershell
# Scan files from pipeline
Get-ChildItem "C:\Documents" -Recurse -File | 
    Where-Object { $_.Extension -in @('.txt', '.doc', '.docx', '.pdf') } |
    ForEach-Object { ferret-scan scan $_.FullName --format json }

# Process scan results
ferret-scan scan "C:\Data" --format json | 
    ConvertFrom-Json | 
    Where-Object { $_.confidence_level -eq "HIGH" } |
    Group-Object type |
    Sort-Object Count -Descending

# Export results to CSV
ferret-scan scan "C:\Documents" --format json |
    ConvertFrom-Json |
    Export-Csv -Path "scan-results.csv" -NoTypeInformation
```

### Advanced PowerShell Usage

```powershell
# Parallel scanning with PowerShell jobs
$Directories = Get-ChildItem "C:\Data" -Directory
$Jobs = foreach ($dir in $Directories) {
    Start-Job -ScriptBlock {
        param($path)
        & ferret-scan scan $path --format json
    } -ArgumentList $dir.FullName
}

# Wait for all jobs and collect results
$Results = $Jobs | Wait-Job | Receive-Job
$Jobs | Remove-Job

# Scheduled scanning with Windows Task Scheduler
$Action = New-ScheduledTaskAction -Execute "ferret-scan" -Argument "scan C:\Data --format json --output C:\Reports\daily-scan.json"
$Trigger = New-ScheduledTaskTrigger -Daily -At "2:00 AM"
Register-ScheduledTask -TaskName "Daily Ferret Scan" -Action $Action -Trigger $Trigger
```

## Configuration Management

### Windows-Specific Configuration

Create a Windows-optimized configuration file:

```yaml
# %APPDATA%\ferret-scan\config.yaml
defaults:
  format: "json"
  checks: "all"
  confidence_levels: "high,medium"
  recursive: true
  enable_preprocessors: true
  no_color: false

platform:
  windows:
    use_appdata: true
    long_path_support: false
    temp_dir: "%TEMP%\\ferret-scan"
    config_dir: "%APPDATA%\\ferret-scan"

profiles:
  windows-quick:
    format: "text"
    checks: "CREDIT_CARD,SSN,SECRETS"
    confidence_levels: "high"
    recursive: false
    description: "Quick Windows scan for common sensitive data"
    
  windows-comprehensive:
    format: "json"
    checks: "all"
    confidence_levels: "all"
    recursive: true
    enable_preprocessors: true
    description: "Comprehensive Windows scan with all features"
    
  windows-enterprise:
    format: "gitlab-sast"
    checks: "all"
    confidence_levels: "high,medium"
    recursive: true
    enable_preprocessors: true
    description: "Enterprise Windows scanning with GitLab integration"
    redaction:
      enabled: true
      output_dir: "./redacted"
      strategy: "format_preserving"

validators:
  creditcard:
    enabled: true
    confidence_threshold: 0.8
  ssn:
    enabled: true
    confidence_threshold: 0.9
  secrets:
    enabled: true
    confidence_threshold: 0.7
```

### Profile Usage

```powershell
# Use specific profiles
ferret-scan scan "C:\Documents" --profile windows-quick
ferret-scan scan "C:\Projects" --profile windows-comprehensive
ferret-scan scan "C:\Data" --profile windows-enterprise

# List available profiles
ferret-scan --list-profiles --config "$env:APPDATA\ferret-scan\config.yaml"

# Override profile settings
ferret-scan scan "C:\Data" --profile windows-quick --format json --confidence high
```

### Environment-Specific Configurations

```powershell
# Development environment
$DevConfig = @"
defaults:
  format: "json"
  checks: "SECRETS,CREDIT_CARD"
  confidence_levels: "high"
  recursive: true

profiles:
  dev-scan:
    format: "text"
    checks: "SECRETS"
    confidence_levels: "high"
    description: "Development environment scanning"
"@

$DevConfig | Out-File "$env:APPDATA\ferret-scan\dev-config.yaml" -Encoding UTF8

# Use development configuration
ferret-scan scan "C:\Projects" --config "$env:APPDATA\ferret-scan\dev-config.yaml"
```

## Web UI Usage

### Starting the Web Interface

```powershell
# Start web UI on default port (8080)
ferret-scan web

# Start on custom port
ferret-scan web --port 9000

# Start in background
Start-Process ferret-scan -ArgumentList "web", "--port", "8080" -WindowStyle Hidden

# Start with specific configuration
ferret-scan web --port 8080 --config "$env:APPDATA\ferret-scan\config.yaml"
```

### Accessing the Web UI

1. **Open Browser**: Navigate to `http://localhost:8080`
2. **Upload Files**: Drag and drop files or use the file picker
3. **Configure Scan**: Select checks, confidence levels, and output format
4. **Run Scan**: Click "Start Scan" to begin analysis
5. **View Results**: Review findings in the results panel
6. **Export Results**: Download results in various formats

### Web UI Features

#### File Upload Methods
- **Drag and Drop**: Drag files directly onto the upload area
- **File Picker**: Click "Choose Files" to browse and select files
- **Directory Upload**: Select entire directories (modern browsers)

#### Scan Configuration
- **Check Selection**: Choose specific validators to run
- **Confidence Levels**: Filter results by confidence (high, medium, low)
- **Output Format**: Select JSON, CSV, or text output
- **Preprocessing**: Enable/disable document text extraction

#### Results Management
- **Real-time Updates**: See results as they're discovered
- **Filtering**: Filter results by type, confidence, or file
- **Sorting**: Sort by confidence, type, or filename
- **Export Options**: Download results in multiple formats

## Batch Operations

### Scanning Multiple Directories

```powershell
# Define directories to scan
$ScanDirs = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads", 
    "$env:USERPROFILE\Desktop",
    "C:\Projects",
    "D:\Data"
)

# Create output directory
$OutputDir = "C:\ScanResults\$(Get-Date -Format 'yyyy-MM-dd')"
New-Item -ItemType Directory -Path $OutputDir -Force

# Scan each directory
foreach ($dir in $ScanDirs) {
    if (Test-Path $dir) {
        $dirName = Split-Path $dir -Leaf
        $outputFile = Join-Path $OutputDir "$dirName-scan.json"
        
        Write-Host "Scanning: $dir" -ForegroundColor Green
        ferret-scan scan $dir --recursive --format json --output $outputFile
        
        Write-Host "Results saved to: $outputFile" -ForegroundColor Cyan
    } else {
        Write-Warning "Directory not found: $dir"
    }
}
```

### Automated Reporting

```powershell
# Generate daily security report
function New-SecurityReport {
    param(
        [string]$ReportDate = (Get-Date -Format 'yyyy-MM-dd'),
        [string]$OutputPath = "C:\Reports"
    )
    
    $ReportDir = Join-Path $OutputPath $ReportDate
    New-Item -ItemType Directory -Path $ReportDir -Force
    
    # Scan critical directories
    $CriticalDirs = @{
        "UserDocuments" = "$env:USERPROFILE\Documents"
        "SharedDrive" = "\\fileserver\shared"
        "ProjectFiles" = "C:\Projects"
        "TempFiles" = "$env:TEMP"
    }
    
    $Summary = @()
    
    foreach ($name in $CriticalDirs.Keys) {
        $path = $CriticalDirs[$name]
        $outputFile = Join-Path $ReportDir "$name-scan.json"
        
        if (Test-Path $path) {
            Write-Host "Scanning $name`: $path" -ForegroundColor Green
            
            # Run scan
            ferret-scan scan $path --recursive --format json --output $outputFile
            
            # Parse results for summary
            if (Test-Path $outputFile) {
                $results = Get-Content $outputFile | ConvertFrom-Json
                $highConfidence = ($results | Where-Object { $_.confidence_level -eq "HIGH" }).Count
                $mediumConfidence = ($results | Where-Object { $_.confidence_level -eq "MEDIUM" }).Count
                
                $Summary += [PSCustomObject]@{
                    Location = $name
                    Path = $path
                    HighRisk = $highConfidence
                    MediumRisk = $mediumConfidence
                    TotalFindings = $results.Count
                    ScanTime = Get-Date
                }
            }
        } else {
            Write-Warning "Path not accessible: $path"
        }
    }
    
    # Generate summary report
    $summaryFile = Join-Path $ReportDir "summary.csv"
    $Summary | Export-Csv -Path $summaryFile -NoTypeInformation
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - $ReportDate</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .high-risk { color: red; font-weight: bold; }
        .medium-risk { color: orange; }
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Generated: $(Get-Date)</p>
    <table>
        <tr>
            <th>Location</th>
            <th>Path</th>
            <th>High Risk</th>
            <th>Medium Risk</th>
            <th>Total Findings</th>
        </tr>
"@
    
    foreach ($item in $Summary) {
        $highClass = if ($item.HighRisk -gt 0) { "high-risk" } else { "" }
        $mediumClass = if ($item.MediumRisk -gt 0) { "medium-risk" } else { "" }
        
        $htmlReport += @"
        <tr>
            <td>$($item.Location)</td>
            <td>$($item.Path)</td>
            <td class="$highClass">$($item.HighRisk)</td>
            <td class="$mediumClass">$($item.MediumRisk)</td>
            <td>$($item.TotalFindings)</td>
        </tr>
"@
    }
    
    $htmlReport += @"
    </table>
</body>
</html>
"@
    
    $htmlFile = Join-Path $ReportDir "report.html"
    $htmlReport | Out-File $htmlFile -Encoding UTF8
    
    Write-Host "Report generated: $ReportDir" -ForegroundColor Green
    return $ReportDir
}

# Run daily report
New-SecurityReport
```

## Integration with Windows Tools

### Windows Task Scheduler

```powershell
# Create scheduled task for daily scanning
$TaskName = "Daily Security Scan"
$TaskDescription = "Daily Ferret Scan security check"

# Define the action
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument @"
-WindowStyle Hidden -Command "& { 
    ferret-scan scan 'C:\Data' --recursive --format json --output 'C:\Reports\daily-scan-$(Get-Date -Format yyyy-MM-dd).json'
    if ($LASTEXITCODE -ne 0) { 
        Write-EventLog -LogName Application -Source 'Ferret Scan' -EventId 1001 -EntryType Error -Message 'Daily scan failed'
    }
}"
"@

# Define the trigger (daily at 2 AM)
$Trigger = New-ScheduledTaskTrigger -Daily -At "2:00 AM"

# Define settings
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Register the task
Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM"
```

### Windows Event Log Integration

```powershell
# Create custom event log source
New-EventLog -LogName Application -Source "Ferret Scan" -ErrorAction SilentlyContinue

# Function to log scan results
function Write-ScanEvent {
    param(
        [string]$Message,
        [string]$EntryType = "Information",
        [int]$EventId = 1000
    )
    
    Write-EventLog -LogName Application -Source "Ferret Scan" -EventId $EventId -EntryType $EntryType -Message $Message
}

# Example usage
$ScanResults = ferret-scan scan "C:\Data" --format json | ConvertFrom-Json
$HighRiskCount = ($ScanResults | Where-Object { $_.confidence_level -eq "HIGH" }).Count

if ($HighRiskCount -gt 0) {
    Write-ScanEvent -Message "High-risk findings detected: $HighRiskCount items" -EntryType Warning -EventId 1001
} else {
    Write-ScanEvent -Message "Scan completed successfully with no high-risk findings" -EntryType Information -EventId 1000
}
```

### File Explorer Integration

```powershell
# Add context menu entry for Ferret Scan
$RegPath = "HKCU:\Software\Classes\Directory\shell\FerretScan"
New-Item -Path $RegPath -Force
Set-ItemProperty -Path $RegPath -Name "(Default)" -Value "Scan with Ferret"
Set-ItemProperty -Path $RegPath -Name "Icon" -Value "C:\Program Files\ferret-scan\ferret-scan.exe"

$CommandPath = "$RegPath\command"
New-Item -Path $CommandPath -Force
Set-ItemProperty -Path $CommandPath -Name "(Default)" -Value 'powershell.exe -Command "ferret-scan scan \"%1\" --format text | Out-GridView -Title \"Ferret Scan Results\""'
```

## Performance Optimization

### Optimizing Scan Performance

```powershell
# Fast scanning for specific data types
ferret-scan scan "C:\Data" --checks CREDIT_CARD,SSN --confidence high --format json

# Disable preprocessors for faster scanning
ferret-scan scan "C:\Data" --enable-preprocessors=false --format text

# Parallel scanning of multiple directories
$Directories = @("C:\Dir1", "C:\Dir2", "C:\Dir3")
$Jobs = foreach ($dir in $Directories) {
    Start-Job -ScriptBlock { 
        param($path)
        ferret-scan scan $path --format json
    } -ArgumentList $dir
}

$Results = $Jobs | Wait-Job | Receive-Job
$Jobs | Remove-Job
```

### Memory Management

```powershell
# Monitor memory usage during scans
$Process = Get-Process ferret-scan -ErrorAction SilentlyContinue
if ($Process) {
    Write-Host "Memory usage: $([math]::Round($Process.WorkingSet64/1MB, 2)) MB"
}

# Process large directories in batches
function Invoke-BatchScan {
    param(
        [string]$RootPath,
        [int]$BatchSize = 100
    )
    
    $AllFiles = Get-ChildItem $RootPath -File -Recurse
    $Batches = [System.Collections.ArrayList]::new()
    
    for ($i = 0; $i -lt $AllFiles.Count; $i += $BatchSize) {
        $Batch = $AllFiles[$i..([Math]::Min($i + $BatchSize - 1, $AllFiles.Count - 1))]
        $Batches.Add($Batch) | Out-Null
    }
    
    foreach ($batch in $Batches) {
        $TempList = $batch | ForEach-Object { $_.FullName }
        $TempFile = [System.IO.Path]::GetTempFileName()
        $TempList | Out-File $TempFile
        
        ferret-scan scan --file-list $TempFile --format json
        Remove-Item $TempFile
        
        # Brief pause between batches
        Start-Sleep 1
    }
}
```

## Troubleshooting Common Issues

### Path-Related Issues

```powershell
# Handle long paths (>260 characters)
# Enable long path support in Windows 10/11
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Use UNC format for long paths
ferret-scan scan "\\?\C:\Very\Long\Path\That\Exceeds\260\Characters"

# Handle special characters in paths
$PathWithSpaces = "C:\Program Files\My App\Data"
ferret-scan scan "`"$PathWithSpaces`"" --format json
```

### Permission Issues

```powershell
# Check if running with sufficient privileges
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $IsAdmin) {
    Write-Warning "Some system directories may require Administrator privileges"
    # Restart as Administrator if needed
    Start-Process PowerShell -Verb RunAs -ArgumentList "-Command", "ferret-scan scan C:\Windows --format json"
}

# Handle access denied errors gracefully
try {
    ferret-scan scan "C:\System Volume Information" --format json
} catch {
    Write-Warning "Access denied to system directory: $($_.Exception.Message)"
}
```

### Network and UNC Path Issues

```powershell
# Test network connectivity before scanning
function Test-NetworkPath {
    param([string]$UNCPath)
    
    try {
        $TestPath = Split-Path $UNCPath -Parent
        Test-Path $TestPath -ErrorAction Stop
        return $true
    } catch {
        Write-Warning "Cannot access network path: $UNCPath"
        return $false
    }
}

# Scan network paths with error handling
$NetworkPaths = @("\\server1\share1", "\\server2\share2")
foreach ($path in $NetworkPaths) {
    if (Test-NetworkPath $path) {
        ferret-scan scan $path --format json --output "network-scan-$(Split-Path $path -Leaf).json"
    }
}
```

## Best Practices

### Security Considerations

1. **Run with Least Privilege**: Only use Administrator privileges when necessary
2. **Secure Output Files**: Store scan results in secure locations
3. **Network Scanning**: Be cautious when scanning network shares
4. **Sensitive Data Handling**: Use redaction features for sensitive findings

### Performance Best Practices

1. **Exclude Unnecessary Directories**: Use suppressions for system directories
2. **Batch Processing**: Process large datasets in smaller batches
3. **Resource Monitoring**: Monitor CPU and memory usage during scans
4. **Scheduled Scanning**: Run intensive scans during off-hours

### Maintenance Tasks

```powershell
# Regular maintenance script
function Invoke-FerretMaintenance {
    # Clean up old scan results
    $OldResults = Get-ChildItem "C:\ScanResults" -File | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-30) }
    $OldResults | Remove-Item -Force
    
    # Update configuration if needed
    $ConfigFile = "$env:APPDATA\ferret-scan\config.yaml"
    if (Test-Path $ConfigFile) {
        $Config = Get-Content $ConfigFile -Raw
        # Perform any necessary config updates
    }
    
    # Check for updates (if update mechanism exists)
    ferret-scan --version
    
    Write-Host "Maintenance completed" -ForegroundColor Green
}

# Schedule maintenance
$MaintenanceAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command Invoke-FerretMaintenance"
$MaintenanceTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "3:00 AM"
Register-ScheduledTask -TaskName "Ferret Scan Maintenance" -Action $MaintenanceAction -Trigger $MaintenanceTrigger
```

## Advanced Scenarios

### Enterprise Integration

```powershell
# SIEM integration example
function Send-ToSIEM {
    param(
        [string]$ScanResultsPath,
        [string]$SIEMEndpoint
    )
    
    $Results = Get-Content $ScanResultsPath | ConvertFrom-Json
    $HighRiskFindings = $Results | Where-Object { $_.confidence_level -eq "HIGH" }
    
    foreach ($finding in $HighRiskFindings) {
        $SIEMEvent = @{
            timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            source = "ferret-scan"
            severity = "high"
            type = $finding.type
            filename = $finding.filename
            confidence = $finding.confidence
        }
        
        # Send to SIEM (example with REST API)
        Invoke-RestMethod -Uri $SIEMEndpoint -Method POST -Body ($SIEMEvent | ConvertTo-Json) -ContentType "application/json"
    }
}
```

### Compliance Reporting

```powershell
# Generate compliance report
function New-ComplianceReport {
    param(
        [string[]]$ScanPaths,
        [string]$ComplianceStandard = "PCI-DSS"
    )
    
    $ComplianceResults = @()
    
    foreach ($path in $ScanPaths) {
        $ScanResults = ferret-scan scan $path --format json | ConvertFrom-Json
        
        # Analyze results for compliance violations
        $CreditCardFindings = $ScanResults | Where-Object { $_.type -eq "CREDIT_CARD" -and $_.confidence_level -eq "HIGH" }
        $SSNFindings = $ScanResults | Where-Object { $_.type -eq "SSN" -and $_.confidence_level -eq "HIGH" }
        
        $ComplianceResults += [PSCustomObject]@{
            Path = $path
            Standard = $ComplianceStandard
            CreditCardViolations = $CreditCardFindings.Count
            SSNViolations = $SSNFindings.Count
            TotalViolations = $CreditCardFindings.Count + $SSNFindings.Count
            ComplianceStatus = if (($CreditCardFindings.Count + $SSNFindings.Count) -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
            ScanDate = Get-Date
        }
    }
    
    return $ComplianceResults
}

# Generate monthly compliance report
$MonthlyPaths = @("C:\CustomerData", "C:\PaymentProcessing", "\\fileserver\sensitive")
$ComplianceReport = New-ComplianceReport -ScanPaths $MonthlyPaths -ComplianceStandard "PCI-DSS"
$ComplianceReport | Export-Csv "compliance-report-$(Get-Date -Format yyyy-MM).csv" -NoTypeInformation
```

---

This comprehensive Windows usage guide covers all aspects of using Ferret Scan effectively on Windows systems, from basic command-line usage to advanced enterprise integration scenarios.