# Windows Installation Guide

## Overview

This guide provides comprehensive instructions for installing Ferret Scan on Windows systems, including automated installation scripts, manual installation, and configuration options.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10 (version 1903 or later) or Windows 11
- **Architecture**: x64 (Intel/AMD 64-bit) or ARM64
- **Memory**: 512 MB RAM minimum, 1 GB recommended
- **Disk Space**: 50 MB for application, additional space for scan results
- **PowerShell**: Version 5.1 or later (included with Windows 10/11)

### Recommended Requirements
- **Operating System**: Windows 11 or Windows 10 (latest version)
- **Architecture**: x64 with modern processor
- **Memory**: 2 GB RAM or more
- **Disk Space**: 200 MB for application and configuration files
- **PowerShell**: Version 7.x (PowerShell Core) for enhanced features

### Optional Components
- **Git for Windows**: Required for pre-commit integration
- **Windows Terminal**: Enhanced command-line experience
- **Visual Studio Code**: For configuration file editing

## Installation Methods

### Method 1: Automated Installation (Recommended)

The automated installation script provides the easiest way to install Ferret Scan with proper configuration.

#### Download and Extract
1. Download the Windows release archive from the releases page
2. Extract `ferret-scan_vX.X.X_windows_amd64.zip` to a temporary directory
3. Open the extracted folder

#### Run Installation Script
```powershell
# Open PowerShell as Administrator
# Navigate to the extracted directory
cd path\to\ferret-scan_vX.X.X_windows_amd64

# Run the installation script
.\scripts\install-system-windows.ps1
```

#### Installation Options
The script supports several installation options:

```powershell
# System-wide installation (default, requires Administrator)
.\scripts\install-system-windows.ps1

# User-only installation
.\scripts\install-system-windows.ps1 -UserInstall

# Custom installation directory
.\scripts\install-system-windows.ps1 -InstallPath "C:\Tools\ferret-scan"

# Skip PATH modification
.\scripts\install-system-windows.ps1 -AddToPath:$false

# Create desktop shortcuts
.\scripts\install-system-windows.ps1 -CreateShortcuts
```

### Method 2: Manual Installation

For users who prefer manual installation or need custom configurations.

#### Step 1: Choose Installation Directory
```powershell
# System-wide installation (requires Administrator)
$InstallDir = "$env:ProgramFiles\ferret-scan"

# User-specific installation
$InstallDir = "$env:LOCALAPPDATA\Programs\ferret-scan"

# Custom directory
$InstallDir = "C:\Tools\ferret-scan"
```

#### Step 2: Create Directory and Copy Files
```powershell
# Create installation directory
New-Item -ItemType Directory -Force -Path $InstallDir

# Copy the binary
Copy-Item "ferret-scan.exe" -Destination "$InstallDir\ferret-scan.exe"

# Copy configuration files (optional)
Copy-Item "config.yaml" -Destination "$InstallDir\config.yaml"
Copy-Item "examples\*" -Destination "$InstallDir\examples\" -Recurse -Force
```

#### Step 3: Add to PATH
```powershell
# Add to user PATH
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
}

# Add to system PATH (requires Administrator)
$SystemPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($SystemPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$SystemPath;$InstallDir", "Machine")
}
```

#### Step 4: Verify Installation
```powershell
# Restart PowerShell or Command Prompt
# Test the installation
ferret-scan --version
```

### Method 3: Portable Installation

For users who want a portable installation without system modifications.

#### Setup Portable Directory
```powershell
# Create portable directory
$PortableDir = "C:\PortableApps\ferret-scan"
New-Item -ItemType Directory -Force -Path $PortableDir

# Copy files
Copy-Item "ferret-scan.exe" -Destination "$PortableDir\ferret-scan.exe"
Copy-Item "config.yaml" -Destination "$PortableDir\config.yaml"
Copy-Item "examples" -Destination "$PortableDir\examples" -Recurse
```

#### Create Batch Script
```batch
@echo off
REM ferret-scan.bat - Portable launcher
set FERRET_CONFIG_DIR=%~dp0
"%~dp0ferret-scan.exe" %*
```

## Configuration

### Configuration Directory Locations

Ferret Scan uses the following configuration directory hierarchy on Windows:

1. **Custom Directory**: `%FERRET_CONFIG_DIR%` (if set)
2. **User AppData**: `%APPDATA%\ferret-scan` (default)
3. **User Profile**: `%USERPROFILE%\.ferret-scan` (fallback)
4. **System-wide**: `%PROGRAMDATA%\ferret-scan` (system installations)

### Initial Configuration

#### Create User Configuration
```powershell
# Create user configuration directory
$ConfigDir = "$env:APPDATA\ferret-scan"
New-Item -ItemType Directory -Force -Path $ConfigDir

# Copy default configuration
Copy-Item "config.yaml" -Destination "$ConfigDir\config.yaml"

# Create suppressions file
New-Item -ItemType File -Path "$ConfigDir\suppressions.yaml" -Force
```

#### Windows-Specific Configuration
Create a Windows-optimized configuration file:

```yaml
# Windows-specific ferret-scan configuration
defaults:
  format: "text"
  checks: "all"
  confidence_levels: "high,medium"
  recursive: true
  enable_preprocessors: true

platform:
  windows:
    use_appdata: true
    long_path_support: false
    temp_dir: "%TEMP%\ferret-scan"
    config_dir: "%APPDATA%\ferret-scan"

profiles:
  windows-dev:
    format: "json"
    checks: "CREDIT_CARD,SSN,SECRETS,EMAIL"
    confidence_levels: "high"
    recursive: true
    description: "Windows development scanning profile"
    
  windows-enterprise:
    format: "gitlab-sast"
    checks: "all"
    confidence_levels: "high,medium"
    recursive: true
    enable_preprocessors: true
    description: "Enterprise Windows scanning with GitLab integration"
```

### Environment Variables

Set up Windows environment variables for optimal operation:

```powershell
# Set configuration directory
[Environment]::SetEnvironmentVariable("FERRET_CONFIG_DIR", "$env:APPDATA\ferret-scan", "User")

# Enable debug mode (optional)
[Environment]::SetEnvironmentVariable("FERRET_DEBUG", "1", "User")

# Set custom temp directory (optional)
[Environment]::SetEnvironmentVariable("FERRET_TEMP_DIR", "$env:TEMP\ferret-scan", "User")
```

## Integration Setup

### PowerShell Integration

#### PowerShell Profile Setup
Add Ferret Scan functions to your PowerShell profile:

```powershell
# Add to $PROFILE (usually $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1)

function Scan-Directory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [string]$Format = "text",
        [string]$Output = $null
    )
    
    $args = @("scan", $Path, "--format", $Format)
    if ($Output) {
        $args += @("--output", $Output)
    }
    
    & ferret-scan @args
}

function Scan-Files {
    param(
        [Parameter(ValueFromPipeline=$true)]
        [string[]]$Files,
        [string]$Format = "json"
    )
    
    process {
        foreach ($file in $Files) {
            ferret-scan scan $file --format $Format
        }
    }
}

# Aliases for convenience
Set-Alias -Name fs -Value ferret-scan
Set-Alias -Name scan -Value Scan-Directory
```

#### PowerShell Completion
Enable tab completion for Ferret Scan commands:

```powershell
# Add to PowerShell profile
Register-ArgumentCompleter -Native -CommandName ferret-scan -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    
    $commands = @('scan', 'web', '--help', '--version', '--config', '--format', '--checks')
    $commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
```

### Git Integration

#### Pre-commit Hook Setup
```powershell
# Navigate to your Git repository
cd C:\path\to\your\repository

# Install pre-commit (requires Python)
pip install pre-commit

# Copy the pre-commit configuration
Copy-Item "$InstallDir\.pre-commit-config.yaml" -Destination ".pre-commit-config.yaml"

# Install the hooks
pre-commit install
```

#### Manual Git Hook
For repositories without pre-commit framework:

```batch
@echo off
REM .git\hooks\pre-commit.bat
echo Running Ferret Scan pre-commit check...
ferret-scan scan . --pre-commit-mode --format text
if %ERRORLEVEL% neq 0 (
    echo Sensitive data detected! Commit blocked.
    exit /b 1
)
echo Pre-commit scan passed.
exit /b 0
```

### Windows Terminal Integration

Add Ferret Scan to Windows Terminal settings:

```json
{
    "name": "Ferret Scan",
    "commandline": "powershell.exe -NoExit -Command \"& { Write-Host 'Ferret Scan Terminal' -ForegroundColor Green; Write-Host 'Type: ferret-scan --help for usage' -ForegroundColor Cyan }\"",
    "icon": "ms-appx:///ProfileIcons/{9acb9455-ca41-5af7-950f-6bca1bc9722f}.png",
    "startingDirectory": "%USERPROFILE%"
}
```

## Verification and Testing

### Installation Verification
```powershell
# Test basic functionality
ferret-scan --version
ferret-scan --help

# Test configuration loading
ferret-scan scan --help

# Test with sample file
echo "Test credit card: 4111-1111-1111-1111" | Out-File test.txt
ferret-scan scan test.txt
Remove-Item test.txt
```

### Performance Testing
```powershell
# Test scanning performance
Measure-Command { ferret-scan scan $env:USERPROFILE\Documents --format json }

# Test web UI startup
Start-Process -NoNewWindow ferret-scan -ArgumentList "web", "--port", "8080"
Start-Sleep 3
Stop-Process -Name "ferret-scan" -Force
```

### Configuration Testing
```powershell
# Test configuration file loading
ferret-scan scan . --config "$env:APPDATA\ferret-scan\config.yaml" --format json

# Test profile usage
ferret-scan scan . --profile windows-dev --format json

# Test Windows-specific paths
ferret-scan scan "C:\Windows\System32\drivers\etc" --format text
```

## Troubleshooting

### Common Issues

#### PATH Not Updated
If `ferret-scan` command is not recognized:
```powershell
# Check if ferret-scan is in PATH
$env:PATH -split ';' | Where-Object { Test-Path "$_\ferret-scan.exe" }

# Manually add to PATH for current session
$env:PATH += ";C:\path\to\ferret-scan"

# Restart PowerShell/Command Prompt
```

#### Permission Errors
For permission-related issues:
```powershell
# Run as Administrator
Start-Process PowerShell -Verb RunAs

# Check file permissions
Get-Acl "C:\path\to\ferret-scan.exe" | Format-List

# Fix permissions if needed
icacls "C:\path\to\ferret-scan.exe" /grant Users:RX
```

#### Long Path Issues
For paths longer than 260 characters:
```powershell
# Enable long path support (Windows 10 version 1607+)
# Run as Administrator
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Restart required
Restart-Computer
```

#### Configuration Issues
For configuration-related problems:
```powershell
# Verify configuration directory
Write-Host "Config directory: $env:APPDATA\ferret-scan"
Test-Path "$env:APPDATA\ferret-scan"

# Check configuration file syntax
ferret-scan scan . --config "$env:APPDATA\ferret-scan\config.yaml" --debug

# Reset to default configuration
Copy-Item "$InstallDir\config.yaml" -Destination "$env:APPDATA\ferret-scan\config.yaml" -Force
```

## Uninstallation

### Automated Uninstallation
```powershell
# Run the uninstall script (if available)
.\scripts\uninstall-system-windows.ps1

# Or use the installed uninstaller
& "$env:ProgramFiles\ferret-scan\uninstall.ps1"
```

### Manual Uninstallation
```powershell
# Remove from PATH
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$NewPath = $UserPath -replace [regex]::Escape(";$InstallDir"), ""
[Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")

# Remove installation directory
Remove-Item -Recurse -Force "$env:ProgramFiles\ferret-scan"

# Remove configuration (optional)
Remove-Item -Recurse -Force "$env:APPDATA\ferret-scan"

# Remove desktop shortcuts (if created)
Remove-Item "$env:USERPROFILE\Desktop\Ferret Scan.lnk" -ErrorAction SilentlyContinue
```

## Advanced Configuration

### Enterprise Deployment

For enterprise environments, consider:

#### Group Policy Deployment
1. Create MSI package using WiX Toolset
2. Deploy via Group Policy Software Installation
3. Configure default settings via registry

#### SCCM Deployment
1. Package the installation as SCCM application
2. Use PowerShell detection methods
3. Configure automatic updates

#### Registry Configuration
```powershell
# Set system-wide defaults via registry
$RegPath = "HKLM:\SOFTWARE\FerretScan"
New-Item -Path $RegPath -Force
Set-ItemProperty -Path $RegPath -Name "DefaultConfig" -Value "$env:PROGRAMDATA\ferret-scan\config.yaml"
Set-ItemProperty -Path $RegPath -Name "EnableLogging" -Value 1
```

### Security Considerations

#### Execution Policy
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Set appropriate policy for scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Antivirus Exclusions
Add exclusions for:
- Installation directory: `C:\Program Files\ferret-scan\`
- Configuration directory: `%APPDATA%\ferret-scan\`
- Temporary scan files: `%TEMP%\ferret-scan\`

#### Network Security
For environments with strict network policies:
- Ferret Scan operates offline by default
- Web UI runs locally (localhost:8080)
- No external network connections required

## Support and Resources

### Documentation
- [Windows Usage Guide](user-guides/README-Windows-Usage.md)
- [Windows Troubleshooting](troubleshooting/WINDOWS_TROUBLESHOOTING.md)
- [Configuration Reference](configuration.md)

### Community
- GitHub Issues: Report bugs and feature requests
- Discussions: Community support and questions

### Enterprise Support
For enterprise deployments:
- Custom installation packages
- Integration assistance
- Training and documentation
- Priority support channels

---

**Note**: This installation guide is specific to Windows systems. For Linux/macOS installation, see [INSTALLATION.md](INSTALLATION.md).