# Windows Configuration Templates

This directory contains Windows-specific configuration templates for Ferret Scanner, designed to work optimally with Windows environments and development workflows.

## Available Templates

### 1. `ferret-windows.yaml` - General Windows Configuration
**Purpose**: General-purpose Windows configuration with platform-specific optimizations.

**Key Features**:
- Windows path format examples (`C:\path\to\file`, `%USERPROFILE%\Documents`)
- APPDATA directory usage for configuration storage
- Windows environment variable integration
- UNC path support for network shares
- Windows-specific profiles for different scenarios

**Best For**:
- General Windows users
- Windows workstations
- Mixed Windows environments

**Usage**:
```cmd
ferret-scan --config examples\ferret-windows.yaml --profile windows-dev .
```

### 2. `ferret-powershell.yaml` - PowerShell Integration
**Purpose**: Optimized for PowerShell scripts and Windows automation workflows.

**Key Features**:
- JSON output format for PowerShell object processing
- PowerShell environment variable syntax (`$env:APPDATA`)
- Automation-friendly profiles with minimal output
- CI/CD integration for PowerShell-based pipelines
- Interactive and automation profiles

**Best For**:
- PowerShell developers and scripters
- Windows automation workflows
- PowerShell-based CI/CD pipelines
- System administrators using PowerShell

**Usage**:
```powershell
# Interactive PowerShell session
$results = ferret-scan --config examples\ferret-powershell.yaml --profile powershell-interactive --format json . | ConvertFrom-Json

# Automation script
ferret-scan --config examples\ferret-powershell.yaml --profile powershell-automation --format json $targetPath
```

### 3. `ferret-enterprise-windows.yaml` - Enterprise Configuration
**Purpose**: Enterprise-grade Windows configuration with compliance and security features.

**Key Features**:
- System-wide installation and configuration
- Comprehensive audit logging and compliance features
- Enterprise security profiles
- Redaction capabilities for sensitive environments
- Group Policy integration considerations
- Executive reporting profiles

**Best For**:
- Enterprise Windows deployments
- Compliance and audit requirements
- Large organizations with security policies
- System administrators managing multiple systems

**Usage**:
```cmd
# Compliance audit
ferret-scan --config examples\ferret-enterprise-windows.yaml --profile enterprise-compliance --format csv .

# Security assessment
ferret-scan --config examples\ferret-enterprise-windows.yaml --profile enterprise-security --format json .
```

### 4. `ferret-dev-windows.yaml` - Development Environment
**Purpose**: Developer-friendly configuration for Windows development environments.

**Key Features**:
- Visual Studio and VS Code integration considerations
- Git hook profiles for pre-commit scanning
- Development server URL patterns (localhost, development ports)
- Code review and CI/CD integration profiles
- Long path support for deep project structures

**Best For**:
- Windows developers
- Development teams using Windows
- Git workflows and pre-commit hooks
- Visual Studio and VS Code users

**Usage**:
```cmd
# Interactive development scanning
ferret-scan --config examples\ferret-dev-windows.yaml --profile dev-interactive .

# Pre-commit hook
ferret-scan --config examples\ferret-dev-windows.yaml --profile dev-precommit --format text .

# CI/CD integration
ferret-scan --config examples\ferret-dev-windows.yaml --profile dev-cicd --format junit .
```

## Windows-Specific Features

### Path Handling
All Windows templates demonstrate proper Windows path handling:

```yaml
# Absolute Windows paths
output_dir: "C:\\Users\\%USERNAME%\\Documents\\ferret-redacted"

# Environment variables
config_dir: "%APPDATA%\\ferret-scan"
temp_dir: "%TEMP%\\ferret-scan"

# UNC paths for network shares
# file://\\server\share\path\to\file
```

### Environment Variables
Common Windows environment variables used in templates:

- `%APPDATA%` - `C:\Users\username\AppData\Roaming`
- `%LOCALAPPDATA%` - `C:\Users\username\AppData\Local`
- `%USERPROFILE%` - `C:\Users\username`
- `%PROGRAMDATA%` - `C:\ProgramData`
- `%TEMP%` - `C:\Users\username\AppData\Local\Temp`
- `%USERNAME%` - Current username
- `%COMPUTERNAME%` - Computer name

### Platform Configuration
Windows-specific platform settings:

```yaml
platform:
  windows:
    use_appdata: true          # Use APPDATA for configuration
    system_wide_install: false # User vs system-wide installation
    create_shortcuts: false    # Desktop/Start Menu shortcuts
    add_to_path: false        # Add to PATH environment variable
    long_path_support: false  # Enable >260 character paths
```

## Integration Examples

### PowerShell Integration
```powershell
# Load configuration and scan
$config = "examples\ferret-powershell.yaml"
$results = ferret-scan --config $config --profile powershell-interactive --format json . | ConvertFrom-Json

# Process results
$highPriorityFindings = $results.findings | Where-Object { $_.confidence -eq "high" }
Write-Host "Found $($highPriorityFindings.Count) high-priority findings"

# Automation example
if ($results.findings.Count -gt 0) {
    Write-Error "Sensitive data found: $($results.findings.Count) findings"
    exit 1
}
```

### Batch Script Integration
```batch
@echo off
set CONFIG=examples\ferret-windows.yaml
set PROFILE=windows-quick

ferret-scan --config %CONFIG% --profile %PROFILE% --format text . > scan-results.txt
if %ERRORLEVEL% neq 0 (
    echo Issues found, check scan-results.txt
    exit /b 1
)
echo Scan completed successfully
```

### Visual Studio Code Integration
Add to `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Ferret Scan",
            "type": "shell",
            "command": "ferret-scan",
            "args": [
                "--config", "examples\\ferret-dev-windows.yaml",
                "--profile", "dev-interactive",
                "--format", "text",
                "."
            ],
            "group": "build",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "focus": false,
                "panel": "shared"
            }
        }
    ]
}
```

### Git Hook Integration
Pre-commit hook (`.git/hooks/pre-commit`):

```bash
#!/bin/sh
# Windows Git Bash pre-commit hook
ferret-scan --config examples/ferret-dev-windows.yaml --profile dev-precommit --format text .
exit $?
```

## Deployment Considerations

### Enterprise Deployment
1. **System-wide Installation**: Install to `%PROGRAMFILES%\ferret-scan`
2. **Configuration Management**: Use `%PROGRAMDATA%\ferret-scan` for system-wide config
3. **Group Policy**: Deploy configuration via Group Policy
4. **Security**: Restrict access to configuration files and audit logs

### Developer Workstations
1. **User Installation**: Install to `%LOCALAPPDATA%\Programs\ferret-scan`
2. **Configuration**: Use `%APPDATA%\ferret-scan` for user-specific config
3. **PATH Integration**: Add to user PATH for command-line access
4. **IDE Integration**: Configure tasks and shortcuts in development tools

### CI/CD Pipelines
1. **Portable Installation**: Use working directory for CI/CD environments
2. **Output Formats**: Use JUnit XML or JSON for pipeline integration
3. **Environment Variables**: Use `%RUNNER_TEMP%` or similar for temporary files
4. **Exit Codes**: Handle exit codes appropriately for pipeline success/failure

## Troubleshooting

### Common Issues
1. **Long Path Errors**: Enable `long_path_support: true` in platform configuration
2. **Permission Errors**: Ensure proper file and directory permissions
3. **Environment Variables**: Verify environment variable expansion
4. **UNC Path Issues**: Use proper UNC path format (`\\server\share`)

### Debug Configuration
Enable debug mode for troubleshooting:

```yaml
defaults:
  debug: true
  verbose: true
```

This will provide detailed logging of path resolution, configuration loading, and platform-specific operations.

## Customization

### Organization-Specific Templates
1. Copy a base template (e.g., `ferret-enterprise-windows.yaml`)
2. Update domain patterns in `intellectual_property.internal_urls`
3. Modify paths to match organizational standards
4. Add organization-specific profiles and validation rules
5. Configure audit logging and compliance requirements

### Development Team Templates
1. Start with `ferret-dev-windows.yaml`
2. Add team-specific URL patterns and validation rules
3. Configure CI/CD integration for your pipeline tools
4. Set up pre-commit hooks and IDE integration
5. Customize output formats for your workflow tools

For more information on Windows compatibility features, see the main documentation and the Windows troubleshooting guide.