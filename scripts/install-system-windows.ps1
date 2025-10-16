# System-wide installation script for Ferret Scan on Windows
# Supports multiple installation methods for internal company deployment

param(
    [Parameter(Position=0)]
    [ValidateSet("source", "binary", "uninstall")]
    [string]$Command = "source",
    
    [Parameter(Position=1)]
    [string]$BinaryPath = "",
    
    [string]$InstallDir = "",
    [string]$ConfigDir = "",
    [switch]$NoConfig = $false,
    [switch]$NoPrecommit = $false,
    [switch]$UserInstall = $false,
    [switch]$Help = $false
)

# Configuration
$BinaryName = "ferret-scan.exe"
$DefaultSystemInstallDir = "${env:ProgramFiles}\FerretScan"
$DefaultUserInstallDir = "${env:LOCALAPPDATA}\FerretScan"

# Set installation directory based on user preference
if (-not $InstallDir) {
    if ($UserInstall) {
        $InstallDir = $DefaultUserInstallDir
    } else {
        $InstallDir = $DefaultSystemInstallDir
    }
}

# Set configuration directory
if (-not $ConfigDir) {
    if ($env:FERRET_CONFIG_DIR) {
        $ConfigDir = $env:FERRET_CONFIG_DIR
    } elseif ($env:APPDATA) {
        $ConfigDir = Join-Path $env:APPDATA "ferret-scan"
    } else {
        $ConfigDir = Join-Path $env:USERPROFILE ".ferret-scan"
    }
}

# Colors for output (using Write-Host with colors)
function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Permissions {
    if (-not $UserInstall -and -not (Test-Administrator)) {
        Write-Error "System-wide installation requires Administrator privileges"
        Write-Info "Run PowerShell as Administrator or use -UserInstall for user-only installation"
        Write-Info "Example: .\install-system-windows.ps1 -UserInstall"
        exit 1
    }
    
    # Test write access to installation directory
    $testPath = Join-Path $InstallDir "test-write-access.tmp"
    try {
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        New-Item -ItemType File -Path $testPath -Force | Out-Null
        Remove-Item $testPath -Force
    } catch {
        Write-Error "Cannot write to installation directory: $InstallDir"
        Write-Info "Check permissions or try a different directory"
        exit 1
    }
}

function Install-FromSource {
    Write-Info "Installing from source..."
    
    # Check if we're in the ferret-scan directory
    if (-not (Test-Path "Makefile") -or -not (Test-Path "go.mod")) {
        Write-Error "Not in ferret-scan source directory"
        Write-Info "Please run this script from the ferret-scan project root"
        exit 1
    }
    
    # Build the binary
    Write-Info "Building ferret-scan..."
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    
    try {
        & make build-windows
        if ($LASTEXITCODE -ne 0) {
            throw "Make build failed"
        }
    } catch {
        Write-Error "Build failed: $_"
        exit 1
    }
    
    # Install binary
    Write-Info "Installing binary to $InstallDir..."
    $sourceBinary = "bin\ferret-scan.exe"
    if (-not (Test-Path $sourceBinary)) {
        Write-Error "Built binary not found: $sourceBinary"
        exit 1
    }
    
    Copy-Item $sourceBinary (Join-Path $InstallDir $BinaryName) -Force
    Write-Success "Binary installed to $(Join-Path $InstallDir $BinaryName)"
}

function Install-FromBinary {
    param([string]$BinaryPath)
    
    if (-not (Test-Path $BinaryPath)) {
        Write-Error "Binary not found: $BinaryPath"
        exit 1
    }
    
    Write-Info "Installing binary from $BinaryPath..."
    Copy-Item $BinaryPath (Join-Path $InstallDir $BinaryName) -Force
    Write-Success "Binary installed to $(Join-Path $InstallDir $BinaryName)"
}

function Install-ConfigFiles {
    Write-Info "Installing configuration files..."
    
    # Create config directory
    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }
    
    # Install the example config as the default config
    $exampleConfig = "examples\ferret.yaml"
    $defaultConfig = Join-Path $ConfigDir "config.yaml"
    $exampleConfigCopy = Join-Path $ConfigDir "ferret.example.yaml"
    
    if (Test-Path $exampleConfig) {
        Copy-Item $exampleConfig $defaultConfig -Force
        Write-Success "Default config installed to $defaultConfig (from $exampleConfig)"
        
        # Also keep a copy as example for reference
        Copy-Item $exampleConfig $exampleConfigCopy -Force
        Write-Success "Example config installed to $exampleConfigCopy"
    } elseif (Test-Path "config.yaml") {
        # Fallback to basic config.yaml if examples/ferret.yaml doesn't exist
        Copy-Item "config.yaml" $defaultConfig -Force
        Write-Success "Default config installed to $defaultConfig"
    } else {
        Write-Warning "No configuration files found to install"
    }
}

function Set-PathEnvironment {
    Write-Info "Setting up PATH environment variable..."
    
    try {
        if ($UserInstall) {
            # User-level PATH
            $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
            if ($currentPath -notlike "*$InstallDir*") {
                $newPath = "$InstallDir;$currentPath"
                [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
                Write-Success "Added $InstallDir to user PATH"
            } else {
                Write-Info "$InstallDir already in user PATH"
            }
        } else {
            # System-level PATH (requires admin)
            $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
            if ($currentPath -notlike "*$InstallDir*") {
                $newPath = "$InstallDir;$currentPath"
                [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
                Write-Success "Added $InstallDir to system PATH"
            } else {
                Write-Info "$InstallDir already in system PATH"
            }
        }
        
        # Update current session PATH
        $env:PATH = "$InstallDir;$env:PATH"
        
    } catch {
        Write-Warning "Failed to update PATH environment variable: $_"
        Write-Info "You may need to manually add $InstallDir to your PATH"
    }
}

function Setup-PrecommitIntegration {
    Write-Info "Setting up pre-commit integration..."
    
    # Note: Pre-commit wrapper scripts have been removed in favor of direct integration
    Write-Info "Pre-commit wrapper scripts have been deprecated - use direct integration instead"
    
    # Provide guidance for direct integration
    Write-Host ""
    Write-Info "For direct pre-commit integration, add to your .pre-commit-config.yaml:"
    Write-Host "  repos:"
    Write-Host "    - repo: local"
    Write-Host "      hooks:"
    Write-Host "        - id: ferret-scan"
    Write-Host "          name: Ferret Scan"
    Write-Host "          entry: ferret-scan --pre-commit-mode"
    Write-Host "          language: system"
    Write-Host "          files: \.(txt|md|py|go|js|ts|java|cpp|c|h)$"
    Write-Host ""
    Write-Info "Or use the Python package:"
    Write-Host "  repos:"
    Write-Host "    - repo: https://github.com/your-org/ferret-scan"
    Write-Host "      rev: v1.0.0"
    Write-Host "      hooks:"
    Write-Host "        - id: ferret-scan"
}

function Test-Installation {
    Write-Info "Verifying installation..."
    
    $ferretScanPath = Join-Path $InstallDir $BinaryName
    if (Test-Path $ferretScanPath) {
        try {
            $version = & $ferretScanPath --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Success "ferret-scan is working correctly (version: $version)"
            } else {
                Write-Warning "ferret-scan binary exists but --version failed"
            }
        } catch {
            Write-Warning "ferret-scan binary exists but cannot execute: $_"
        }
    } else {
        Write-Error "ferret-scan binary not found at $ferretScanPath"
    }
    
    # Test if it's in PATH
    try {
        $pathVersion = & ferret-scan --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "ferret-scan is available in PATH"
        }
    } catch {
        Write-Warning "ferret-scan not found in PATH"
        Write-Info "You may need to restart your terminal or add $InstallDir to PATH manually"
    }
}

function Remove-PathEnvironment {
    Write-Info "Removing from PATH environment variable..."
    
    try {
        if ($UserInstall) {
            # User-level PATH
            $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
            $newPath = ($currentPath -split ';' | Where-Object { $_ -ne $InstallDir }) -join ';'
            [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
            Write-Success "Removed $InstallDir from user PATH"
        } else {
            # System-level PATH
            $currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
            $newPath = ($currentPath -split ';' | Where-Object { $_ -ne $InstallDir }) -join ';'
            [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
            Write-Success "Removed $InstallDir from system PATH"
        }
    } catch {
        Write-Warning "Failed to update PATH environment variable: $_"
        Write-Info "You may need to manually remove $InstallDir from your PATH"
    }
}

function Uninstall-FerretScan {
    Write-Info "Uninstalling ferret-scan..."
    
    # Remove binary
    $binaryPath = Join-Path $InstallDir $BinaryName
    if (Test-Path $binaryPath) {
        Remove-Item $binaryPath -Force
        Write-Success "Removed $binaryPath"
    } else {
        Write-Warning "Binary not found: $binaryPath"
    }
    
    # Remove installation directory if empty
    try {
        if (Test-Path $InstallDir) {
            $items = Get-ChildItem $InstallDir
            if ($items.Count -eq 0) {
                Remove-Item $InstallDir -Force
                Write-Success "Removed empty installation directory: $InstallDir"
            } else {
                Write-Info "Installation directory not empty, preserving: $InstallDir"
            }
        }
    } catch {
        Write-Warning "Could not remove installation directory: $_"
    }
    
    # Remove from PATH
    Remove-PathEnvironment
    
    # Ask about config directory
    if (Test-Path $ConfigDir) {
        Write-Host ""
        Write-Info "Configuration directory found: $ConfigDir"
        Write-Host "Contents:"
        try {
            Get-ChildItem $ConfigDir | Format-Table Name, Length, LastWriteTime
        } catch {
            Write-Host "  (empty or inaccessible)"
        }
        Write-Host ""
        $response = Read-Host "Remove configuration directory $ConfigDir? [y/N]"
        if ($response -match '^[Yy]$') {
            Remove-Item $ConfigDir -Recurse -Force
            Write-Success "Removed $ConfigDir"
        } else {
            Write-Info "Configuration directory preserved"
        }
    } else {
        Write-Info "No configuration directory found at $ConfigDir"
    }
    
    # Check for project-level pre-commit hooks
    if (Test-Path ".git\hooks\pre-commit") {
        Write-Host ""
        Write-Info "Found Git pre-commit hook in current directory"
        $response = Read-Host "Remove pre-commit hook from current project? [y/N]"
        if ($response -match '^[Yy]$') {
            Remove-Item ".git\hooks\pre-commit" -Force
            Write-Success "Removed .git\hooks\pre-commit"
        }
    }
    
    # Provide cleanup instructions
    Write-Host ""
    Write-Info "Manual cleanup (if needed):"
    Write-Host "• Remove from PATH if manually added"
    Write-Host "• Run 'pre-commit uninstall' in projects using pre-commit framework"
    Write-Host "• Remove project-specific .ferret-scan.yaml files"
    Write-Host "• Remove project-specific .ferret-scan-suppressions.yaml files"
    
    Write-Success "Uninstallation complete"
}

function Show-Usage {
    Write-Host "Usage: .\install-system-windows.ps1 [COMMAND] [OPTIONS]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  source              Install from source (default)"
    Write-Host "  binary <path>       Install from existing binary"
    Write-Host "  uninstall          Remove ferret-scan installation"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -InstallDir DIR     Installation directory"
    Write-Host "                      Default: C:\Program Files\FerretScan (system)"
    Write-Host "                      Default: %LOCALAPPDATA%\FerretScan (user)"
    Write-Host "  -ConfigDir DIR      Configuration directory"
    Write-Host "                      Default: %APPDATA%\ferret-scan"
    Write-Host "  -UserInstall        Install for current user only (no admin required)"
    Write-Host "  -NoConfig           Skip configuration file installation"
    Write-Host "  -NoPrecommit        Skip pre-commit integration setup"
    Write-Host "  -Help               Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\install-system-windows.ps1                           # Install from source (requires admin)"
    Write-Host "  .\install-system-windows.ps1 -UserInstall              # Install for user only"
    Write-Host "  .\install-system-windows.ps1 binary .\ferret-scan.exe  # Install from binary"
    Write-Host "  .\install-system-windows.ps1 uninstall                 # Uninstall"
    Write-Host "  .\install-system-windows.ps1 -InstallDir C:\Tools      # Custom install directory"
}

# Main script logic
if ($Help) {
    Show-Usage
    exit 0
}

Write-Host "🚀 Ferret Scan Windows Installation" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Install directory: $InstallDir"
Write-Host "Config directory: $ConfigDir"
Write-Host "Command: $Command"
Write-Host "Install type: $(if ($UserInstall) { 'User' } else { 'System' })"
Write-Host ""

switch ($Command) {
    "source" {
        Test-Permissions
        Install-FromSource
        Set-PathEnvironment
    }
    "binary" {
        if (-not $BinaryPath) {
            Write-Error "Binary path required for 'binary' command"
            Show-Usage
            exit 1
        }
        Test-Permissions
        Install-FromBinary $BinaryPath
        Set-PathEnvironment
    }
    "uninstall" {
        if (-not $UserInstall) {
            Test-Permissions
        }
        Uninstall-FerretScan
        exit 0
    }
}

# Install additional components
if (-not $NoConfig) {
    Install-ConfigFiles
}

if (-not $NoPrecommit) {
    Setup-PrecommitIntegration
}

Test-Installation

Write-Host ""
Write-Success "Installation complete!"
Write-Host ""
Write-Info "Next steps:"
Write-Host "1. Test installation: ferret-scan --version"
Write-Host "2. Set up pre-commit: cd your-repo && .\scripts\setup-pre-commit.sh"
Write-Host "3. Configure user settings: notepad `"$ConfigDir\config.yaml`""
Write-Host ""
Write-Info "Documentation: https://your-internal-docs/ferret-scan"