# Ferret Scan Installation Guide

This guide covers all installation methods for Ferret Scan, from development to production deployment.

## Quick Installation (Recommended)

### System-wide Installation

#### Linux/macOS
```bash
# Clone the repository
git clone <your-internal-repo-url>
cd ferret-scan

# Build first
make build

# macOS: Handle security for built binary BEFORE installation
chmod +x bin/ferret-scan
xattr -d com.apple.quarantine bin/ferret-scan

# Install system-wide (installs to /usr/local/bin/ferret-scan)
sudo scripts/install-system.sh

# Verify installation
ferret-scan --version
```

**⚠️ macOS Security Note**: If macOS blocks execution with "cannot be opened because it is from an unidentified developer", run these commands on the binary BEFORE installation:
```bash
chmod +x bin/ferret-scan
xattr -d com.apple.quarantine bin/ferret-scan
```
Only use these commands for executables from trusted sources.

This installs:
- `ferret-scan` binary to `/usr/local/bin/`
- **Ready-to-use configuration** to `~/.ferret-scan/config.yaml` (from examples/ferret.yaml)
- Example configuration to `~/.ferret-scan/ferret.example.yaml`
- Pre-commit wrapper to `/usr/local/bin/ferret-scan-precommit`

#### Windows
```powershell
# Clone the repository
git clone <your-internal-repo-url>
cd ferret-scan

# Install system-wide (requires Administrator)
.\scripts\install-system-windows.ps1

# Or install for current user only (no admin required)
.\scripts\install-system-windows.ps1 -UserInstall

# Verify installation
ferret-scan --version
```

This installs:
- `ferret-scan.exe` binary to `C:\Program Files\FerretScan\` (system) or `%LOCALAPPDATA%\FerretScan\` (user)
- **Ready-to-use configuration** to `%APPDATA%\ferret-scan\config.yaml` (from examples/ferret.yaml)
- Example configuration to `%APPDATA%\ferret-scan\ferret.example.yaml`
- Adds installation directory to PATH environment variable

**Note:** For IP detection and full functionality, you also need a project-specific `ferret.yaml` configuration file in your repository root.

## Installation Methods

### 1. Python Package Installation (Recommended for Pre-commit)

The Python package provides the easiest way to use ferret-scan in pre-commit workflows:

```bash
# Install the Python package
pip install ferret-scan

# Verify installation
ferret-scan --version

# Use in pre-commit
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: ferret-scan --pre-commit-mode
        language: python
        files: \.(py|js|ts|go|java|json|yaml|yml)$
        pass_filenames: true
EOF

# Install pre-commit hooks
pre-commit install

# Copy configuration file for IP detection
cp examples/ferret.yaml ferret.yaml
git add ferret.yaml
```

**Features:**
- ✅ Automatic binary management
- ✅ Cross-platform compatibility  
- ✅ No manual binary downloads
- ✅ Perfect for pre-commit integration
- ✅ Supports all ferret-scan features

**Important:** The Python package requires a `ferret.yaml` configuration file in your project root for IP detection and full functionality.

### 2. Automated System Installation (Recommended for Teams)

#### Linux/macOS
The automated installer handles everything:

```bash
# Basic installation
sudo scripts/install-system.sh

# Custom installation directory
sudo scripts/install-system.sh --install-dir /opt/bin

# Skip configuration files
sudo scripts/install-system.sh --no-config

# Install from existing binary
sudo scripts/install-system.sh binary ./ferret-scan-linux-amd64
```

#### Windows
The PowerShell installer provides the same functionality:

```powershell
# Basic installation (requires Administrator)
.\scripts\install-system-windows.ps1

# User installation (no admin required)
.\scripts\install-system-windows.ps1 -UserInstall

# Custom installation directory
.\scripts\install-system-windows.ps1 -InstallDir "C:\Tools\FerretScan"

# Skip configuration files
.\scripts\install-system-windows.ps1 -NoConfig

# Install from existing binary
.\scripts\install-system-windows.ps1 binary .\ferret-scan.exe
```

**Features:**
- ✅ System-wide availability
- ✅ Configuration management
- ✅ Pre-commit integration
- ✅ Automatic PATH setup
- ✅ Easy uninstallation

### 3. Manual System Installation

#### Linux/macOS
```bash
# Build from source
make build

# macOS: Handle security for built binary BEFORE installation
chmod +x bin/ferret-scan
xattr -d com.apple.quarantine bin/ferret-scan

# Install manually to /usr/local/bin/
sudo cp bin/ferret-scan /usr/local/bin/
sudo chmod +x /usr/local/bin/ferret-scan

# Verify
ferret-scan --version
```

#### Windows
```powershell
# Build from source
make build-windows

# Install manually (requires Administrator for system-wide)
New-Item -ItemType Directory -Path "C:\Program Files\FerretScan" -Force
Copy-Item bin\ferret-scan.exe "C:\Program Files\FerretScan\ferret-scan.exe"

# Add to PATH
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
$newPath = "C:\Program Files\FerretScan;$currentPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")

# Verify (restart terminal first)
ferret-scan --version
```

### 4. Local Development Installation

For development work without system-wide installation:

#### Linux/macOS
```bash
# Build locally
make build

# Use directly
./bin/ferret-scan --version

# Or add to PATH temporarily
export PATH="$(pwd)/bin:$PATH"
```

#### Windows
```powershell
# Build locally
make build-windows

# Use directly
.\bin\ferret-scan.exe --version

# Or add to PATH temporarily
$env:PATH = "$(Get-Location)\bin;$env:PATH"
```

### 4. Container Installation

```bash
# Build container
make container-build

# Run in container
make container-run
```

## Pre-commit Integration Setup

After system installation, set up pre-commit hooks:

### Option 1: Automated Setup

```bash
# In your project repository
scripts/setup-pre-commit.sh
```

Choose from:
1. **STRICT** - Block commits on high-confidence findings
2. **BALANCED** - Block on high, warn on medium
3. **ADVISORY** - Show findings but never block
4. **SECRETS** - Focus only on API keys and secrets

### Option 2: Manual Pre-commit Setup

```bash
# Install pre-commit if needed
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan Security Check
        entry: ferret-scan-precommit
        language: system
        files: '\.(go|js|py|java|txt|md|yaml|yml|json|xml|sql|sh)$'
        exclude: '^(test_|_test\.|spec_|_spec\.)'
        env:
          FERRET_CONFIDENCE: "high,medium"
          FERRET_CHECKS: "all"
          FERRET_FAIL_ON: "high"
EOF

# Install hooks
pre-commit install
```

### Option 3: Direct Binary Integration

If you prefer to use the binary directly in pre-commit:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan Security Check
        entry: ferret-scan
        language: system
        args: ['--file', '--confidence', 'high,medium', '--format', 'text', '--quiet']
        files: '\.(go|js|py|java|txt|md|yaml|yml|json|xml|sql|sh)$'
```

## Team Deployment Strategies

### Strategy 1: Centralized Installation (Recommended)

**For internal company repos with shared infrastructure:**

```bash
# On shared development servers/containers
sudo scripts/install-system.sh

# Developers just clone and use
git clone <repo>
cd project
pre-commit install  # Uses system ferret-scan
```

**Pros:**
- Consistent versions across team
- No individual setup required
- Easy updates
- Better performance

### Strategy 2: Individual Installation

**For distributed teams:**

```bash
# Each developer installs
git clone <ferret-scan-repo>
cd ferret-scan
sudo scripts/install-system.sh

# Then in their projects
scripts/setup-pre-commit.sh
```

### Strategy 3: Container-based Development

**For containerized development environments:**

```dockerfile
# In your development Dockerfile
FROM golang:1.21

# Install ferret-scan
COPY ferret-scan/ /tmp/ferret-scan/
RUN cd /tmp/ferret-scan && \
    make build && \
    cp bin/ferret-scan /usr/local/bin/ && \
    chmod +x /usr/local/bin/ferret-scan && \
    rm -rf /tmp/ferret-scan

# Install pre-commit
RUN pip install pre-commit
```

## Configuration Management

### Pre-commit Profile Configuration

Ferret Scan includes a built-in pre-commit profile that automatically optimizes settings for pre-commit workflows:

```yaml
# ferret.yaml - Project configuration
defaults:
  confidence_levels: "high,medium"
  checks: "CREDIT_CARD,SECRETS,SSN,EMAIL"

profiles:
  precommit:
    description: "Pre-commit optimized profile"
    confidence_levels: "high"
    checks: "CREDIT_CARD,SECRETS,SSN"
    quiet: true
    no_color: true
    batch_size: 50
```

**Automatic Pre-commit Detection:**
Ferret Scan automatically detects pre-commit environments by checking for:
- `PRE_COMMIT` environment variable
- `_PRE_COMMIT_RUNNING` environment variable  
- `PRE_COMMIT_HOME` environment variable

When detected, it automatically enables:
- Quiet mode (reduced output)
- No color output (terminal compatibility)
- Optimized batch processing
- Appropriate exit codes for commit blocking

### User Configuration

After installation, configure user-specific settings:

```bash
# Create user config directory
mkdir -p ~/.ferret-scan

# Copy default config
cp config.yaml ~/.ferret-scan/config.yaml

# Edit user settings
vim ~/.ferret-scan/config.yaml
```

### Team Configuration

Set up team-specific configuration in your project:

```bash
# Create team config file
cat > ferret.yaml << 'EOF'
defaults:
  confidence_levels: "high,medium"
  checks: "CREDIT_CARD,SECRETS,SSN,EMAIL"
  quiet: false
  no_color: false

profiles:
  precommit:
    description: "Pre-commit optimized profile"
    confidence_levels: "high"
    checks: "CREDIT_CARD,SECRETS,SSN"
    quiet: true
    no_color: true

  strict:
    description: "High security profile"
    confidence_levels: "high,medium,low"
    checks: "all"
    fail_on_first: true
EOF

# Commit team configuration
git add ferret.yaml
git commit -m "Add ferret-scan team configuration"
```

**Simplified Team Setup:**
With direct pre-commit integration, teams can now use a single configuration file instead of complex wrapper scripts.

### Configuration Hierarchy

Ferret Scan looks for configuration files in this order:

1. **Project-specific**: `.ferret-scan.yaml` (in current directory)
2. **User-specific**: `~/.ferret-scan/config.yaml` (user home directory)
3. **Built-in defaults**: Embedded in the binary

```bash
# Project configuration (commit to repo)
vim .ferret-scan.yaml

# User configuration (personal settings)
vim ~/.ferret-scan/config.yaml

# Suppressions (keep local)
vim ~/.ferret-scan/suppressions.yaml
```

## Verification and Testing

### Test System Installation

```bash
# Check binary availability
which ferret-scan
ferret-scan --version

# Test basic functionality
echo "4111-1111-1111-1111" | ferret-scan --config ~/.ferret-scan/config.yaml --file -

# Test pre-commit integration
echo "test-data: sk_test_123" > test.yaml
ferret-scan-precommit test.yaml
rm test.yaml
```

### Test Pre-commit Integration

```bash
# In a git repository
echo "Credit card: 4111-1111-1111-1111" > sensitive.txt
git add sensitive.txt
git commit -m "Test commit"  # Should be blocked

# Clean up
git reset HEAD~1
rm sensitive.txt
```

## Troubleshooting

### Common Issues

**1. "ferret-scan: command not found"**
```bash
# Check installation
ls -la /usr/local/bin/ferret-scan

# Check PATH
echo $PATH | grep -o '/usr/local/bin'

# Add to PATH if missing
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**2. "Permission denied"**
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/ferret-scan
sudo chmod +x /usr/local/bin/ferret-scan-precommit
```

**3. "Build failed"**
```bash
# Check Go installation
go version

# Check dependencies
go mod tidy

# Clean and rebuild
make clean
make build
```

**4. Pre-commit not working**
```bash
# Check pre-commit installation
pre-commit --version

# Reinstall hooks
pre-commit uninstall
pre-commit install

# Test manually
pre-commit run ferret-scan --all-files
```

### Windows-Specific Issues

**1. "'ferret-scan' is not recognized as an internal or external command"**
```powershell
# Check installation
Test-Path "C:\Program Files\FerretScan\ferret-scan.exe"

# Check PATH
$env:PATH -split ';' | Where-Object { $_ -like "*FerretScan*" }

# Add to PATH if missing (requires Administrator)
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
$newPath = "C:\Program Files\FerretScan;$currentPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")

# Restart terminal and test
ferret-scan --version
```

**2. "Access denied" or "Permission denied"**
```powershell
# Run PowerShell as Administrator for system-wide installation
# Or use user installation instead
.\scripts\install-system-windows.ps1 -UserInstall

# Check file permissions
Get-Acl "C:\Program Files\FerretScan\ferret-scan.exe"
```

**3. "Build failed" on Windows**
```powershell
# Check Go installation
go version

# Check dependencies
go mod tidy

# Clean and rebuild for Windows
make clean
make build-windows

# Check for Windows-specific build issues
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o bin\ferret-scan.exe cmd\main.go
```

**4. Long path issues**
```powershell
# Enable long path support in Windows 10/11
# Run as Administrator:
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Or use UNC paths for very long paths
# \\?\C:\very\long\path\to\file
```

**5. PowerShell execution policy issues**
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Allow script execution (run as Administrator)
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Or bypass for single script
PowerShell -ExecutionPolicy Bypass -File .\scripts\install-system-windows.ps1
```

### Debug Mode

Enable debug output for troubleshooting:

#### Linux/macOS
```bash
# Debug system installation
sudo FERRET_DEBUG=1 scripts/install-system.sh

# Debug pre-commit
FERRET_DEBUG=1 ferret-scan-precommit test-file.py

# Debug binary directly
ferret-scan --config ferret.yaml --debug --file test-file.py
```

#### Windows
```powershell
# Debug system installation
$env:FERRET_DEBUG=1; .\scripts\install-system-windows.ps1

# Debug binary directly
$env:FERRET_DEBUG=1; ferret-scan --config ferret.yaml --debug --file test-file.py

# Or set environment variable persistently
[Environment]::SetEnvironmentVariable("FERRET_DEBUG", "1", "User")
ferret-scan --config ferret.yaml --debug --file test-file.py
```

## Uninstallation

### Complete Removal

#### Linux/macOS
```bash
# Uninstall system-wide installation
sudo scripts/install-system.sh uninstall

# Remove user configuration
rm -rf ~/.ferret-scan

# Remove pre-commit hooks (per project)
pre-commit uninstall
```

#### Windows
```powershell
# Uninstall system-wide installation
.\scripts\install-system-windows.ps1 uninstall

# Remove user configuration manually if needed
Remove-Item "$env:APPDATA\ferret-scan" -Recurse -Force

# Remove pre-commit hooks (per project)
pre-commit uninstall
```

### Partial Removal

#### Linux/macOS
```bash
# Remove only binary
sudo rm /usr/local/bin/ferret-scan
sudo rm /usr/local/bin/ferret-scan-precommit

# Keep configuration
# /etc/ferret-scan/ remains
```

#### Windows
```powershell
# Remove only binary
Remove-Item "C:\Program Files\FerretScan\ferret-scan.exe" -Force

# Remove from PATH manually through System Properties > Environment Variables
# Keep configuration in %APPDATA%\ferret-scan\
```

## Advanced Installation Options

### Custom Installation Locations

```bash
# Install to custom directory
sudo scripts/install-system.sh --install-dir /opt/ferret-scan/bin

# Update PATH
echo 'export PATH="/opt/ferret-scan/bin:$PATH"' >> ~/.bashrc
```

### Network Installation

For air-gapped environments:

```bash
# Build on connected machine
make build
tar -czf ferret-scan-bundle.tar.gz bin/ scripts/ config.yaml

# Transfer to air-gapped machine
scp ferret-scan-bundle.tar.gz target-machine:

# Install on air-gapped machine
tar -xzf ferret-scan-bundle.tar.gz
sudo scripts/install-system.sh binary bin/ferret-scan
```

### CI/CD Integration

For automated deployment:

```bash
# In your CI/CD pipeline
git clone <ferret-scan-repo>
cd ferret-scan
make build
sudo scripts/install-system.sh --no-config --no-precommit
```

## Best Practices

### For Development Teams

1. **Use system-wide installation** for consistency
2. **Set up team configuration** in project repos
3. **Use suppressions** for legitimate false positives
4. **Start with advisory mode** and gradually increase strictness
5. **Document team-specific configuration** decisions

### For Production Deployment

1. **Pin specific versions** in your deployment scripts
2. **Test configuration changes** in staging first
3. **Monitor suppression usage** to prevent abuse
4. **Set up centralized logging** for security findings
5. **Regular security reviews** of suppression rules

### For Security Teams

1. **Audit installation scripts** before deployment
2. **Monitor system-wide configuration** changes
3. **Review team suppression files** regularly
4. **Set up alerts** for high-confidence findings
5. **Maintain documentation** for security policies

## Support

For installation issues:
- Check the [troubleshooting section](#troubleshooting)
- Review system logs: `journalctl -u ferret-scan` (if using systemd)
- Test with debug mode: `FERRET_DEBUG=1 ferret-scan --version`
- Contact your internal DevSecOps team

For configuration help:
- See [Configuration Guide](configuration.md)
- Review [Pre-commit Integration](PRE_COMMIT_INTEGRATION.md)
- Check [Suppression System](user-guides/README-Suppressions.md)