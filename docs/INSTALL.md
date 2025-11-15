# Ferret Scan Installation

Quick installation guide for release downloads.

## 🚀 Quick Start

### 1. System-wide Installation (Recommended)

#### Linux/macOS
```bash
# After extracting the release archive:
# macOS: Handle security for downloaded binary installation
chmod +x ferret-scan
xattr -d com.apple.quarantine ferret-scan

# System-wide installation (installs to /usr/local/bin/ferret-scan)
sudo scripts/install-system.sh

# Set up pre-commit integration:
pip install pre-commit
# See docs/PRE_COMMIT_INTEGRATION.md for configuration examples

# Test installation:
ferret-scan --version
```

**⚠️ macOS Security Note**: If macOS blocks execution with "cannot be opened because it is from an unidentified developer", run these commands on the downloaded binary BEFORE installation:
```bash
chmod +x ferret-scan
xattr -d com.apple.quarantine ferret-scan
```
Only use these commands for executables from trusted sources.

This installs:
- `ferret-scan` binary to `/usr/local/bin/`
- Ready-to-use configuration to `~/.ferret-scan/config.yaml`
- Pre-commit wrapper to `/usr/local/bin/ferret-scan-precommit`

#### Windows
```powershell
# After extracting the release archive:
# Run PowerShell as Administrator and install system-wide
.\scripts\install-system-windows.ps1

# Or install for current user only (no admin required)
.\scripts\install-system-windows.ps1 -UserInstall

# Set up pre-commit integration:
pip install pre-commit
# See docs/PRE_COMMIT_INTEGRATION.md for configuration examples

# Test installation:
ferret-scan --version
```

This installs:
- `ferret-scan.exe` binary to `C:\Program Files\FerretScan\` (system) or `%LOCALAPPDATA%\FerretScan\` (user)
- Ready-to-use configuration to `%APPDATA%\ferret-scan\config.yaml`
- Adds installation directory to PATH environment variable

### 2. Manual Installation

#### Linux/macOS
```bash
# Make binary executable and handle macOS security
chmod +x ferret-scan
xattr -d com.apple.quarantine ferret-scan  # macOS only

# Move to system location
sudo mv ferret-scan /usr/local/bin/

# Copy configuration
mkdir -p ~/.ferret-scan
cp config.yaml ~/.ferret-scan/

# Test
ferret-scan --version
```

#### Windows
```powershell
# Create installation directory
New-Item -ItemType Directory -Path "C:\Program Files\FerretScan" -Force

# Copy binary to installation directory
Copy-Item ferret-scan.exe "C:\Program Files\FerretScan\ferret-scan.exe"

# Add to PATH (requires Administrator)
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
$newPath = "C:\Program Files\FerretScan;$currentPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")

# Copy configuration
New-Item -ItemType Directory -Path "$env:APPDATA\ferret-scan" -Force
Copy-Item config.yaml "$env:APPDATA\ferret-scan\config.yaml"

# Test (restart terminal first)
ferret-scan --version
```

## 📖 Complete Documentation

For comprehensive installation options, see:

- [docs/INSTALLATION.md](INSTALLATION.md) - Full installation guide
- [docs/PRE_COMMIT_INTEGRATION.md](PRE_COMMIT_INTEGRATION.md) - Git integration
- [README.md](../README.md) - Complete project documentation

## 🔧 Usage

```bash
# Basic scan
ferret-scan --file document.txt

# Web interface
ferret-scan --web

# Pre-configured profiles
ferret-scan --file . --recursive --profile quick
```

## 🗑️ Uninstallation

To remove Ferret Scan:

#### Linux/macOS
```bash
# Complete removal
sudo scripts/install-system.sh uninstall

# Or using Makefile
make uninstall
```

#### Windows
```powershell
# Complete removal
.\scripts\install-system-windows.ps1 uninstall

# Or manual removal
Remove-Item "C:\Program Files\FerretScan\ferret-scan.exe" -Force
# Remove from PATH manually through System Properties > Environment Variables
```

See [docs/UNINSTALL.md](UNINSTALL.md) for complete uninstallation options.

## 🆘 Support

If you encounter issues:

1. Check [docs/INSTALLATION.md](INSTALLATION.md) troubleshooting section
2. **Windows users:** Check [docs/troubleshooting/WINDOWS_TROUBLESHOOTING.md](troubleshooting/WINDOWS_TROUBLESHOOTING.md)
3. Check [docs/UNINSTALL.md](UNINSTALL.md) for removal issues
4. Verify permissions:
   - Linux/macOS: `ls -la /usr/local/bin/ferret-scan`
   - Windows: `Test-Path "C:\Program Files\FerretScan\ferret-scan.exe"`
5. Test configuration: `ferret-scan --list-profiles`
