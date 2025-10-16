# Ferret Scan Uninstallation Guide

Complete guide for removing Ferret Scan from your system.

## 🗑️ Quick Uninstall

### System-wide Installation

```bash
# Using the install script (recommended)
sudo scripts/install-system.sh uninstall

# Or using Makefile
make uninstall
```

### Manual Uninstall

```bash
# Remove binaries
sudo rm -f /usr/local/bin/ferret-scan
sudo rm -f /usr/local/bin/ferret-scan-precommit

# Remove user configuration (optional)
rm -rf ~/.ferret-scan
```

## 🧹 Complete Cleanup Options

### Option 1: Script-based Cleanup (Recommended)

```bash
# Interactive uninstall with options
sudo scripts/install-system.sh uninstall

# This will:
# ✓ Remove system binaries
# ✓ Ask about configuration directory
# ✓ Check for project pre-commit hooks
# ✓ Provide manual cleanup instructions
```

### Option 2: Makefile Cleanup

```bash
# Remove system installation only
make uninstall

# Remove pre-commit hooks from current project
make clean-precommit

# Clean all development artifacts
make clean-all

# Complete cleanup (everything)
make clean-everything
```

## 📋 What Gets Removed

### System Files
- `/usr/local/bin/ferret-scan` - Main binary
- `/usr/local/bin/ferret-scan-precommit` - Pre-commit wrapper

### User Configuration
- `~/.ferret-scan/config.yaml` - User configuration
- `~/.ferret-scan/ferret.example.yaml` - Example configuration
- `~/.ferret-scan/suppressions.yaml` - User suppressions (if exists)

### Project Files (Manual Cleanup)
- `.ferret-scan.yaml` - Project configuration
- `.ferret-scan-suppressions.yaml` - Project suppressions
- `.git/hooks/pre-commit` - Git pre-commit hook (if manually installed)
- `.pre-commit-config.yaml` - Pre-commit framework config

## 🔍 Verification

After uninstallation, verify removal:

```bash
# Check binaries are removed
which ferret-scan                    # Should return nothing
which ferret-scan-precommit          # Should return nothing

# Check configuration is removed
ls -la ~/.ferret-scan/               # Should not exist (if removed)

# Check pre-commit integration
pre-commit run ferret-scan --all-files  # Should fail if removed
```

## 🚨 Troubleshooting

### "Permission Denied" Errors

```bash
# Ensure you have sudo privileges
sudo ls /usr/local/bin/ferret-scan*

# If files exist but can't be removed:
sudo chmod +w /usr/local/bin/ferret-scan*
sudo rm -f /usr/local/bin/ferret-scan*
```

### Configuration Won't Delete

```bash
# Check ownership
ls -la ~/.ferret-scan/

# Fix permissions if needed
chmod -R u+w ~/.ferret-scan/
rm -rf ~/.ferret-scan/
```

### Pre-commit Hooks Still Running

```bash
# Remove from pre-commit framework
pre-commit uninstall

# Remove manual Git hook
rm -f .git/hooks/pre-commit

# Check .pre-commit-config.yaml
vim .pre-commit-config.yaml  # Remove ferret-scan entries
```

## 🔄 Partial Uninstall Options

### Keep Configuration, Remove Binaries

```bash
# Remove only system binaries
sudo rm -f /usr/local/bin/ferret-scan
sudo rm -f /usr/local/bin/ferret-scan-precommit

# Keep ~/.ferret-scan/ for future reinstallation
```

### Remove Pre-commit Integration Only

```bash
# Remove from current project
pre-commit uninstall
rm -f .git/hooks/pre-commit

# Edit .pre-commit-config.yaml to remove ferret-scan hook
# Keep system installation for manual use
```

### Clean Development Environment Only

```bash
# Remove build artifacts and caches
make clean-all

# Keep system installation intact
```

## 🔄 Reinstallation

After uninstallation, you can reinstall anytime:

```bash
# Download latest release
wget https://releases/ferret-scan_latest.tar.gz
tar -xzf ferret-scan_latest.tar.gz
cd ferret-scan_latest/

# Reinstall
sudo scripts/install-system.sh
```

## 📞 Support

If you encounter issues during uninstallation:

1. **Check permissions**: Ensure you have sudo access
2. **Manual cleanup**: Use the manual commands above
3. **Verify removal**: Use the verification commands
4. **Clean slate**: Remove all files manually if needed

### Manual Complete Removal

```bash
# Nuclear option - remove everything manually
sudo rm -f /usr/local/bin/ferret-scan*
rm -rf ~/.ferret-scan/
rm -f .git/hooks/pre-commit
pre-commit uninstall 2>/dev/null || true

# Clean Go module cache (if built from source)
go clean -modcache 2>/dev/null || true
```

## 🎯 Post-Uninstall Checklist

- [ ] System binaries removed (`which ferret-scan` returns nothing)
- [ ] User configuration removed (or preserved by choice)
- [ ] Pre-commit hooks removed from projects
- [ ] No ferret-scan entries in `.pre-commit-config.yaml`
- [ ] Build artifacts cleaned (if developed locally)
- [ ] Go module cache cleaned (if needed)

Your system is now clean of Ferret Scan installations! 🎉