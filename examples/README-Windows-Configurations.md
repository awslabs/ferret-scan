# Windows Configuration

This directory contains `ferret-windows.yaml` — the Windows variant of the main `ferret.yaml` example configuration.

## What's Different from the Main Config

The Windows config mirrors `ferret.yaml` exactly (same profiles, same defaults) but adds:

- **Platform section** — `platform.windows` settings for APPDATA usage, long path support, system-wide install options
- **Windows paths** — Redaction output and audit log paths use `%USERPROFILE%`, `%LOCALAPPDATA%`, `%TEMP%`
- **Windows excludes** — Adds `desktop.ini` and `Thumbs.db`
- **Microsoft infrastructure patterns** — Commented-out SharePoint/Teams/Active Directory URL patterns

## Usage

```powershell
# Copy to your project root
Copy-Item examples\ferret-windows.yaml ferret.yaml

# Or reference directly
ferret-scan.exe --config examples\ferret-windows.yaml --file . --recursive

# Use a profile
ferret-scan.exe --profile ci --file .
ferret-scan.exe --profile precommit --file .\src\app.py

# Web mode
ferret-scan.exe --web --port 8080
```

## Profiles

The same 5 profiles as the main config:

| Profile      | Format      | Use Case                                                                     |
| ------------ | ----------- | ---------------------------------------------------------------------------- |
| `cli`        | text        | Interactive terminal scanning                                                |
| `web`        | json        | Web UI (`--web` mode)                                                        |
| `ci`         | gitlab-sast | Azure DevOps, GitHub Actions, GitLab CI (change to `junit`/`sarif` as needed)|
| `precommit`  | text        | Git pre-commit hooks                                                         |
| `redaction`  | text        | Scan and redact to `%USERPROFILE%\Documents\ferret-redacted`                 |

## PowerShell Integration

```powershell
# Parse JSON output in PowerShell
$results = ferret-scan.exe --profile ci --format json --file . | ConvertFrom-Json
$results | Where-Object { $_.confidence -ge 80 } | Format-Table

# Pre-commit with Husky or similar
ferret-scan.exe --pre-commit-mode --profile precommit --respect-gitignore --allow-project-config
```

`--allow-project-config` is needed because the `ferret.yaml` copied above sits in the working directory:
in pre-commit mode such a file is refused without it (see
[Pre-commit integration](../docs/PRE_COMMIT_INTEGRATION.md#a-project-config-in-a-hook)).

## Enterprise Deployment (GPO/SCCM)

For system-wide deployment, set in the platform section:

```yaml
platform:
  windows:
    system_wide_install: true
    use_appdata: false
    config_dir: "%PROGRAMDATA%\\ferret-scan"
    temp_dir: "%PROGRAMDATA%\\ferret-scan\\temp"
```

## See Also

- [Windows Installation Guide](../docs/WINDOWS_INSTALLATION.md)
- [Windows Troubleshooting](../docs/troubleshooting/WINDOWS_TROUBLESHOOTING.md)
- [Windows Development](../docs/development/WINDOWS_DEVELOPMENT.md)
