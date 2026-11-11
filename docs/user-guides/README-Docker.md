# Container Usage Guide (Docker/Finch)

[← Back to Documentation Index](../README.md)

This guide covers running Ferret Scan in containers using either Docker or Finch.

## Pulling the Prebuilt Image (Recommended)

Multi-architecture images (linux/amd64 + linux/arm64) are published to **Amazon ECR Public** — no build required:

```bash
# Pull the latest release
docker pull public.ecr.aws/awslabs/ferret-scan:latest   # or: finch pull ...

# Pin to a specific version (recommended for CI)
docker pull public.ecr.aws/awslabs/ferret-scan:1.10.0
```

Gallery: <https://gallery.ecr.aws/awslabs/ferret-scan>

The examples below use the short `ferret-scan` tag; substitute
`public.ecr.aws/awslabs/ferret-scan:latest` to run the prebuilt image directly.

## Building the Container Image

Prefer the prebuilt image above unless you are developing Ferret Scan itself.

```bash
# Build with auto-detection (recommended - includes version info)
make container-build

# Or build manually with Docker/Finch
./scripts/container-build.sh

# Or build directly (without version injection)
docker build -t ferret-scan .  # if using Docker
finch build -t ferret-scan .   # if using Finch
```

## Running the Container

### Web UI Mode

```bash
# Start web UI on port 8080 (basic mode - no persistent suppressions)
docker run -p 127.0.0.1:8080:8080 ferret-scan --web --port 8080

# With persistent config and suppressions (RECOMMENDED)
docker run -p 127.0.0.1:8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --web --port 8080

# Custom port
docker run -p 127.0.0.1:3000:3000 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --web --port 3000
```

The `127.0.0.1:` prefix keeps the UI on this machine: inside the container the server binds
`0.0.0.0` (the image sets `FERRET_CONTAINER_MODE=true`), so the publish is the boundary, and to use
the UI from another machine you forward the port over SSH from that machine
(`ssh -L 8080:127.0.0.1:8080 <docker-host>`, then open `http://localhost:8080`) rather than
publishing it more widely. Keep every port on the way equal (the host port, the container port,
`--port` and a tunnel's local port), as the custom-port line does: the UI refuses a scan whose
browser `Origin` names a port other than the one it listens on.

### CLI Mode

```bash
# Run CLI with a file from host system (with colored output)
docker run --rm -t -v $(pwd):/data ferret-scan --file /data/sample.txt

# With persistent config and suppressions
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --file /data/sample.txt

# Run with debug output
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --file /data/sample.txt --debug

# Scan multiple files (quote the glob pattern)
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --file "/data/*.pdf"

# Scan directory recursively
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --file /data --recursive
```

**Notes**:
- The image's entrypoint is `/ferret-scan`, so everything after the image name is an argument to
  it: do not repeat `ferret-scan` there. `docker run ... ferret-scan ferret-scan --file ...` reads
  the second `ferret-scan` and every argument after it as input paths, and exits 1 with an error
  that names `--file` as an input path that does not exist.
- When using glob patterns (like `*.pdf`), always quote them to prevent shell expansion

## Usage Examples

### Container Runtime Notes

#### Docker
- Standard container runtime with broad compatibility
- Full feature support including health checks
- Widely available on most platforms

#### Finch
- Lightweight alternative to Docker on macOS and Linux
- Uses same container images and commands as Docker
- May have slightly different networking behavior on some systems
- All Ferret Scan features work identically

### Web UI Features
- **File Upload**: Upload single or multiple files through browser
- **Real-time Results**: See scan results as files are processed
- **All CLI Options**: Access to confidence levels, check types
- **Progress Tracking**: Visual progress for multi-file scans

### CLI Features
- **Batch Processing**: Scan multiple files with quoted glob patterns
- **Output Formats**: Text, JSON, CSV, YAML, JUnit XML, GitLab SAST or SARIF 2.1.0 report output
- **Configuration**: YAML config files and profiles
- **Directory Scanning**: Recursive directory processing
- **Colored Output**: Use `-t` flag for colored terminal output
- **Auto Cleanup**: Use `--rm` flag to automatically remove containers after execution

## Volume Mapping

### Required Volumes
- `-v $(pwd):/data` - Mount current directory for file access

### Optional Volumes
- `-v ~/.ferret-scan:/home/ferret/.ferret-scan` - Persist config and suppressions

### Directory Structure in Container
```
/home/ferret/.ferret-scan/
├── config.yaml        # Configuration file
└── suppressions.yaml  # Suppression rules
```

### Environment Variables
- `FERRET_CONFIG_DIR` - Config directory location. The image does not set it (nor
  `XDG_CONFIG_HOME`), so the config directory is `$HOME/.ferret-scan`: `/home/ferret/.ferret-scan`
  for the image's user `ferret`, the directory the examples above mount. Pass
  `-e FERRET_CONFIG_DIR=<dir>` to read another one.
- `FERRET_CONTAINER_MODE` - Set to `true` in the image. It makes the web UI bind
  `0.0.0.0` instead of `127.0.0.1`, so the port publish works; `--bind` overrides it.
- `TMPDIR` - Set to `/home/ferret/tmp` in the image, a directory user `ferret` owns.

The web UI port is a flag, not an environment variable — `--web --port 8080`, as in
`docker-compose.yml`. There is no `PORT` variable: it is read nowhere, and with
`PORT=9999 ferret-scan --web --port 8091` the server binds 8091 and 9999 refuses.

## Troubleshooting

### Suppressed Findings Not Working

If suppressed findings aren't working in the container:

1. **Verify correct volume mapping**:
   ```bash
   # Correct mapping (host:container)
   docker run -p 127.0.0.1:8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --web --port 8080

   # NOT this (wrong container path)
   # docker run -p 127.0.0.1:8080:8080 -v ~/.ferret-scan:/root/.ferret-scan ferret-scan --web --port 8080
   ```

2. **Check if suppression file exists and is accessible**:
   ```bash
   # Check if your local suppression file exists
   ls -la ~/.ferret-scan/suppressions.yaml

   # If it doesn't exist, create the directory and file
   mkdir -p ~/.ferret-scan
   echo 'version: "1.0"' > ~/.ferret-scan/suppressions.yaml
   echo 'rules: []' >> ~/.ferret-scan/suppressions.yaml
   ```

3. **Verify volume mounting works**:
   ```bash
   # Print the suppression file as the container sees it (the image has no shell and no cat)
   docker run --rm -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --file /home/ferret/.ferret-scan/suppressions.yaml --preprocess-only
   ```
   `Error: Input path does not exist` means nothing is mounted at that path. `warning: cannot read
   suppression file … permission denied` means user `ferret` (UID 1000) cannot read it: see
   [Permission Issues](#permission-issues).

4. **Check which config file the container reads**:
   ```bash
   # The image does not set FERRET_CONFIG_DIR; --debug names the config file a scan read
   docker run --rm -v ~/.ferret-scan:/home/ferret/.ferret-scan -v $(pwd):/data ferret-scan --file /data/sample.txt --debug 2>&1 | grep 'settings come from'
   ```
   With a `config.yaml` in the mounted directory and no profile, the line ends
   `settings come from /home/ferret/.ferret-scan/config.yaml (auto-discovered) and the flags`;
   without one, `settings come from the built-in configuration and the flags`.



### Debug Output Issues

If you see excessive debug output:

1. **Check if debug mode is enabled**: The web UI should run in quiet mode by default
2. **Restart the container**: Debug output should be minimal in production mode

### Permission Issues

If you encounter permission issues:

1. **Check volume permissions**:
   ```bash
   # Ensure your local .ferret-scan directory is readable
   chmod 755 ~/.ferret-scan
   chmod 644 ~/.ferret-scan/*.yaml 2>/dev/null || true
   ```

2. **User ID mismatch**: Container runs as user `ferret` (UID 1000)
   ```bash
   # Check your user ID
   id -u

   # If your UID is not 1000, you may need to adjust permissions
   sudo chown -R 1000:1000 ~/.ferret-scan

   # Or run container as your user (less secure)
   docker run --user $(id -u):$(id -g) -p 127.0.0.1:8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan --web --port 8080
   ```



## Image Details

- **Base Image**: `scratch`, which is empty: no shell, no package manager, no CA certificates.
  The image holds the static binary (`/ferret-scan`), `/etc/passwd` and `/etc/group` for user
  `ferret`, `/tmp`, and `/home/ferret` with its `.ferret-scan` and `tmp` directories
- **Multi-stage build**: Builder stage with Go toolchain, minimal runtime stage
- **User**: Runs as non-root user `ferret` (UID 1000)
- **Size**: Optimized with cache cleanup
- **Default Mode**: CLI mode (use `--web` flag for web UI)
- **Binary**: Single `ferret-scan` executable with both CLI and web capabilities
- **Volumes**: `/home/ferret/.ferret-scan` for persistent data
