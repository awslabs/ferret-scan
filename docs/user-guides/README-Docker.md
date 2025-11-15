# Container Usage Guide (Docker/Finch)

[← Back to Documentation Index](../README.md)

This guide covers running Ferret Scan in containers using either Docker or Finch.

## Building the Container Image

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

### Web UI Mode (Default)

```bash
# Start web UI on port 8080 (basic mode - no persistent suppressions)
docker run -p 8080:8080 ferret-scan

# With persistent config and suppressions (RECOMMENDED)
docker run -p 8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan

<!-- GENAI_DISABLED: With AWS credentials for GenAI features (using credentials file)
docker run -p 8080:8080 \
  -v ~/.ferret-scan:/home/ferret/.ferret-scan \
  -v ~/.aws:/home/ferret/.aws:ro \
  ferret-scan

# With AWS credentials for GenAI features (using environment variables)
docker run -p 8080:8080 \
  -v ~/.ferret-scan:/home/ferret/.ferret-scan \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  ferret-scan
-->

# Custom port
docker run -p 3000:8080 -e PORT=8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan
```

### CLI Mode

```bash
# Run CLI with a file from host system (with colored output)
docker run --rm -t -v $(pwd):/data ferret-scan ferret-scan --file /data/sample.txt

# With persistent config and suppressions
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan ferret-scan --file /data/sample.txt

<!-- GENAI_DISABLED: Run with GenAI enabled (using credentials file)
docker run --rm -t -v $(pwd):/data \
  -v ~/.ferret-scan:/home/ferret/.ferret-scan \
  -v ~/.aws:/home/ferret/.aws:ro \
  ferret-scan ferret-scan --file /data/sample.pdf --enable-genai

# Run with GenAI enabled (using environment variables)
docker run --rm -t -v $(pwd):/data \
  -v ~/.ferret-scan:/home/ferret/.ferret-scan \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  ferret-scan ferret-scan --file /data/sample.pdf --enable-genai
-->

# Run with debug output
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan ferret-scan --file /data/sample.txt --debug

# Scan multiple files (quote the glob pattern)
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan ferret-scan --file "/data/*.pdf"

# Scan directory recursively
docker run --rm -t -v $(pwd):/data -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan ferret-scan --file /data --recursive
```

**Notes**:
- When using glob patterns (like `*.pdf`), always quote them to prevent shell expansion
- AWS credentials can be passed via environment variables or mounted credentials file

<!-- GENAI_DISABLED: AWS Credentials for GenAI Features

To use GenAI features (Textract OCR, Transcribe, Comprehend), provide AWS credentials using one of these methods:
-->

### Method 1: Environment Variables
```bash
# Pass current shell environment variables
docker run -p 8080:8080 \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  ferret-scan

# Or specify values directly
docker run -p 8080:8080 \
  -e AWS_ACCESS_KEY_ID=AKIA... \
  -e AWS_SECRET_ACCESS_KEY=abc123... \
  -e AWS_SESSION_TOKEN=token... \
  ferret-scan
```

### Method 2: AWS Credentials File
```bash
# Mount your ~/.aws directory (read-only)
docker run -p 8080:8080 -v ~/.aws:/home/ferret/.aws:ro ferret-scan
```

### Method 3: Environment File
```bash
# Create .env file with credentials
echo "AWS_ACCESS_KEY_ID=AKIA..." > .env
echo "AWS_SECRET_ACCESS_KEY=abc123..." >> .env
echo "AWS_SESSION_TOKEN=token..." >> .env

# Use --env-file
docker run -p 8080:8080 --env-file .env ferret-scan
```

**Important**: Ensure your AWS credentials are not expired, especially session tokens from temporary credentials.

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
- **All CLI Options**: Access to confidence levels, check types<!-- GENAI_DISABLED: , GenAI features -->
- **Progress Tracking**: Visual progress for multi-file scans

### CLI Features
- **Batch Processing**: Scan multiple files with quoted glob patterns
- **Output Formats**: Text, JSON, CSV, YAML, JUnit XML, or GitLab SAST report output
- **Configuration**: YAML config files and profiles
<!-- GENAI_DISABLED: - **GenAI Integration**: Amazon Textract, Transcribe, and Comprehend -->
- **Directory Scanning**: Recursive directory processing
- **Colored Output**: Use `-t` flag for colored terminal output
- **Auto Cleanup**: Use `--rm` flag to automatically remove containers after execution

## Volume Mapping

### Required Volumes
- `-v $(pwd):/data` - Mount current directory for file access

### Optional Volumes
- `-v ~/.ferret-scan:/home/ferret/.ferret-scan` - Persist config and suppressions
<!-- GENAI_DISABLED: - `-v ~/.aws:/home/ferret/.aws:ro` - AWS credentials for GenAI features -->

### Directory Structure in Container
```
/home/ferret/.ferret-scan/
├── config.yaml        # Configuration file
└── suppressions.yaml  # Suppression rules
```

### Environment Variables
- `FERRET_CONFIG_DIR` - Config directory location (set to `/home/ferret/.ferret-scan` in container)
- `PORT` - Web UI port (default: 8080)
- `FERRET_CONTAINER_MODE` - Set to `true` in container for optimized operation
- `FERRET_QUIET_MODE` - Set to `true` in container to reduce debug output
- AWS credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`

## Troubleshooting

### Suppressed Findings Not Working

If suppressed findings aren't working in the container:

1. **Verify correct volume mapping**:
   ```bash
   # Correct mapping (host:container)
   docker run -p 8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan

   # NOT this (wrong container path)
   # docker run -p 8080:8080 -v ~/.ferret-scan:/root/.ferret-scan ferret-scan
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
   # Test if container can see your suppression file
   docker run --rm -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan cat /home/ferret/.ferret-scan/suppressions.yaml
   ```

4. **Check config directory environment variable**:
   ```bash
   # Verify the container is using the correct config directory
   docker run --rm -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan env | grep FERRET_CONFIG_DIR
   # Should show: FERRET_CONFIG_DIR=/home/ferret/.ferret-scan
   ```



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
   docker run --user $(id -u):$(id -g) -p 8080:8080 -v ~/.ferret-scan:/home/ferret/.ferret-scan ferret-scan
   ```



## Image Details

- **Base Image**: Amazon Linux 2023
- **Multi-stage build**: Builder stage with Go toolchain, minimal runtime stage
- **User**: Runs as non-root user `ferret` (UID 1000)
- **Size**: Optimized with cache cleanup
- **Default Mode**: CLI mode (use `--web` flag for web UI)
- **Binary**: Single `ferret-scan` executable with both CLI and web capabilities
- **Volumes**: `/home/ferret/.ferret-scan` for persistent data
