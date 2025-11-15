# Multi-Architecture Docker Build Guide

This document explains how to build and use multi-architecture Docker images for Ferret Scan using GitHub Actions and GitHub Container Registry.

## Overview

The multi-architecture Docker build workflow automatically creates container images for multiple CPU architectures:

- **linux/amd64** - Standard x86_64 architecture (Intel/AMD)
- **linux/arm64** - ARM 64-bit architecture (Apple Silicon, AWS Graviton)

## Workflow Triggers

The Docker build workflow (`docker-multiarch.yml`) runs on:

- **Push to main/master** - Full multi-arch build
- **Tags (v*)** - Release builds with semantic versioning
- **Pull Requests** - AMD64-only build for faster feedback
- **Manual dispatch** - Customizable platform selection

## Image Registry

Images are published to GitHub Container Registry (GHCR):
```
ghcr.io/[your-username]/[repository-name]
```

## Image Tags

The workflow automatically generates multiple tags:

- `latest` - Latest main branch build
- `v1.2.3` - Exact version tag
- `v1.2` - Minor version tag
- `v1` - Major version tag
- `main-sha123456` - Branch with commit SHA
- `pr-123` - Pull request builds

## Usage Examples

### Pull and Run

```bash
# Pull the latest image
docker pull ghcr.io/[your-username]/[repository-name]:latest

# Run in CLI mode
docker run --rm -v $(pwd):/data \
  ghcr.io/[your-username]/[repository-name]:latest \
  --file /data/sample.txt

# Run in web mode
docker run --rm -p 8080:8080 \
  ghcr.io/[your-username]/[repository-name]:latest \
  --web --port 8080
```

### Platform-Specific Pulls

```bash
# Force ARM64 on Apple Silicon
docker pull --platform linux/arm64 \
  ghcr.io/[your-username]/[repository-name]:latest

# Force AMD64 on any system
docker pull --platform linux/amd64 \
  ghcr.io/[your-username]/[repository-name]:latest
```

### Local Development

```bash
# Build locally for current platform
docker build -t ferret-scan:local .

# Build for specific platform
docker buildx build --platform linux/arm64 -t ferret-scan:arm64 .

# Use Docker Compose for development
docker-compose up ferret-scan

# Run CLI mode with Docker Compose
docker-compose --profile cli run --rm ferret-scan-cli
```

## Security Features

The workflow includes several security enhancements:

### Vulnerability Scanning
- **Trivy** - Comprehensive vulnerability scanner
- **Grype** - Additional vulnerability detection
- Results uploaded to GitHub Security tab

### Software Bill of Materials (SBOM)
- Generates SPDX-format SBOM
- Tracks all dependencies and components
- Available as workflow artifact

### Image Signing (Optional)
To enable image signing with Cosign, add these steps to your workflow:

```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3

- name: Sign container image
  run: |
    cosign sign --yes ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ steps.meta.outputs.version }}
```

## Performance Optimizations

### Build Cache
- Uses GitHub Actions cache for Docker layers
- Significantly reduces build times
- Shared across workflow runs

### Platform Strategy
- **PR builds**: AMD64 only for speed
- **Main builds**: Full multi-arch
- **Manual builds**: Customizable platforms

### Resource Limits
The Dockerfile is optimized for minimal resource usage:
- Multi-stage build reduces final image size
- Static binary compilation
- Scratch base image (~5-10MB final size)

## Troubleshooting

### Build Failures

1. **QEMU Issues**: ARM emulation can be slow or fail
   ```bash
   # Test QEMU locally
   docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
   ```

2. **Platform Mismatch**: Ensure your Dockerfile supports multi-arch
   ```dockerfile
   # Use TARGETPLATFORM build arg
   ARG TARGETPLATFORM
   RUN echo "Building for $TARGETPLATFORM"
   ```

3. **Registry Authentication**: Check GitHub token permissions
   - Ensure `packages: write` permission
   - Verify GITHUB_TOKEN is available

### Testing Multi-Arch Images

```bash
# Inspect image manifest
docker buildx imagetools inspect ghcr.io/[your-username]/[repository-name]:latest

# Test specific architecture
docker run --platform linux/arm64 --rm \
  ghcr.io/[your-username]/[repository-name]:latest --version
```

## Configuration

### Workflow Inputs

When manually triggering the workflow:

- **platforms**: Comma-separated list (e.g., `linux/amd64,linux/arm64`)
- **push_image**: Whether to push to registry (true/false)

### Environment Variables

- `REGISTRY`: Container registry URL (default: ghcr.io)
- `IMAGE_NAME`: Repository name (auto-detected)

## Best Practices

1. **Test Locally First**
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 -t test .
   ```

2. **Use Specific Tags**
   ```bash
   # Prefer specific versions over 'latest'
   docker pull ghcr.io/[your-username]/[repository-name]:v1.2.3
   ```

3. **Monitor Build Times**
   - ARM builds can take 2-3x longer than AMD64
   - Consider reducing platforms for development builds

4. **Security Scanning**
   - Review vulnerability reports in GitHub Security tab
   - Update base images regularly
   - Monitor SBOM for supply chain security

## Integration with Existing Workflows

The Docker workflow integrates with your existing CI/CD:

- **Ferret Scan Workflow**: Continues to run security scans
- **Release Workflow**: Can trigger Docker builds on tags
- **GoReleaser**: Complements binary releases with container images

## Next Steps

1. **Enable the workflow** by pushing to main branch
2. **Configure repository secrets** if needed
3. **Update documentation** with your specific registry URLs
4. **Set up branch protection** to require successful builds
5. **Configure Dependabot** for automated dependency updates
