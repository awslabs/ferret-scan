# Multi-Architecture Docker Build Guide

This document explains how to build and use multi-architecture Docker images for Ferret Scan using GitHub Actions.

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

The public image is published to **Amazon ECR Public**:

```
public.ecr.aws/awslabs/ferret-scan
```

Gallery: <https://gallery.ecr.aws/awslabs/ferret-scan>

> **Note:** The workflow also pushes the same digest to GitHub Container Registry
> (`ghcr.io/awslabs/ferret-scan`), but that package is **private** — public
> package visibility is disabled at the organization level, so it is not
> anonymously pullable. Use the ECR Public image for all external/public use.
> The GHCR mirror is retained only for authenticated internal consumers.

## Image Tags

The workflow automatically generates multiple tags:

- `latest` - Latest tagged release
- `1.2.3` - Exact version tag
- `1.2` - Minor version tag
- `main` - Latest main branch (development) build
- `pr-123` - Pull request builds (not pushed)

## Usage Examples

### Pull and Run

```bash
# Pull the latest image
docker pull public.ecr.aws/awslabs/ferret-scan:latest

# Run in CLI mode
docker run --rm -v $(pwd):/data \
  public.ecr.aws/awslabs/ferret-scan:latest \
  --file /data/sample.txt

# Run in web mode
docker run --rm -p 8080:8080 \
  public.ecr.aws/awslabs/ferret-scan:latest \
  --web --port 8080
```

### Platform-Specific Pulls

```bash
# Force ARM64 on Apple Silicon
docker pull --platform linux/arm64 \
  public.ecr.aws/awslabs/ferret-scan:latest

# Force AMD64 on any system
docker pull --platform linux/amd64 \
  public.ecr.aws/awslabs/ferret-scan:latest
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

3. **Registry Authentication**: Check credentials
   - ECR Public push uses AWS OIDC (`id-token: write` + the `AWS_ROLE_ARN` secret)
   - GHCR push uses `GITHUB_TOKEN` with `packages: write`

### Testing Multi-Arch Images

```bash
# Inspect image manifest
docker buildx imagetools inspect public.ecr.aws/awslabs/ferret-scan:latest

# Test specific architecture
docker run --platform linux/arm64 --rm \
  public.ecr.aws/awslabs/ferret-scan:latest --version
```

## Configuration

### Workflow Inputs

When manually triggering the workflow:

- **platforms**: Comma-separated list (e.g., `linux/amd64,linux/arm64`)
- **push_image**: Whether to push to registry (true/false)

### Environment Variables

The registry targets are defined at the top of `docker-multiarch.yml`:

- `ECR_REGISTRY` / `ECR_REPOSITORY` - the public ECR Public target
- `GHCR_REGISTRY` / `GHCR_REPOSITORY` - the private GHCR mirror

## Best Practices

1. **Test Locally First**
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 -t test .
   ```

2. **Use Specific Tags**
   ```bash
   # Prefer specific versions over 'latest'
   docker pull public.ecr.aws/awslabs/ferret-scan:1.2.3
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
2. **Configure repository secrets** if needed (`AWS_ROLE_ARN` for ECR Public)
3. **Set up branch protection** to require successful builds
4. **Configure Dependabot** for automated dependency updates
