# Docker Integration Guide

This guide covers using Ferret Scan with Docker and container-based workflows, including pre-commit hooks and CI/CD pipelines.

## Docker Image Features

Ferret Scan provides an ultra-minimal Docker image with the following characteristics:

- **Size**: ~5-10MB (scratch-based image)
- **Security**: Runs as non-root user (ferret:1000)
- **Flexibility**: Supports both CLI and web modes
- **Performance**: Static binary with no runtime dependencies
- **Compatibility**: Works with Docker, Finch, Podman, and other container runtimes

## Building the Docker Image

### Local Build

```bash
# Using Docker
docker build -t ferret-scan .

# Using Finch (Docker alternative)
finch build -t ferret-scan .

# Using Podman
podman build -t ferret-scan .
```

### Build Arguments

```bash
# Build with version information
docker build \
  --build-arg VERSION=1.0.0 \
  --build-arg GIT_COMMIT=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  -t ferret-scan:1.0.0 .
```

## Basic Usage

### CLI Mode

```bash
# Scan current directory
docker run --rm -v $(pwd):/data ferret-scan --file /data --recursive

# Scan specific file
docker run --rm -v $(pwd):/data ferret-scan --file /data/sensitive-file.py

# With configuration file
docker run --rm \
  -v $(pwd):/data \
  -v $(pwd)/ferret.yaml:/ferret.yaml \
  ferret-scan --config /ferret.yaml --file /data
```

### Web UI Mode

```bash
# Start web server on port 8080
docker run --rm -p 8080:8080 ferret-scan --web --port 8080

# Custom port
docker run --rm -p 9000:9000 ferret-scan --web --port 9000

# With persistent configuration
docker run --rm \
  -p 8080:8080 \
  -v ~/.ferret-scan:/home/ferret/.ferret-scan \
  ferret-scan --web --port 8080
```

## Pre-commit Integration

### Docker-based Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-docker
        name: Ferret Scan - Docker
        entry: docker run --rm -v $(pwd):/data ferret-scan:latest --pre-commit-mode
        language: system
        files: '\.(py|js|ts|go|java|json|yaml|yml)$'
        pass_filenames: true
        args: ["/data"]
```

### Finch-based Pre-commit Hook

For environments using Finch instead of Docker:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-finch
        name: Ferret Scan - Finch
        entry: finch run --rm -v $(pwd):/data ferret-scan:latest --pre-commit-mode
        language: system
        files: '\.(py|js|ts|go|java|json|yaml|yml)$'
        pass_filenames: true
        args: ["/data"]
```

### Advanced Docker Pre-commit Configuration

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-docker-advanced
        name: Ferret Scan - Docker Advanced
        entry: docker run --rm -v $(pwd):/data -v $(pwd)/ferret.yaml:/ferret.yaml ferret-scan:latest
        language: system
        files: '\.(py|js|ts|go|java|json|yaml|yml|env|conf)$'
        exclude: '^(test_|_test\.|docs/|examples/)'
        pass_filenames: true
        args: 
          - --pre-commit-mode
          - --config
          - /ferret.yaml
          - --confidence
          - high,medium
          - /data
```

## CI/CD Integration

### GitLab CI/CD

```yaml
# .gitlab-ci.yml
ferret-scan:
  stage: security
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - docker pull ferret-scan:latest
  script:
    - |
      docker run --rm -v $PWD:/data ferret-scan:latest \
        --file /data --recursive \
        --format gitlab-sast \
        --output /data/ferret-sast-report.json \
        --confidence high,medium \
        --no-color --quiet
  artifacts:
    reports:
      sast: ferret-sast-report.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  ferret-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Pull Ferret Scan image
        run: docker pull ferret-scan:latest
      
      - name: Run Ferret Scan
        run: |
          docker run --rm -v ${{ github.workspace }}:/data \
            ferret-scan:latest --file /data --recursive \
            --format json --output /data/results.json \
            --confidence high,medium --no-color --quiet
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: ferret-scan-results
          path: results.json
        if: always()
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Pull the latest image
                    sh 'docker pull ferret-scan:latest'
                    
                    // Run scan
                    sh '''
                        docker run --rm -v ${WORKSPACE}:/data \
                          ferret-scan:latest --file /data --recursive \
                          --format json --output /data/results.json \
                          --confidence high,medium --no-color --quiet
                    '''
                }
                
                // Archive results
                archiveArtifacts artifacts: 'results.json', fingerprint: true
                
                // Publish results (if Jenkins security plugin is available)
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'results.json',
                    reportName: 'Ferret Scan Report'
                ])
            }
        }
    }
    
    post {
        always {
            // Clean up
            sh 'docker system prune -f'
        }
    }
}
```

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
- main
- develop

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: Docker@2
  displayName: 'Pull Ferret Scan Image'
  inputs:
    command: 'pull'
    arguments: 'ferret-scan:latest'

- task: Docker@2
  displayName: 'Run Ferret Scan'
  inputs:
    command: 'run'
    arguments: >
      --rm -v $(Build.SourcesDirectory):/data 
      ferret-scan:latest --file /data --recursive 
      --format json --output /data/results.json 
      --confidence high,medium --no-color --quiet

- task: PublishBuildArtifacts@1
  displayName: 'Publish Scan Results'
  inputs:
    pathToPublish: 'results.json'
    artifactName: 'ferret-scan-results'
  condition: always()
```

### CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: docker:latest
    steps:
      - checkout
      - setup_remote_docker
      - run:
          name: Pull Ferret Scan
          command: docker pull ferret-scan:latest
      - run:
          name: Run Security Scan
          command: |
            docker run --rm -v $PWD:/data \
              ferret-scan:latest --file /data --recursive \
              --format json --output /data/results.json \
              --confidence high,medium --no-color --quiet
      - store_artifacts:
          path: results.json
          destination: ferret-scan-results

workflows:
  version: 2
  security:
    jobs:
      - security-scan
```

## Advanced Docker Usage

### Custom Configuration

```bash
# Mount custom configuration
docker run --rm \
  -v $(pwd):/data \
  -v $(pwd)/custom-ferret.yaml:/config/ferret.yaml \
  ferret-scan:latest \
  --config /config/ferret.yaml \
  --file /data --recursive
```

### Environment Variables

```bash
# Set environment variables for container behavior
docker run --rm \
  -v $(pwd):/data \
  -e FERRET_CONTAINER_MODE=true \
  -e FERRET_QUIET_MODE=true \
  ferret-scan:latest \
  --file /data --recursive
```

### Persistent Storage

```bash
# Create persistent volume for configuration and suppressions
docker volume create ferret-config

# Use persistent volume
docker run --rm \
  -v $(pwd):/data \
  -v ferret-config:/home/ferret/.ferret-scan \
  ferret-scan:latest \
  --file /data --recursive
```

### Multi-stage Scanning

```bash
# Stage 1: Quick scan for high confidence findings
docker run --rm -v $(pwd):/data ferret-scan:latest \
  --file /data --recursive --confidence high \
  --format json --output /data/high-confidence.json

# Stage 2: Comprehensive scan if no high confidence findings
if [ ! -s /data/high-confidence.json ] || [ "$(jq '.findings | length' /data/high-confidence.json)" -eq 0 ]; then
  docker run --rm -v $(pwd):/data ferret-scan:latest \
    --file /data --recursive --confidence high,medium,low \
    --format json --output /data/full-scan.json
fi
```

## Container Security Best Practices

### Running as Non-root

The Ferret Scan container runs as user `ferret` (UID 1000) by default:

```bash
# Verify non-root execution
docker run --rm ferret-scan:latest id
# Output: uid=1000(ferret) gid=1000(ferret) groups=1000(ferret)
```

### Read-only Root Filesystem

```bash
# Run with read-only root filesystem for enhanced security
docker run --rm --read-only \
  -v $(pwd):/data \
  -v /tmp \
  ferret-scan:latest \
  --file /data --recursive
```

### Resource Limits

```bash
# Set memory and CPU limits
docker run --rm \
  --memory=512m \
  --cpus=1.0 \
  -v $(pwd):/data \
  ferret-scan:latest \
  --file /data --recursive
```

### Network Isolation

```bash
# Run without network access (for offline scanning)
docker run --rm --network none \
  -v $(pwd):/data \
  ferret-scan:latest \
  --file /data --recursive
```

## Troubleshooting

### Common Issues

**1. Permission Denied Errors**
```bash
# Ensure proper volume mounting permissions
docker run --rm -v $(pwd):/data:ro ferret-scan:latest --file /data --recursive
```

**2. Container Not Found**
```bash
# Build the image locally if not available in registry
docker build -t ferret-scan .
```

**3. Volume Mount Issues**
```bash
# Use absolute paths for volume mounts
docker run --rm -v "$(pwd)":/data ferret-scan:latest --file /data --recursive
```

**4. Performance Issues**
```bash
# Increase memory limit for large repositories
docker run --rm --memory=1g -v $(pwd):/data ferret-scan:latest --file /data --recursive
```

### Debug Mode

```bash
# Run with debug output
docker run --rm -v $(pwd):/data ferret-scan:latest \
  --file /data --recursive --debug --verbose
```

### Container Inspection

```bash
# Inspect the container
docker run --rm -it ferret-scan:latest /bin/sh

# Check container size
docker images ferret-scan:latest

# View container layers
docker history ferret-scan:latest
```

## Integration with Container Orchestration

### Kubernetes Job

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: ferret-scan-job
spec:
  template:
    spec:
      containers:
      - name: ferret-scan
        image: ferret-scan:latest
        args: ["--file", "/data", "--recursive", "--format", "json", "--output", "/results/scan.json"]
        volumeMounts:
        - name: source-code
          mountPath: /data
          readOnly: true
        - name: results
          mountPath: /results
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
      volumes:
      - name: source-code
        configMap:
          name: source-code-config
      - name: results
        emptyDir: {}
      restartPolicy: Never
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  ferret-scan:
    image: ferret-scan:latest
    volumes:
      - ./:/data:ro
      - ./results:/results
    command: >
      --file /data --recursive 
      --format json --output /results/scan.json 
      --confidence high,medium
    mem_limit: 512m
    cpus: 1.0
    read_only: true
    tmpfs:
      - /tmp
    user: "1000:1000"
```

## Performance Optimization

### Container Caching

```bash
# Use multi-stage builds for better caching
# (Already implemented in the Dockerfile)

# Pre-pull images in CI/CD
docker pull ferret-scan:latest
```

### Parallel Scanning

```bash
# Split large repositories for parallel processing
docker run --rm -v $(pwd)/src:/data ferret-scan:latest --file /data --recursive &
docker run --rm -v $(pwd)/tests:/data ferret-scan:latest --file /data --recursive &
wait
```

### Resource Optimization

```bash
# Optimize for memory-constrained environments
docker run --rm \
  --memory=256m \
  --oom-kill-disable=false \
  -v $(pwd):/data \
  ferret-scan:latest \
  --file /data --recursive --confidence high
```

This Docker integration provides a robust, secure, and performant way to use Ferret Scan in containerized environments, making it easy to integrate into any CI/CD pipeline or development workflow.