# Docker Hub MCP Server - Docker Build Documentation

This document describes the Docker image build and deployment process for the Docker Hub MCP Server.

## Container Registry

Docker images are published to GitHub Container Registry (GHCR):

**Repository**: `ghcr.io/transform-ia/dockerhub-mcp`

## Image Tags

Images are tagged based on the git branch or tag:

- **Latest**: `ghcr.io/transform-ia/dockerhub-mcp:latest` (built from main branch)
- **Version tags**: `ghcr.io/transform-ia/dockerhub-mcp:v1.0.0` (built from git tags like `v1.0.0`)
- **Semantic versions**:
  - `ghcr.io/transform-ia/dockerhub-mcp:1.0.0` (full version)
  - `ghcr.io/transform-ia/dockerhub-mcp:1.0` (major.minor)
  - `ghcr.io/transform-ia/dockerhub-mcp:1` (major only)
- **Branch tags**: `ghcr.io/transform-ia/dockerhub-mcp:feature-branch` (for non-main branches)
- **PR tags**: `ghcr.io/transform-ia/dockerhub-mcp:pr-123` (for pull requests)

## Supported Architectures

Images are built for multiple architectures:

- **linux/amd64** (Intel/AMD 64-bit)
- **linux/arm64** (ARM 64-bit, including Apple Silicon, AWS Graviton)

Docker will automatically pull the correct image for your platform.

## CI/CD Pipeline

### Automated Builds

GitHub Actions automatically builds and pushes images on:

1. **Push to main branch** - Updates the `latest` tag
2. **Git tags** (e.g., `v1.0.0`) - Creates versioned image tags
3. **Pull requests** - Builds images but does not push to registry (test only)

### Build Workflow

The build workflow (`.github/workflows/docker-build.yml`) performs:

1. **Multi-architecture build** using Docker Buildx
2. **Layer caching** via GitHub Actions cache for faster builds
3. **SBOM generation** (Software Bill of Materials)
4. **Provenance attestation** for supply chain security
5. **Automatic tagging** based on git refs

### Dockerfile Linting

The linting workflow (`.github/workflows/lint-dockerfile.yml`) runs hadolint on every Dockerfile change to ensure best practices.

## Using the Docker Image

### Pull the Image

```bash
# Pull latest version
docker pull ghcr.io/transform-ia/dockerhub-mcp:latest

# Pull specific version
docker pull ghcr.io/transform-ia/dockerhub-mcp:1.0.0
```

### Run the Container

#### Public Docker Hub Access (No Authentication)

```bash
docker run -it --rm \
  ghcr.io/transform-ia/dockerhub-mcp:latest
```

#### Authenticated Access (Recommended)

```bash
docker run -it --rm \
  -e HUB_PAT_TOKEN=your_docker_hub_pat_token \
  ghcr.io/transform-ia/dockerhub-mcp:latest \
  --username=your_docker_hub_username
```

#### HTTP Transport Mode

```bash
docker run -it --rm \
  -p 3000:3000 \
  -e HUB_PAT_TOKEN=your_docker_hub_pat_token \
  ghcr.io/transform-ia/dockerhub-mcp:latest \
  --transport=http --port=3000 --username=your_docker_hub_username
```

### Docker Compose Example

```yaml
services:
  dockerhub-mcp:
    image: ghcr.io/transform-ia/dockerhub-mcp:latest
    environment:
      - HUB_PAT_TOKEN=${HUB_PAT_TOKEN}
    command:
      - --transport=http
      - --port=3000
      - --username=${DOCKER_HUB_USERNAME}
    ports:
      - "3000:3000"
    restart: unless-stopped
```

## Building Locally

### Prerequisites

- Docker Engine 20.10+ or Docker Desktop
- Docker Buildx plugin

### Build for Current Platform

```bash
docker build -t dockerhub-mcp:local .
```

### Build Multi-Architecture Image

```bash
# Create a new builder instance
docker buildx create --name multiarch-builder --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t dockerhub-mcp:local \
  --load \
  .
```

**Note**: `--load` only works for single platform builds. For multi-platform, use `--push` to push directly to a registry.

## Release Process

### Creating a New Release

1. **Update version** in `package.json` (if needed)
2. **Commit changes**:
   ```bash
   git add package.json
   git commit -m "Bump version to 1.0.0"
   ```

3. **Create and push git tag**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

4. **GitHub Actions automatically**:
   - Builds multi-arch image
   - Tags as `v1.0.0`, `1.0.0`, `1.0`, `1`, and `latest`
   - Pushes to GitHub Container Registry

### Verifying the Release

```bash
# Check the image exists
docker manifest inspect ghcr.io/transform-ia/dockerhub-mcp:1.0.0

# Verify multi-arch support
docker buildx imagetools inspect ghcr.io/transform-ia/dockerhub-mcp:1.0.0
```

## Security

### Image Security Features

- **Non-root user**: Container runs as `appuser` (UID/GID 1000)
- **Minimal base**: Alpine Linux for smaller attack surface
- **Production dependencies only**: Dev dependencies excluded
- **SBOM**: Software Bill of Materials included
- **Provenance**: Build provenance attestation

### Scanning for Vulnerabilities

```bash
# Using Docker Scout (if available)
docker scout cves ghcr.io/transform-ia/dockerhub-mcp:latest

# Using Trivy
trivy image ghcr.io/transform-ia/dockerhub-mcp:latest
```

## Troubleshooting

### Image Pull Issues

**Problem**: `Error response from daemon: unauthorized`

**Solution**: The package may be private. Authenticate with GitHub:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

### Architecture Mismatch

**Problem**: `exec format error` when running container

**Solution**: Ensure you're pulling the correct architecture:

```bash
docker pull --platform linux/amd64 ghcr.io/transform-ia/dockerhub-mcp:latest
```

### Build Failures in CI/CD

Check the GitHub Actions logs:

1. Go to repository → Actions tab
2. Click on failed workflow run
3. Expand failed step to see error details

Common issues:
- Dockerfile syntax errors (check hadolint workflow)
- Network issues during build
- GITHUB_TOKEN permissions (ensure `packages: write` is set)

## Further Reading

- [Docker Hub MCP Server README](README.md)
- [GitHub Container Registry Documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Docker Buildx Documentation](https://docs.docker.com/buildx/working-with-buildx/)
- [Dockerfile Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
