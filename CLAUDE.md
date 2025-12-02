# Claude Code Working Notes

## Repository Purpose

MCP (Model Context Protocol) server providing Docker Hub integration. Built with TypeScript/Node.js. Exposes Docker Hub operations for repositories, tags, and images.

## Plugin Usage

### When to use plugins

- `/docker:cmd-lint` - Lint Dockerfile (if building Docker image)
- `/mcp:cmd-test` - Test MCP server connectivity
- `/github:cmd-status` - Check GitHub workflow status
- `/orchestrator:detect` - Auto-detect appropriate plugin

### Available plugins

- docker, mcp, github, markdown, orchestrator

## Development Workflow

**Build Process:**

1. Modify TypeScript code in `src/`
2. Install dependencies: `npm install`
3. Build: `npm run build` (transpiles TypeScript to JavaScript)
4. Test: `npm test`
5. Lint: `npm run lint` (ESLint)
6. Build Docker image: `docker build -t hub-mcp:test .`
7. Test MCP server: `/mcp:cmd-test hub-mcp`
8. Commit changes

## MCP Server Capabilities

**Tools provided:**

- List Docker Hub repositories
- Query image tags
- Get image manifests and metadata
- Search Docker Hub
- Repository webhooks management

**Integration:**

- Connects to Docker Hub REST API
- Requires Docker Hub token via environment variable
- Supports both public and private repositories

## Project Structure

- `src/` - TypeScript source code
- `src/index.ts` - Entry point
- `src/mcp/` - MCP protocol implementation
- `src/dockerhub/` - Docker Hub API client
- `dist/` - Compiled JavaScript (gitignored)
- `package.json` - Node.js dependencies and scripts
- `tsconfig.json` - TypeScript configuration
- `Dockerfile` - Multi-stage build (Node.js → runtime)

## TypeScript Development

- Use strict mode TypeScript
- Follow ESLint configuration
- Write unit tests for MCP tools
- Document exported functions with JSDoc
- Use async/await for API calls

## Testing

- Unit tests: `npm test`
- Integration tests: Require Docker Hub credentials
- MCP connectivity: `/mcp:cmd-test hub-mcp`
- Docker build: `docker build .`

## Deployment

1. Build and push Docker image to registry
2. Update corresponding Helm chart with new image tag
3. Register in `.mcp.json`: `/mcp:cmd-add hub-mcp <url>`
4. Deploy via ArgoCD

## Configuration

Environment variables:

- `DOCKERHUB_TOKEN` - Docker Hub authentication token
- `DOCKERHUB_USERNAME` - Docker Hub username
- `MCP_SERVER_PORT` - MCP server listening port (default: 8080)
