# zyrax-guard

Audit AI agent configs (prompt injection, malicious MCP servers) and vet packages. CLI + MCP server. Local, zero-dependency.

```bash
npx zyrax-guard scan-agents .
npx zyrax-guard check lodash
# MCP server (stdio):
npx -y zyrax-guard mcp
```

Prebuilt Go binary shipped per-platform via optionalDependencies — no runtime download.

<!-- mcp-name: io.github.tiagosilva07/zyrax-guard -->
