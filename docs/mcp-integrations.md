# Using Zyrax Guard with AI coding agents

Register `zyrax-guard mcp` as an MCP server and your agent gains two tools:

- **`scan_agents`** — audit the agent config files in a repo (`CLAUDE.md`, `.mcp.json`,
  settings, skills) for prompt injection, malicious MCP servers, credential-exfil, and
  risky permissions *before the agent acts on them*.
- **`check_package`** — vet a package before install (AI agents hallucinate package
  names; attackers pre-register them as malware — Guard breaks that chain).

## Claude Code CLI

Register Guard as a persistent MCP tool so Claude checks packages automatically:

```bash
claude mcp add zyrax-guard -- zyrax-guard mcp
```

That's it. Claude Code now has `check_package` and `scan_agents` tools it calls before suggesting
`npm install` / `pip install` / `cargo add`. Guard's `check_package` tool accepts a
`deep` boolean to enable the deep install-script check:

```
check_package(name="some-pkg", ecosystem="npm", deep=true)
```

You can also add a rule to your `CLAUDE.md`:

```markdown
## Dependency policy
Before installing any package, use the zyrax-guard MCP tool to check it.
Never install a BLOCK result. Treat WARN as a prompt to confirm with the user.
```

## Cursor

Add to `.cursor/mcp.json` in your project root (or the global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "zyrax-guard": {
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  }
}
```

Restart Cursor. The agent now has access to `check_package` and `scan_agents`.

## Windsurf

Add to `.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "zyrax-guard": {
      "command": "zyrax-guard",
      "args": ["mcp"],
      "description": "Check npm/PyPI/crates packages for malware and typosquats before installing"
    }
  }
}
```

## VS Code (GitHub Copilot / Copilot Chat)

Add to your VS Code `settings.json`:

```json
{
  "github.copilot.chat.mcp.servers": {
    "zyrax-guard": {
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  }
}
```

Or add to `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "zyrax-guard": {
      "type": "stdio",
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  }
}
```

## Continue.dev

Add to `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "zyrax-guard",
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  ]
}
```

## How the MCP tool works

Once registered, the agent has access to `scan_agents`:

```json
{
  "name": "scan_agents",
  "arguments": { "dir": "." }
}
```

Once registered, the agent has access to `check_package`:

```json
{
  "name": "check_package",
  "arguments": {
    "name": "lodahs",
    "ecosystem": "npm",
    "deep": false
  }
}
```

Returns:

```json
{
  "verdict": "BLOCK",
  "reasons": ["MAL-2025-25502: Malicious code in lodahs (npm)"],
  "didYouMean": "lodash"
}
```

A `BLOCK` is a normal result (not an MCP error) — the agent should stop and tell the user
rather than proceeding with the install.

Guard also exposes a `scan_agents` tool over MCP — see
[Auditing AI agent configs](../README.md#auditing-ai-agent-configs-scan-agents).
