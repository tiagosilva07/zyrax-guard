# Using Zyrax Guard with AI coding agents

AI agents sometimes hallucinate package names. Attackers pre-register those names as
malware. Guard breaks that attack chain by checking every package before the agent ever
runs an install.

Register `zyrax-guard mcp` as an MCP server in your agent of choice and it gains a
`check_package` tool (and `scan_agents`) it can call before suggesting an install.

## Claude Code CLI

Register Guard as a persistent MCP tool so Claude checks packages automatically:

```bash
claude mcp add zyrax-guard -- zyrax-guard mcp
```

That's it. Claude Code now has a `check_package` tool it calls before suggesting
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

Restart Cursor. The agent now has access to `check_package` before installing anything.

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
