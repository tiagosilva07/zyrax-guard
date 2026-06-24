# @tiagosilva07/zyrax-guard-darwin-arm64

Prebuilt `zyrax-guard` binary for **darwin-arm64**.

You don't install this directly — it's a platform-specific dependency of the
[`zyrax-guard`](https://www.npmjs.com/package/zyrax-guard) package, selected automatically
via `optionalDependencies`. Install the main package instead:

```bash
npx zyrax-guard scan-agents .   # audit AI agent configs before you run them
```

[Zyrax Guard](https://github.com/tiagosilva07/zyrax-guard) audits AI agent configs (prompt
injection, malicious MCP servers, credential-exfil) and vets packages. Local, zero-dependency. MIT.
