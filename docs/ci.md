# Using Zyrax Guard in CI

The fastest way to gate a repo is the [GitHub Action](../README.md#github-action). The
recipes below show the underlying `zyrax-guard scan` invocations for a PR gate across
ecosystems — useful for non-GitHub CI or custom pipelines.

> **Pin for production:** these examples pin third-party actions to commit SHAs — mutable tags are a supply-chain risk (the exact risk Guard exists to catch). Pin `zyrax-guard` to an exact version or commit SHA too for fully reproducible CI.

## GitHub Actions (PR gate)

```yaml
# .github/workflows/guard.yml
name: Dependency guard
on: [pull_request]
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd  # pin: actions/checkout@v5
        with: { fetch-depth: 0 }
      - uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c  # pin: actions/setup-go@v6
        with: { go-version: "1.26" }
      - run: go install github.com/tiagosilva07/zyrax-guard/cmd/zyrax-guard@latest
      - name: Guard new dependencies
        run: |
          git show "origin/${{ github.base_ref }}:package-lock.json" > /tmp/base-lock.json 2>/dev/null || echo '{"packages":{}}' > /tmp/base-lock.json
          zyrax-guard scan \
            --base /tmp/base-lock.json \
            --head package-lock.json \
            --strict \
            --sarif > guard.sarif
      - uses: github/codeql-action/upload-sarif@dd903d2e4f5405488e5ef1422510ee31c8b32357  # pin: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: guard.sarif }
```

It checks only **newly added or changed** dependencies (fast, no re-flagging the whole
tree), fails the PR on any BLOCK, and uploads results to GitHub Code Scanning.

## Audit agent configs

Audit the repo's AI agent configs (`CLAUDE.md`, `.mcp.json`, agent settings, skills) for
prompt injection, malicious MCP servers, and risky permissions:

```yaml
- name: Audit agent configs
  run: zyrax-guard scan-agents --strict .
```

Add `--sarif` to emit SARIF 2.1.0 and upload it via `github/codeql-action/upload-sarif@v3`
so findings surface inline on the PR. The [GitHub Action](../README.md#github-action)
(`scan: both` + `agents-sarif-file`) wires both the dependency and agent-config scans up
for you.

## PyPI in CI

```bash
git show "origin/$BASE_REF:poetry.lock" > /tmp/base-lock.txt 2>/dev/null || echo "" > /tmp/base-lock.txt
zyrax-guard scan --ecosystem pypi \
  --base /tmp/base-lock.txt \
  --head poetry.lock \
  --sarif --strict > guard.sarif
```

## crates.io in CI

```bash
git show "origin/$BASE_REF:Cargo.lock" > /tmp/base-lock.txt 2>/dev/null || echo "" > /tmp/base-lock.txt
zyrax-guard scan --ecosystem crates \
  --base /tmp/base-lock.txt \
  --head Cargo.lock \
  --sarif --strict > guard.sarif
```
