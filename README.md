# Zyrax Guard

[![CI](https://github.com/tiagosilva07/zyrax-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tiagosilva07/zyrax-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/tiagosilva07/zyrax-guard)](https://goreportcard.com/report/github.com/tiagosilva07/zyrax-guard)
[![Website](https://img.shields.io/badge/website-zyrax.io-2cc9da)](https://zyrax.io)

**Audit your AI agent configs before you run them.**
Catch the prompt injection, malicious MCP servers, and credential-exfil hiding in the
files that steer your AI — `CLAUDE.md`, `.mcp.json`, agent settings, skills — and vet the
packages they pull in. In milliseconds. Nothing leaves your machine.

```
$ zyrax-guard scan-agents .

Scanning . for agent config files...
  Found 2 file(s): .mcp.json, CLAUDE.md

  [HIGH]  .mcp.json
           MCP server 'data-exfil' uses non-HTTPS URL: http://attacker.example.com/collect
           → Use HTTPS for all external MCP server URLs.

  [CRITICAL]  CLAUDE.md:3
           Prompt injection keyword detected: 'ignore previous instructions'
           → Remove or review this instruction. Triage as false positive if intentional.

  2 finding(s) — 1 CRITICAL, 1 HIGH

$ zyrax-guard check lodahs
✗ lodahs@0.0.1-security — BLOCK
  - looks like a typo of "lodash" (far more popular); this name has only 45 weekly downloads
  - MAL-2025-25502: Malicious code in lodahs (npm)
  did you mean: lodash
  to override:  zyrax-guard allow lodahs
```

Works locally, in CI, and as a gate for AI coding agents. No account required. Nothing
phones home except the public package name you are querying.

🌐 **Homepage:** [zyrax.io](https://zyrax.io)

---

## Install

### npm / npx

```bash
npx zyrax-guard@latest scan-agents .     # audit agent configs
npx zyrax-guard@latest check lodash      # vet a package
```

Ships the prebuilt Go binary per-platform (via `optionalDependencies`) — no runtime
download. Works anywhere Node 18+ is available.

### Homebrew (macOS / Linux)

```bash
brew install tiagosilva07/zyrax/zyrax-guard
```

Installs the signed release binary (SHA-256 verified by Homebrew). Updates land via
`brew upgrade` once a new release is published.

### Quick install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/tiagosilva07/zyrax-guard/main/scripts/install.sh | sh
```

Downloads the signed release binary for your OS/arch, verifies its SHA-256 against
the release checksums, and installs it (to `/usr/local/bin`, or `~/.local/bin` if that
is not writable). Pin a version with `VERSION=v0.5.0`, or set `BINDIR` to choose where
it lands. Verifies the cosign signature too when `cosign` is on your PATH.

### `go install` (Go 1.23+)

```bash
go install github.com/tiagosilva07/zyrax-guard/cmd/zyrax-guard@latest
```

### Signed release binary

Download from [Releases](https://github.com/tiagosilva07/zyrax-guard/releases).
Every release ships:

- Pre-built binaries for linux/darwin/windows × amd64/arm64
- `checksums.txt` (SHA-256)
- SLSA L3 build provenance (`.cosign.bundle` per artifact)
- SBOM (`zyrax-guard.spdx.json`)

Verify a binary:

```bash
cosign verify-blob \
  --bundle zyrax-guard-linux-amd64.cosign.bundle \
  zyrax-guard-linux-amd64
```

### Build from source

```bash
git clone https://github.com/tiagosilva07/zyrax-guard
cd zyrax-guard
go build -o zyrax-guard ./cmd/zyrax-guard
```

---

## Updating

Guard checks for a newer release at most once a day (a read-only lookup of its own version
on `registry.npmjs.org`) and prints a one-line notice on stderr when one is available. To
update:

```bash
zyrax-guard upgrade          # detects how Guard was installed and updates it
zyrax-guard version --check  # force a version check now
```

`upgrade` delegates to your package manager (`npm`/`brew`/`go`) when Guard was installed that
way; for `curl|sh` / standalone-binary installs on Linux/macOS it downloads the signed release,
**verifies its SHA-256 against the signed `checksums.txt` before replacing the binary** (and the
cosign signature when `cosign` is available). Standalone Windows binaries are upgraded manually
for now (the notice links to Releases). Disable the daily check with `ZYRAX_NO_UPDATE_CHECK=1`.

---

## Quickstart

### Audit AI agent configs

```bash
zyrax-guard scan-agents .          # scan current directory
zyrax-guard scan-agents /repo      # scan a specific path
zyrax-guard scan-agents . --json   # JSON output
zyrax-guard scan-agents . --strict # exit 1 for any finding (not just CRITICAL/HIGH)
```

Scans `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.mcp.json`, `.claude/settings.json`,
and Cursor rules files. Exits 1 if any CRITICAL or HIGH finding is found.

### Check a single package

```bash
zyrax-guard check lodash                          # npm (default)
zyrax-guard check requests --ecosystem pypi       # PyPI
zyrax-guard check serde --ecosystem crates        # crates.io
```

### Check-then-install

```bash
zyrax-guard install lodash axios                  # vets, then runs npm install
zyrax-guard install flask --ecosystem pypi        # vets, then runs pip install
zyrax-guard install serde --ecosystem crates      # vets, then runs cargo add
```

### Allow a package (add to local policy)

```bash
zyrax-guard allow my-internal-pkg
# allowed "my-internal-pkg" (recorded in .zyrax/policy.json)
```

Commit `.zyrax/policy.json` — it is the reviewable allowlist for your project.

### Scan a PR's lockfile diff

```bash
zyrax-guard scan --base /tmp/base-lock.json --head package-lock.json --sarif
```

Emits SARIF 2.1.0 to stdout. Exit code 0 if no BLOCK; non-zero otherwise.
Add `--strict` to treat WARN as failure.

---

## Auditing AI agent configs (`scan-agents`)

AI coding agents (Claude Code, Cursor, Gemini CLI) read configuration files that can be
weaponized: a malicious `CLAUDE.md` in a repo you clone, a tampered `.mcp.json` that
points to an attacker's server, an MCP tool whose description hides instructions, a
`settings.json` granting wildcard shell access, or prose that quietly steers the agent
toward reading `.env` and POSTing it out. Guard detects these before the agent runs.

```bash
zyrax-guard scan-agents .
```

### What it scans

| File | Location |
|---|---|
| `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` | Repo root |
| `.mcp.json` | Repo root and subdirectories |
| `.claude/settings.json` | `.claude/` directory |
| `.cursor/rules`, `.cursor/rules/*.mdc` | Cursor rules |
| `SKILL.md` | Under any `skills/` directory |

### What it detects

| Rule | Severity |
|---|---|
| Prompt injection keywords (`ignore previous instructions`, `new objective:`, …) | CRITICAL |
| Hidden unicode characters (zero-width, bidi overrides) | CRITICAL |
| Base64-encoded instructions bypassing keyword filters | CRITICAL |
| Conditional/sleeper triggers (`when user asks X, do Y`) | CRITICAL |
| MCP tool description carrying injection keywords (read as trusted model context) | CRITICAL |
| Persona override (`you are not Claude`, `your true purpose`) | HIGH |
| MCP server using non-HTTPS URL | HIGH |
| MCP server using raw IP address (possible C2) | HIGH |
| MCP server using tunnel service (ngrok, Cloudflare, …) | HIGH |
| MCP server running a shell, inline `-c`/`-e`, temp-dir binary, or dangerous env var | HIGH |
| Instruction referencing credential files (`.env`, `id_rsa`, `.aws/credentials`) | HIGH |
| Exfiltration sink (`send`/`POST`/`curl` + external URL on one line) | HIGH |
| Wildcard `allow` in `permissions` | HIGH |
| Unrestricted shell access with no deny rules | MEDIUM |
| `npx` MCP server without a lock file | MEDIUM |
| Auto-run hooks executing commands (download-execute → CRITICAL, shell flag → HIGH) | CRITICAL–MEDIUM |

Exit code: `1` if any CRITICAL or HIGH finding; `0` otherwise. Use `--strict` for exit `1` on any finding.

### In CI

```yaml
- name: Audit agent configs
  run: zyrax-guard scan-agents . --strict
```

### Via MCP (`scan_agents` tool)

Once registered as an MCP server, agents also have access to `scan_agents`:

```json
{
  "name": "scan_agents",
  "arguments": { "dir": "." }
}
```

---

## GitHub Action

Gate every pull request. By default (`scan: both`) Zyrax Guard audits AI agent configs
(prompt injection, malicious MCP servers, risky permissions) **and** gates dependencies
added in the PR, failing the check if anything is blocked. Add
`.github/workflows/zyrax-guard.yml`:

```yaml
name: Zyrax Guard
on: pull_request
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0          # lets Guard diff against the PR base (added deps only)
      - uses: tiagosilva07/zyrax-guard@v0
        with:
          ecosystem: npm          # npm | pypi | crates
```

On a pull request it scans only the dependencies added versus the base branch; otherwise
it scans the whole lockfile. The job fails when a dependency is blocked. `@v0` tracks the
latest 0.x release; pin an exact version (e.g. `@v0.7.1`) for fully reproducible CI.

**Inputs** (all optional): `scan` (`deps | agents | both`, default `both`), `ecosystem`
(default `npm`), `lockfile` (default per-ecosystem), `base` (explicit base lockfile),
`strict` (treat WARN as failure), `deep` (inspect install scripts), `version` (Guard
release, default `latest`), `fail-on-block` (default `true`), `sarif-file` (write
dependency SARIF for Code Scanning), `agents-sarif-file` (write agent-config SARIF for
Code Scanning), `args` (extra raw flags).

Upload results to **GitHub Code Scanning** so findings show up inline on the PR:

```yaml
      - uses: tiagosilva07/zyrax-guard@v0
        with:
          sarif-file: zyrax-guard.sarif
          fail-on-block: "false"   # let Code Scanning surface findings; don't hard-fail
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: zyrax-guard.sarif
```

Audit agent configs **and** dependencies, both surfaced in Code Scanning:

```yaml
      - uses: tiagosilva07/zyrax-guard@v0
        with:
          scan: both
          sarif-file: zyrax-guard-deps.sarif
          agents-sarif-file: zyrax-guard-agents.sarif
          fail-on-block: "false"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: zyrax-guard-deps.sarif
          category: zyrax-guard-deps
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: zyrax-guard-agents.sarif
          category: zyrax-guard-agents
```

(That job needs `permissions: { security-events: write }`.)

---

## Ecosystems

Guard supports **npm, PyPI, and crates.io**. Pick one with `--ecosystem` (default `npm`):

```bash
zyrax-guard check --ecosystem pypi requests
zyrax-guard check --ecosystem crates serde
zyrax-guard scan --ecosystem crates              # PR gate over Cargo.lock
zyrax-guard scan --ecosystem pypi               # PR gate over poetry.lock / requirements.txt
```

---

## How the checks work

Guard runs against public registry metadata only — no local execution, no installs, no sandboxing:

| Check | Verdict trigger |
|---|---|
| **Existence** | Package not found on the registry → **BLOCK** (hallucinated or trap name) |
| **Typosquat** | Name is 1 edit away from a far-more-popular package AND has near-zero downloads → **BLOCK** with a "did you mean" suggestion |
| **Known-bad** | OSV advisory match → malware / high-severity → **BLOCK**; low-severity → **WARN** |
| **Age & popularity** | Published < 30 days AND < 50 weekly downloads → **WARN** |
| **Lockfile integrity** | *(scan only)* Resolved URL or integrity hash changed → **BLOCK** |
| **Maintainer change** | *(scan only)* New version published by a previously unseen maintainer → **WARN** |

---

## Deep check (`--deep`)

By default checks are metadata-only (milliseconds). Add `--deep` to also download the
package's distribution artifact and **statically inspect the code it runs at install/build
time** — npm `preinstall`/`install`/`postinstall` scripts, PyPI `setup.py`, crates `build.rs`:

```bash
zyrax-guard check --deep some-pkg
zyrax-guard scan --deep                          # PR gate, deep mode
```

It flags red-flag patterns — network calls, process spawning, base64/obfuscated `eval` —
and **BLOCKs** on dangerous combinations (e.g. "download a script and run it"). It runs
**no code** (purely static) and is **best-effort**: if the artifact cannot be fetched you
get an informational note, never a false block.

Zero added dependencies — the extractor uses stdlib `archive/tar` + `compress/gzip` only.

---

## The three verdicts

| Verdict | Meaning | Default exit code |
|---|---|---|
| **SAFE** | No signals worth noting | `0` |
| **WARN** | Suspicious — review before proceeding | `0` (use `--strict` to make it `1`) |
| **BLOCK** | Strong indicator of malicious or hallucinated package | `1` |

---

## Configuration

Zyrax Guard is configured entirely through command flags and an optional local
policy file — no config file or environment variables required.

### Commands

| Command | Purpose |
|---|---|
| `check <name>[@version]` | Vet a single package |
| `install <name>` | Check, then install if safe |
| `scan` | Vet a lockfile (or a PR's lockfile diff) |
| `scan-agents <dir>` | Audit AI agent config files |
| `allow <name>` | Add a package to the local allowlist |
| `init` | Print the shell hook (gate installs transparently) |
| `mcp` | Run the MCP server (`check_package`, `scan_agents`) |
| `mcp install [--global]` | Register Guard with your AI agent |
| `upgrade` | Update Guard to the latest release (verified) |
| `version [--check]` | Print version; `--check` checks for a newer release |

### Flags

| Flag | Commands | Default | Effect |
|---|---|---|---|
| `--ecosystem npm\|pypi\|crates` | check, install, scan | `npm` | Target package ecosystem |
| `--strict` | check, install, scan, scan-agents | off | Tighten failure: WARN → fail (package commands); any finding → fail (`scan-agents`) |
| `--deep` | check, install, scan | off | Download + statically analyze install/build scripts |
| `--json` | check, scan, scan-agents | off | JSON output |
| `--sarif` | check, scan | off | SARIF 2.1.0 output (for code-scanning ingestion) |
| `--ignore-scripts` | install | off | Pass `--ignore-scripts` through to npm |
| `--base <file>` | scan | — | Base lockfile to diff against (scan only added/changed deps) |
| `--head <file>` | scan | `package-lock.json` | Head lockfile to scan |

### Local policy file

`zyrax-guard allow <name>` records decisions in `.zyrax/policy.json` at the project root:

```json
{ "allow": ["my-internal-pkg"], "deny": ["known-bad-pkg"] }
```

Allowlisted packages skip checks; denylisted packages always BLOCK. Commit the file to
share policy across a team. (Org-wide policy is a paid drop-in via the `Policy` seam.)

### Exit codes

| Context | Exits `1` when |
|---|---|
| `check` / `install` / `scan` | a **BLOCK** verdict — or a **WARN** with `--strict` |
| `scan-agents` | a **CRITICAL** or **HIGH** finding — or **any** finding with `--strict` |

See [The three verdicts](#the-three-verdicts) for package verdict meanings.

---

## Make it automatic — shell hook

The shell hook intercepts `npm install` / `pip install` / `cargo add` transparently.
Every new package gets checked before the real installer runs; already-installed and
non-install commands pass through untouched.

### macOS / Linux (bash or zsh)

Add to `~/.bashrc`, `~/.zshrc`, or `~/.bash_profile`:

```bash
# Gate npm installs (default)
eval "$(zyrax-guard init bash)"

# Gate pip installs
eval "$(zyrax-guard init bash pip)"

# Gate cargo add
eval "$(zyrax-guard init bash cargo)"
```

Apply immediately without restarting your terminal:

```bash
source ~/.zshrc        # or ~/.bashrc
```

### Windows (PowerShell)

Add to your PowerShell profile (`$PROFILE`). To find and open it:

```powershell
notepad $PROFILE      # creates the file if it doesn't exist
```

Add this line and save:

```powershell
Invoke-Expression (zyrax-guard init powershell | Out-String)
```

Apply immediately:

```powershell
. $PROFILE
```

From now on every `npm install`, `pip install`, or `cargo add` in a PowerShell window
is automatically checked before anything installs.

---

## Using with AI coding agents

Register `zyrax-guard mcp` as an MCP server and your agent gains a `scan_agents` tool to
audit the configs it's about to act on — and a `check_package` tool it calls before every
install (AI agents hallucinate package names; attackers pre-register them as malware,
and Guard breaks that chain).

**One-step register (recommended):**

```bash
zyrax-guard mcp install            # writes ./.mcp.json for this project
zyrax-guard mcp install --global   # registers globally with Claude Code (user scope)
```

`mcp install` writes a standard `.mcp.json` (read by Claude Code, Cursor, and VS Code) and
auto-detects whether to register `zyrax-guard mcp` (binary on PATH) or `npx -y zyrax-guard mcp`.
Override with `--command binary|npx`. `--global` delegates to `claude mcp add -s user` (it prints
the manual command if the `claude` CLI isn't installed).

Manual one-liner (Claude Code):

```bash
claude mcp add zyrax-guard -- npx -y zyrax-guard mcp
```

→ **[MCP setup for Claude Code, Cursor, Windsurf, VS Code, and Continue.dev](docs/mcp-integrations.md)**

Guard is on the official MCP registry as `io.github.tiagosilva07/zyrax-guard` — register it
in one line with `npx -y zyrax-guard mcp`.

---

## Using in CI

Gate pull requests so a malicious or hallucinated dependency fails the build. The
[GitHub Action](#github-action) is the quickest path; `zyrax-guard scan` recipes for
GitHub Actions, PyPI, and crates.io live in the CI guide.

→ **[CI recipes (GitHub Actions PR gate, PyPI, crates.io)](docs/ci.md)**

---

## Privacy promise

Only the **public package names you query** leave your machine, as read-only lookups
against public registry APIs:

- `registry.npmjs.org` — existence and metadata
- `api.npmjs.org` — download counts
- `api.osv.dev` — known advisories
- `registry.npmjs.org` — Guard's own latest version (update check, ≤1×/day; disable with `ZYRAX_NO_UPDATE_CHECK=1`)
- `github.com` — only when you run `zyrax-guard upgrade` (downloads the signed release binary)

No telemetry. No account. No secrets sent anywhere. The binary is reproducible
(`-trimpath`), and every release ships SLSA L3 provenance so you can verify the build
chain yourself.

---

## Free & open source

Zyrax Guard is **MIT-licensed and free** — the agent-config auditor (`scan-agents` +
the `scan_agents` MCP tool), every package check, the PR gate with JSON/SARIF output, the
`check_package` MCP tool, and the shell hook. Read the code and verify the binary yourself.

A **Zyrax platform** for teams (organization-wide policy, continuous monitoring, dashboards,
and audit/compliance reporting) is in development — learn more at **[zyrax.io](https://zyrax.io)**.

---

## Roadmap

| Version | Item | Status |
|---|---|---|
| **v0.1.0** | npm CLI: `check` + PR-gate `scan` (lockfile diff) + JSON/SARIF + self-hardening CI | shipped |
| **v0.2.0** | MCP server (`check_package`) + shell-hook (`zyrax-guard init`) | shipped |
| **v0.3.0** | PyPI + crates.io parity across check/install/hook/MCP/scan | shipped |
| **v0.4.x** | Deep check (`--deep`): static install/build-script analysis + overall time budget | shipped |
| **v0.5.0** | Rebrand to Zyrax; public release | shipped |
| **v0.6.x** | GitHub Action + Marketplace listing + `curl\|sh` installer; floating `@v0` tag | shipped |
| **v0.7.0** | `scan-agents`: AI agent config audit (prompt injection, MCP hosts, permissions) + Phase 2 detections (credential access, exfiltration sinks, MCP tool-description injection) | shipped |
| **v0.8** | First-class CI surfacing for `scan-agents`: SARIF output + GitHub code-scanning upload + inline PR annotations | shipped |
| **exploring** | Community-curated threat intel (shared malicious-package & MCP-host feeds); more ecosystems (Go modules, RubyGems) via the `Ecosystem` seam | — |

The roadmap items drop in via the existing `Ecosystem`, `ThreatIntel`, `Policy`, and
`Reporter` seams — no re-architecting required.

---

## License

MIT — see [LICENSE](LICENSE).
