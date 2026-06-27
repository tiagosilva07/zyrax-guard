# Security Policy

## Supported versions

Only the latest release is actively maintained. Security fixes are not backported
to older releases.

| Version | Supported |
|---------|-----------|
| Latest  | ✅ |
| Older   | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing **privacy@zyrax.io**. Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept.
- Any suggested fix if you have one.

We will acknowledge your report within **48 hours** and aim to release a fix
within **14 days** for critical issues. We will credit you in the release notes
unless you prefer to remain anonymous.

## Security design

Zyrax Guard is itself a security tool. These invariants must never regress:

- **No arbitrary code execution.** The tool reads registry metadata and
  (optionally) extracts distribution archives in memory. It never shells out to
  user-supplied input and never executes downloaded code.
- **Command injection safe.** All subprocess calls use argument arrays, never
  shell interpolation.
- **SSRF guard.** The httpx client enforces an explicit allowlist of registry
  hosts. No user-supplied URL is fetched without going through that allowlist.
- **Hardened archive extraction.** Untrusted tarballs (for `--deep`) are
  extracted with path-traversal, symlink, and decompression-bomb defenses.
- **Zero telemetry.** Only the public package name you query leaves your machine,
  as a read-only lookup against public registry APIs.
- **Reproducible builds.** Releases are built with `-trimpath` and ship SLSA L3
  provenance and a cosign bundle so you can verify the build chain independently.

## Operational controls

Controls that are actively enforced in this repository:

- **Branch protection.** Direct pushes to `main` and `develop` are blocked; all changes arrive via pull request.
- **SHA-pinned GitHub Actions.** Every third-party action in `.github/workflows/` is pinned to a full commit SHA (not a mutable tag) to prevent tag-hijacking supply-chain attacks.
- **CI gates on every PR.** The `ci.yml` workflow must pass before a PR can merge; it enforces:
  - `gofmt` formatting (unformatted files fail the build)
  - `go vet ./...`
  - `go build ./...`
  - `go test -race -count=1 ./...`
  - `govulncheck ./...` (known Go vulnerability database)
  - `staticcheck ./...`
  - 20-second fuzz run (`FuzzDamerau`)
  - gitleaks secret scan (full git history)
  - dependency-review (PR events only — blocks high+ severity CVEs and GPL/AGPL/LGPL licenses)
- **Signed releases with provenance.** Every release binary is cosign-signed (keyless, SLSA L3), ships an SBOM (`zyrax-guard.spdx.json` in SPDX format), and a `checksums.txt` (SHA-256).
- **Verified self-upgrade.** `zyrax-guard upgrade` verifies the SHA-256 checksum against the signed `checksums.txt` and (when `cosign` is available) verifies the keyless cosign signature before replacing the binary. A signature mismatch aborts the upgrade.
- **Least-privilege workflow permissions.** The top-level `permissions: {}` in `ci.yml` denies all permissions by default; individual jobs grant only what they need (e.g. `contents: read`).

## Scope

In scope:

- The `zyrax-guard` binary and all packages under `internal/`
- The CI release pipeline (`.github/workflows/`)
- Supply-chain risks in the project's own dependencies

Out of scope:

- Vulnerabilities in packages that Zyrax Guard **reports on** (report those to
  the affected package maintainer or to OSV at https://osv.dev)
- Social engineering or phishing attacks
