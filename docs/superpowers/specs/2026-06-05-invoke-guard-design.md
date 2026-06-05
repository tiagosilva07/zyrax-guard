# Invoke Guard (Design)

**Date:** 2026-06-05
**Status:** Design — awaiting review before implementation plan
**Repo:** new **public** repository `invoke-guard`, MIT. The free, open-source companion
to the Invoke supply-chain platform (separate codebase; related by product/brand, not by
shared code).

---

## 1. What it is

A **single-binary CLI that vets a dependency *before* it is installed** and decides whether
it is `SAFE`, `WARN`, or `BLOCK`. It protects human developers and AI coding agents (agents
run the same install commands and sometimes hallucinate package names attackers pre-register
with malware), and — via a PR-time gate — protects **multi-contributor projects** from
contributor-introduced supply-chain risk. Fully useful for a single developer with **no
account and no backend**; nothing phones home.

## 2. Goals & non-goals

**Goals (v1):**
- Vet npm dependencies pre-install with four instant checks + two multi-contributor checks.
- Work locally (individual) and in CI (PR gate over the lockfile diff).
- Be **multi-ecosystem by architecture** (npm implemented; PyPI/crates drop in later).
- Be **self-hardened** — it runs package managers, so it must be command-injection-safe.
- Emit **stable, versioned results** (`--json`, `--sarif`) that the Invoke platform ingests.
- Be **open-core**: free + complete for individual/single-repo; paid value behind clean seams.

**Non-goals (v1 — explicitly deferred, see §11 roadmap):** MCP server; shell-hook
auto-interception; PyPI/crates providers; deep/sandbox behavioral analysis; any paid
provider; first-party source-code scanning (that is the Invoke platform's SAST job — Guard
gates *dependencies*, not people or your own code).

## 3. Architecture — a verdict engine behind four seams

The core is an **ecosystem-agnostic verdict engine** consuming signals and emitting
`SAFE | WARN | BLOCK`. Everything ecosystem- or business-specific sits behind an interface,
so the engine never changes and the roadmap items are additive drop-ins.

```
        ┌──────────── Verdict Engine (pure, isolated, heavily unit-tested) ────────────┐
        │   signals → score → SAFE | WARN | BLOCK                                       │
        └──────▲──────────────▲───────────────▲────────────────────▲───────────────────┘
               │              │               │                     │
         Ecosystem        ThreatIntel       Policy               Reporter
         (npm v1;          (OSS: OSV +       (OSS: local          (OSS: text/json/sarif;
          PyPI/crates       registry;         .invoke/policy;      paid: push → Invoke
          later)            paid: curated     paid: org policy)    platform)
                            feed)
```

### Interfaces (the seams)
- **`Ecosystem`** — `Exists(name, version)`, `Metadata(name)` (publish age, weekly downloads,
  maintainers, repo URL), `Advisories(name, version)`, `PopularList()` (typosquat seed),
  `ValidateName(name)` (legal-grammar check), `Install(names, opts)` (arg-array exec).
  npm in v1.
- **`ThreatIntel`** — `Lookup(eco, name, version) []Advisory`. OSS providers: OSV.dev +
  a bundled denylist. The paid curated feed is a same-interface provider (seam only, not built).
- **`Policy`** — `Decision(pkg) (allow|deny|defer)` + `Allow(name)`. OSS: a committed
  `.invoke/policy.json` (approved set + rules + allowlist). Paid org-policy is a drop-in.
- **`Reporter`** — `Report(results)`. OSS: `text`, `json`, `sarif`. The **platform push** is a
  reporter (paid `--report invoke`), so free users self-integrate via `--sarif`.

Each is a Go interface in its own package; the verdict engine depends only on the interfaces.

## 4. The checks

Instant, no backend beyond read-only public lookups for the queried package.

1. **Existence** — `Ecosystem.Exists`. Not found → **BLOCK** (hallucinated/trap name).
2. **Typosquat** — Damerau-Levenshtein of the queried name vs `PopularList()`. Distance 1 to a
   much-more-popular package **and** the queried package itself has near-zero downloads →
   **BLOCK** (suggest the real one). Weaker similarity → **WARN** ("did you mean X?").
3. **Known-bad** — `ThreatIntel.Lookup` (OSV + bundled denylist) for the exact name+version.
   Malicious / high-severity advisory match → **BLOCK**; low-severity → **WARN**.
4. **Age & popularity** — from `Metadata`: published < 30 days **and** < 50 weekly downloads →
   risk signal → **WARN** (never blocks alone).

**Multi-contributor differentiators (also v1):**
5. **Lockfile integrity** — when scanning a PR diff: an existing dependency's resolved
   URL/integrity hash changed, or a lockfile entry has no manifest counterpart (lockfile-only
   injection / dependency confusion) → **WARN/BLOCK**.
6. **Maintainer change** — a dependency's new version was published by a different maintainer
   account, or the package's repo URL changed (account-takeover signal) → **WARN**.

## 5. Verdict logic

The engine combines signals into one verdict:
- **BLOCK** if: does not exist; OR known-malicious / high-severity advisory; OR strong
  typosquat (distance 1 to a top-popular package while itself near-zero downloads); OR a
  hard lockfile-integrity violation.
- **WARN** if: weaker typosquat similarity; OR brand-new + very low downloads; OR low-severity
  advisory; OR maintainer/owner change; OR soft lockfile anomaly.
- **SAFE** otherwise.

Policy overlays the verdict: an explicit local allow → forced SAFE (with a note); a policy
deny → forced BLOCK. Typosquat thresholds (the false-positive risk) are **configurable
constants** with conservative defaults, tuned against a real popular-package corpus in tests.

## 6. Surfaces (v1)

- `invoke-guard check <name>[@version]` — vet one package; print verdict + reasons; exit code.
- `invoke-guard install <names…>` — check all; only if all pass, run the **real** installer via
  **argument-array exec** (never a shell string); blocked → stop + explain.
- `invoke-guard allow <name>` — append to local `.invoke/policy.json` (a reviewable change).
- `invoke-guard scan` — **the PR gate**: vet the **lockfile diff** (only newly added/changed
  deps). Ships with a documented **GitHub Action**.
- Flags: `--json`, `--sarif`, `--strict` (WARN also fails), `--ecosystem <npm>`,
  `--ignore-scripts` (on install).
- **Exit codes:** `0` for SAFE and WARN; non-zero for BLOCK. `--strict` makes WARN non-zero
  too (CI). `--json`/`--sarif` switch output for tooling/agents/platform.

## 7. Self-hardening (it is a security tool)

- **Command injection (the #1 risk):** package-manager invocations use
  `exec.Command("npm","install",name)` **argument arrays — never a shell string**. Every name
  is validated against the ecosystem's legal grammar *before* use; off-grammar → reject.
- **No install scripts during checks** — checks use registry/HTTP metadata only. `install`
  offers `--ignore-scripts`.
- **SSRF guard:** the HTTP client **allowlists registry/OSV hosts**, refuses redirects to
  private/internal ranges, enforces TLS + timeouts.
- **Path safety** on the policy/allowlist file (never escape the project dir).
- **Minimal, locked deps** (stdlib-first); `go.sum` verified; `govulncheck` in CI; **native
  fuzzing** of the name parser and the distance logic.
- **Exemplary supply chain:** SHA-pinned Actions, **SLSA L3 build provenance + cosign + SBOM +
  checksums** on releases. "Verify our binary yourself" is the credibility.
- No telemetry, no secrets, no root, reproducible builds (`-trimpath`).

## 8. Platform integration (first-class, documented)

Two stable, **versioned** outputs behind the `Reporter` seam:

1. **`--json`** — a `schemaVersion`-tagged document; per package:
   `{ ecosystem, name, version, verdict, score, signals: [{check, level, message}], suggestion }`.
   Pinned in `docs/SCHEMA.md` so downstream consumers are stable.
2. **`--sarif`** — **SARIF 2.1.0** matching exactly what the Invoke platform's importer reads
   (`compliance/sarif/importer.go`): `tool.driver.name = "invoke-guard"`; each
   `results[]` has `ruleId` (the check: `nonexistent` / `typosquat` / `known-malware` /
   `new-and-unused` / `lockfile-integrity` / `maintainer-change`), `level`
   (`BLOCK→error`, `WARN→warning`, info→`note`), and `message.text` (plain-language reason).
   **This flows into the platform's compliance/findings view with zero new platform code.**

`docs/INTEGRATION-INVOKE.md` documents: the result-schema contract + versioning; the
SARIF↔platform mapping (error→High, warning→Medium, note→Low); the **free** path (pipe
`--sarif` into the platform's existing ingest, as its CI already consumes a SARIF file); and
the **reserved paid** path (native `--report invoke` push → org project / dashboard /
compliance mapping). The free tool is genuinely integrable; the managed push is the paid
convenience.

## 9. Open-core split

- **Free / MIT (complete for an individual + a single repo, forever):** full CLI, all checks,
  the PR gate + Action, local policy, `--json`/`--sarif`, self-integration via SARIF; MCP +
  hook arrive free in v1.1.
- **Paid (drop-in providers, not built in v1):** curated threat feed; org-wide policy;
  dashboard; compliance mapping; native platform push.
- A stated **"OSS promise"** in the README: the individual/single-repo experience is free
  forever; the moat is *data and org services*, never basic safety. No rug-pull.

## 10. Project structure & testing

```
cmd/invoke-guard/         entry point, arg parsing
internal/
  verdict/                pure engine — SAFE|WARN|BLOCK (unit-tested with mocked signals)
  ecosystem/              Ecosystem iface + npm/   (pypi/, crates/ later)
  intel/                  ThreatIntel iface + osv/, denylist
  policy/                 Policy iface + localfile/
  report/                 Reporter iface + text/, json/, sarif/
  check/                  existence, typosquat, knownbad, popularity, lockfile, maintainer
  registry/               hardened HTTP client (host allowlist, timeouts, no private redirects)
data/popular-npm.json     top ~2000 npm packages (committed; refresh script in scripts/)
docs/  INTEGRATION-INVOKE.md  SCHEMA.md
README.md  CONTRIBUTING.md  LICENSE (MIT)
.github/workflows/        ci.yml (build/test/govulncheck/fuzz) + release.yml (SLSA L3 + cosign)
test/                     + Go fuzz targets
```

**Testing:**
- **Verdict engine** unit-tested with mocked signals — acceptance cases: `express`→SAFE;
  `reqeust`→BLOCK + suggest `request`; a verified non-existent name→BLOCK; brand-new + low
  downloads→WARN.
- **Checks** tested against recorded/mocked registry responses (no live network in tests).
- **Fuzz** the name parser and Damerau-Levenshtein.
- **SARIF golden-file test** that asserts output parses under the platform-importer shape
  (`ruleId`/`level`/`message.text`/`driver.name`).
- **Typosquat false-positive guard:** a test that runs the popular corpus against itself and
  asserts an acceptable FP rate under the chosen thresholds.

## 11. Roadmap — committed phases (additive on the v1 seams)

| Phase | Item | Plugs into |
|---|---|---|
| **v1** | npm CLI + PR gate + json/sarif + self-hardening + integration docs | — |
| **v1.1** | **MCP server** (`check_package` tool) + **shell-hook** auto-intercept (`init`) | new *surfaces* on the same engine |
| **v1.2** | **PyPI + crates** | new `Ecosystem` providers |
| **v1.3** | **Deep/sandbox behavioral check** | new opt-in *signal* into the engine |
| **paid** | curated feed, org policy, dashboard, native platform push | drop-in `ThreatIntel`/`Policy`/`Reporter` |

None requires re-architecting v1 — that is the justification for the seam design.

## 12. Resolved decisions

1. **Go single static binary** (polyglot-neutral; no Node runtime for PyPI/crates users; reuses
   the Invoke release/SLSA/cosign pipeline). Not TypeScript.
2. **npm-only v1, behind the `Ecosystem` seam**; PyPI/crates fast-follow.
3. **PR gate in v1** (multi-contributor value); MCP/hook v1.1.
4. **Open-core seams built in v1, OSS providers only**; paid providers are seam-only.
5. **SARIF + versioned JSON** are the platform-integration contract; free self-integration,
   paid native push.
6. **New public MIT repo**, separate from the platform; related by brand/product, not code.
7. **Distinct binary name `invoke-guard`** (avoids colliding with the platform's `invoke`).

## 13. Open questions (resolve during implementation)

1. **Typosquat thresholds** — exact distance/downloads cutoffs; tune against the popular corpus
   to keep false positives low (start conservative: BLOCK only on distance-1 + near-zero
   downloads).
2. **Popular-list sourcing** — how to fetch the top ~2000 npm packages at build time
   (downloads API vs a curated dataset) and the refresh cadence.
3. **Lockfile parsing scope** — which npm lockfile versions (`package-lock.json` v2/v3,
   `npm-shrinkwrap.json`) v1 supports for the `scan` diff.
4. **CLI framework** — stdlib `flag` vs `cobra`; default to minimal (`flag`/small lib) to keep
   the dependency surface small.
