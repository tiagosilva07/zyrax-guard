---
name: production-readiness
description: >
  A go/no-go checklist for shipping code to production. Use this whenever you're about
  to deploy, finishing a feature, opening a PR for real traffic, or someone asks "is
  this production-ready". Covers correctness, errors, security, observability, and
  scale. Applies to Go, React/TypeScript, and C#/.NET.
---

# Production-readiness gate

Run this before code reaches real users. Anything unchecked is a conscious risk
someone has to accept — not an oversight.

## Correctness
- [ ] Tests cover the new logic, including the failure paths — and they pass.
- [ ] Build is clean (no warnings treated as acceptable noise).
- [ ] Edge cases handled: empty, null/nil, very large, concurrent, boundary values.
- [ ] No debug code, dead code, or commented-out blocks left behind.

## Error handling
- [ ] Errors are handled or propagated with context — never silently swallowed.
- [ ] User-facing failures are graceful and recoverable; no raw stack traces shown.
- [ ] External calls (DB, network, third party) have timeouts and a failure path.
- [ ] Retries are bounded and idempotent where used.

## Security
- [ ] No secrets in code, logs, or client bundles.
- [ ] All external input validated; queries parameterized.
- [ ] AuthN/AuthZ checks on every protected path.
- [ ] (If sensitive surface) ran the `security-auditor`.

## Observability
- [ ] Structured logs at the right level — enough to debug an incident, not so much
      they leak data or drown signal.
- [ ] Key metrics emitted (latency, error rate, throughput on hot paths).
- [ ] Health/readiness endpoints exist (services).

## Performance & scale
- [ ] No obvious N+1 queries or unbounded loops on hot paths.
- [ ] Pagination/limits on anything that can grow unbounded.
- [ ] (If hot path under load) baseline measured; see the `perf-optimizer`.

## Operability
- [ ] Config via env/secret manager, not hardcoded.
- [ ] Graceful shutdown handled.
- [ ] Rollback path exists and is known.
- [ ] DB migrations are backward-compatible (can roll back without data loss).

## Stack quick-hits
- **Go:** `go vet` + `-race` clean on concurrent code; contexts plumbed through;
  errors wrapped.
- **React/TS:** loading/empty/error states present; no `any` without justification;
  bundle size sane.
- **C#/.NET:** no sync-over-async; `IDisposable` honored; nullable warnings addressed.

## How to use
State which items pass, which fail, and which don't apply. For each failing item,
either fix it or get an explicit decision to accept the risk. Don't quietly skip.
