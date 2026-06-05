# Integrating Invoke Guard with the Invoke platform

Guard runs locally and in CI with no backend. Its results can flow into the Invoke
supply-chain platform for org-wide visibility and compliance mapping.

## Free path — SARIF (works today, no platform changes)

`invoke-guard scan --sarif > guard.sarif` emits SARIF 2.1.0 whose results match
exactly what the Invoke platform's SARIF importer reads:

| SARIF field | Value |
|---|---|
| `runs[].tool.driver.name` | `invoke-guard` |
| `results[].ruleId` | the check: `nonexistent`, `typosquat`, `known-malware`, `new-and-unused`, `lockfile-integrity`, `maintainer-change` |
| `results[].level` | `error` (BLOCK) / `warning` (WARN) / `note` (info) |
| `results[].message.text` | `name@version: <plain-language reason>` |

The platform maps `error→High`, `warning→Medium`, `note→Low`. Upload `guard.sarif`
the same way the platform's own scanners publish SARIF — Guard findings then appear
in the project's compliance/findings view, mapped to supply-chain controls.

## JSON path — tooling

`--json` emits the versioned schema in `SCHEMA.md` for custom integrations/agents.

## Paid path (roadmap) — native push

A future `--report invoke` pushes results directly to an Invoke org project
(authenticated), adding the dashboard, org policy, curated-feed verdicts, and
compliance reporting. Reserved on the same Reporter seam; the SARIF/JSON paths stay
free forever.
