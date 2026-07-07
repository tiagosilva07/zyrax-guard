# Claude Code starter setup — Go / React (+ C# later)

A small, opinionated `.claude/` team for building production code. The design follows
one rule: **use the cheapest primitive that fits the job.** Not everything is an agent.

## What's here

```
CLAUDE.md                         baseline standards, loaded every session
.claude/
  commands/
    plan.md                       /plan — tech-lead orchestrator (clarify → route)
  agents/                         specialist workers (isolated context, scoped tools)
    architect.md                  design new features/services/MVPs
    refactorer.md                 clean up code without changing behavior
    debugger.md                   root-cause bugs and failures
    perf-optimizer.md             fix measured performance problems
    security-auditor.md           READ-ONLY security review
    devops.md                     deploy, CI/CD, monitoring
  skills/                         shared playbooks, auto-loaded when relevant
    clean-architecture/SKILL.md
    accessible-components/SKILL.md
    production-readiness/SKILL.md
```

## How the pieces relate

- **CLAUDE.md** is always on — the senior-engineer baseline every agent inherits.
- **Skills** are *standards* ("how we build X"). Claude pulls them in automatically when
  the work matches the description. They're shared, so a standard lives in one place.
- **Subagents** are *workers* with their own context window and scoped tools. They cost
  more (a subagent-heavy session can use several times the tokens of a single thread),
  so they're reserved for isolatable, output-heavy work.
- **/plan** is the *orchestrator*: it clarifies the request, decides the approach, and
  routes steps to the right specialist — the tech-lead role.

## Install

Drop `CLAUDE.md` and `.claude/` at the root of your repo:

```
your-repo/
  CLAUDE.md
  .claude/
  ... your code ...
```

To use these across all projects instead, put the same files under `~/.claude/`.
Restart Claude Code so it picks up the new agents and skills. Run `/agents` to confirm
the subagents are registered, and `/plan <your task>` to start a planned build.

## Day-to-day usage

- Starting something non-trivial → `/plan add user auth with refresh tokens`
- Direct delegation also works → "use the security-auditor on the payments package"
- Most of the time you just work normally; skills and agents trigger themselves when the
  description matches what you're doing.

## If you want to start smaller

The full set is here because it maps to the work you described, but you don't need all
of it on day one. A solid minimum is **CLAUDE.md + architect + refactorer +
security-auditor**, plus the **clean-architecture** and **production-readiness** skills.
Add `debugger`, `perf-optimizer`, and `devops` when you actually hit those needs.

## Tuning the models

Each agent has a `model:` field in its frontmatter. Deep-reasoning agents (`architect`,
`security-auditor`) are set to `opus`; the rest to `sonnet`. Change these to fit your
budget — set any to `inherit` to use whatever model the session is running, or `haiku`
for cheap, simple passes.

## Adding C# later

When you start C# work, you mostly **don't** need new agents — the roles are
language-agnostic. To tune them:

1. Add C#/.NET conventions to the `## Stack` section of `CLAUDE.md`.
2. The agents and skills already include C#/.NET notes; expand them as your patterns
   settle (preferred project layout, DI container, test framework, etc.).
3. If C# work develops its own substantial playbook, add a skill (e.g.
   `.claude/skills/dotnet-patterns/SKILL.md`) rather than a new agent.

## A note on tradeoffs

This is a starting point, not scripture. If an agent never triggers, sharpen its
`description`. If two agents keep overlapping, merge them. If you find yourself
re-typing the same instructions, that's the signal to capture them — as a skill if it's
a standard, a command if it's a manual workflow, or CLAUDE.md if it's always-on.
