---
name: clean-architecture
description: >
  Principles and checks for structuring code with clear boundaries, low coupling, and
  high cohesion. Use this whenever you are designing a new module, refactoring existing
  code, reviewing structure, deciding where logic should live, or untangling a messy
  codebase — even if the user doesn't say the words "clean architecture". Applies to
  Go, React/TypeScript, and C#/.NET.
---

# Clean architecture (applied, not dogmatic)

The goal is code that's easy to change safely. Use these principles as a lens, not a
religion — apply the ones that reduce real coupling, skip ceremony that doesn't.

## Core principles

1. **Separate concerns by responsibility.** Transport (HTTP/handlers), business logic
   (services/use-cases), and data access (repositories) are three different jobs. Keep
   them in different units so a change to one doesn't ripple into the others.
2. **Depend inward, on abstractions.** Business logic should not import the database
   driver or the web framework. Define interfaces it needs; let the outer layers
   implement them. Dependencies point toward the domain, never out of it.
3. **High cohesion, low coupling.** Things that change together live together; things
   that don't, don't. A package/module should have one clear reason to exist.
4. **No leaky boundaries.** Don't pass framework types (HTTP requests, ORM entities)
   into business logic. Translate at the edge.
5. **Single source of truth.** One place for each piece of logic. Duplication is a bug
   waiting to diverge.

## When structuring or refactoring, check:

- Can I describe each unit's single responsibility in one sentence? If not, split it.
- Does business logic depend on a concrete framework/DB? Invert it behind an interface.
- Is the same logic in more than one place? Consolidate.
- Could I swap the database or the web layer without touching business rules? That's
  the test for whether boundaries are clean.
- Am I adding a layer that doesn't pull its weight? Remove it. Simplicity wins.

## Stack-specific shape

**Go**
```
/cmd            entrypoints
/internal
  /transport    http handlers, routing, request/response mapping
  /service      business logic, depends on repo interfaces
  /repository   data access, implements interfaces
  /domain       core types, no external imports
```
Define repository interfaces in the service layer (consumer side), implement them in
`/repository`. Wrap errors with context as they cross boundaries.

**React / TypeScript**
- Separate **presentation** (dumb components) from **container/logic** (hooks).
- Put server-state access behind a data layer (e.g. query hooks), not inside UI.
- Shared logic → custom hooks; shared UI → reusable components. No business rules
  buried in JSX.

**C# / .NET**
- Layered or vertical-slice; domain project has no dependency on infrastructure.
- Constructor injection; program against interfaces; keep EF/DbContext out of the
  domain.

## Do not

- Add abstraction "for later" with no current consumer.
- Refactor and change behavior in the same step (see the `refactorer` agent's rule).
- Mistake "more folders" for "better architecture." Boundaries are about dependencies,
  not directory count.
