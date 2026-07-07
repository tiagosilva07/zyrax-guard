---
name: accessible-components
description: >
  Patterns for building reusable, accessible, production-grade React/TypeScript UI
  components. Use this whenever you create or review a UI component, build a form,
  design a component API, or work on the frontend — even if accessibility isn't
  explicitly mentioned. Covers state handling, a11y, responsiveness, and prop design.
---

# Production-grade React components

A component is "done" when it handles the messy real world, not just the happy path.

## Every component must handle all four states

Never build only the success state. Explicitly handle:

1. **Loading** — show a skeleton or spinner; don't leave a blank flash.
2. **Empty** — a real "nothing here yet" state with guidance, not an empty `<div>`.
3. **Error** — a recoverable message; never a silent failure or a crash.
4. **Success** — the actual content.

If a component fetches data, all four are required. Reviewers should reject any that
only renders the success case.

## Accessibility (non-negotiable, build it in from the start)

- **Semantic HTML first.** A `<button>` is a button. Don't make `<div onClick>` when a
  native element exists — you lose keyboard and screen-reader support for free.
- **Keyboard operable.** Everything clickable must be reachable and usable with Tab /
  Enter / Space / Esc. Visible focus styles — never `outline: none` with no replacement.
- **Labels & names.** Every input has an associated `<label>`. Icon-only buttons get an
  `aria-label`. Images get meaningful `alt`.
- **ARIA only when HTML can't.** Prefer native semantics; reach for ARIA roles/states
  for custom widgets (modals, tabs, comboboxes) and manage focus correctly.
- **Color isn't the only signal.** Pair color with text/icon; check contrast (WCAG AA).
- **Announce dynamic changes** (loading, errors) via `aria-live` where appropriate.

## Reusability & API design

- **Props are a contract.** Type them precisely; required vs optional is meaningful.
  Provide sensible defaults so the common case is one line.
- **Composition over configuration.** Prefer `children` and slots over a dozen boolean
  flags. If a component has 15 props, it's probably two components.
- **Controlled vs uncontrolled** — pick one deliberately and document it.
- **Don't hardcode** spacing/colors; use design tokens / theme variables.
- **No business logic inside presentational components** — pass data and callbacks in.

## Responsiveness

- Mobile-first; test at small, medium, large widths.
- Fluid layouts (flex/grid) over fixed pixel widths.
- Touch targets large enough to tap (~44px); don't rely on hover for essential actions.

## Deliver with the component

- **Props/API** table (name, type, default, purpose).
- **Usage example(s)** — the common case and one edge case.
- **The four states** demonstrated.

## Quick review checklist

- [ ] Loading / empty / error / success all handled
- [ ] Keyboard operable with visible focus
- [ ] Labels / alt / accessible names present
- [ ] Types precise; sensible defaults
- [ ] No business logic baked in; reusable
- [ ] Responsive; tokens not magic numbers
