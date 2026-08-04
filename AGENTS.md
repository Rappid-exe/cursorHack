# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of
  adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current
  requirements. Avoid speculative abstractions, configuration, and
  indirection.
- Grow the system in layers. Start from the smallest version that works end
  to end, and add each new capability on top of a product that already
  works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall
  complexity or improve reliability. Do not reimplement common
  functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own
  implementation or adding packages. Do not assume a library lacks a
  capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap
  that only works for now and is meant to be replaced later.

## Project-specific

- **The model never makes a security claim.** It classifies tool capability
  against a closed vocabulary and locates verbatim spans. Every path,
  severity and recommendation comes from the rule table in `src/lib/engine`.
  A change that lets model output reach a finding unvalidated is wrong even
  if it produces better findings.
- **Datasets are pulled at build time and committed.** The running app makes
  no outbound request. If a feature needs live data, it needs a seed script.
- **Report clean results as clean.** The census says zero servers carry an
  actively-exploited CVE because that is what we measured. Never manufacture
  a finding to make a demo land.
- `npx tsx scripts/verify-engine.ts` and `scripts/verify-fallback.ts` must
  pass before any commit. They exist to catch the failures that do not break
  the build.
