# Changelog

## v0.1.0

First tagged release. A fully offline, reproducible agent attack/defense cyber range mapped
to OWASP ASI01-10.

- Synthetic company environment: email, documents, calendar, memory, tickets, payments,
  with MCP-style signed tool manifests and a deterministic seed.
- Attack catalog: ten attacks, one per ASI category, with delayed triggers and world-state
  objective checks.
- Control plane: kill switch, circuit breaker, signed manifests, OPA/Cedar-style
  authorization, signed delegation, provenance/taint, hard budgets, trajectory monitor,
  consequential-action approval, memory quarantine/expiry, content classifier, and an
  append-only incident recorder.
- Six defense presets and an experiment engine: security-utility table, Pareto frontier with
  Wilson intervals, and an acceptance gate mapping every mitigation to a reproducible attack.
- Typer CLI: `taxonomy`, `attacks`, `defenses`, `run`, `experiment`, `pareto`,
  `verify-gate`, `demo`.
- 20 tests, all passing, no network required.

Headline results: a content classifier leaves 59% attack success and is structurally blind
to authorization and delayed-memory attacks; deterministic controls cut this to 7%; adding a
trajectory monitor reaches 0% at no measured utility loss in this environment.
