# Changelog

## v0.2.0

Live agents: the range can now be driven by an agent that reads the environment as text and
derives its own tool calls, instead of only the simulated susceptibility dial.

- Pluggable `AgentBackend` interface with three backends, all behind one protocol:
  - `ParsingAgent`: reads email, docs, memory, and tool manifests and parses instructions
    into tool calls. No model, no API key, fully offline. Runs today.
  - `HostedAgent`: any OpenAI/Anthropic-compatible chat endpoint over HTTP, configured from
    the environment. Needs only an API key, no local model.
  - `OllamaAgent`: a local Ollama server, optional.
- `run_live` reuses the same control plane, metrics, and objective checks as the simulated
  path, so results are directly comparable.
- New CLI: `agentsec run-live` and `agentsec live-demo`.
- 21 new tests (41 total): the live agent is hijacked purely by reading attacker-controlled
  content with no defense, is stopped by the combined stack, and a cautious agent that
  ignores instructions found inside data is never hijacked.

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
