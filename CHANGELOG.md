# Changelog

## v0.3.2

- Ollama now works on normal laptops: the adapter caps the context window (`num_ctx=4096`,
  override with `OLLAMA_NUM_CTX`). Ollama otherwise allocates the model's full 128k context,
  whose KV cache needs ~14 GB and fails to load. Verified end to end with `llama3.2`: the real
  model is hijacked with no defense and blocked by `combined_monitor`.
- Fixed a missing `urllib.request` import in the live adapter.

## v0.3.1

- Ollama/local-model robustness: the live HTTP adapter now waits up to 5 minutes (local
  models are slow to load) and reports server errors, including out-of-memory, as a single
  clean line instead of a stack trace. `run-live` catches backend errors gracefully.
- Added `OLLAMA.md`: install, pick a model your machine can load, and run the range through a
  real local model with `--backend ollama:<model>`.

## v0.3.0

- `agentsec plot`: renders the security-utility Pareto frontier to `docs/pareto.png` with
  Wilson intervals on both axes and the non-dominated point highlighted. `--live` computes it
  with the live parsing agent. The image now leads the README.
- New `plotting.py` module (matplotlib behind the optional `plot` extra, headless/CI-safe).
- 44 tests: the plot writes a valid PNG.

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
- New CLI: `agentsec run-live`, `agentsec live-demo`, and `agentsec live-experiment` (the
  security-utility table and Pareto frontier computed with the live agent).
- Reproducibility fix: the run loop no longer seeds its RNG from Python's per-process
  ``hash``, so every result is identical across machines and independent of PYTHONHASHSEED.
- 23 new tests (43 total): the live agent is hijacked purely by reading attacker-controlled
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
