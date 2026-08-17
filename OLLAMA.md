# Running AgentSec Range with a local Ollama model

AgentSec Range can drive the range with a real local LLM instead of the simulated agent or
the offline parsing agent. The Ollama backend is built in and uses only the standard library,
so there is nothing extra to `pip install`.

## 1. Install Ollama and pull a model

Install from https://ollama.com/download, then pull a model:

```bash
ollama pull llama3.2        # ~3B, light: runs on ~4-6 GB of free RAM
# or, if you have plenty of RAM/VRAM:
ollama pull llama3.1        # 8B, needs roughly 8-16 GB free
```

Check what is available and that the server is up:

```bash
ollama list
curl http://localhost:11434/api/tags
```

### Choose a model your machine can load

An 8B model can need well over 8 GB of RAM to load. If you see an error like
`out-of-memory during startup: failed to allocate buffer of size ...`, the model is too big
for the free memory on your machine. Use a smaller one (`llama3.2`, `llama3.2:1b`,
`qwen2.5:3b`, or `phi3:mini`) and pass that name to the commands below.

## 2. Run the range through the model

Pass `--backend ollama:<model>` to any live command:

```bash
agentsec run-live --attack goal-hijack --defense no_defense      --backend ollama:llama3.2
agentsec run-live --attack goal-hijack --defense combined_monitor --backend ollama:llama3.2
agentsec live-experiment --backend ollama:llama3.2
```

Now the tool calls come from a real local model reading the planted content. The control
plane, metrics, and incident traces are identical to the simulated and parsing paths, so the
results are directly comparable.

## 3. Notes

- **First call is slow.** The model loads into memory on the first request (tens of seconds).
  The adapter waits up to 5 minutes, so let it finish; later calls are faster.
- **Custom host or port:** set `OLLAMA_HOST`, for example
  `export OLLAMA_HOST=http://localhost:11434`.
- **Small models may not tool-call cleanly.** The agent is asked to reply with a JSON list of
  tool calls. Larger instruct-tuned models follow this better; a tiny model may ramble, which
  yields fewer parsed calls. That is itself a real finding about model reliability, but for
  clean tool-calling prefer `llama3.1` (if it fits) over a 1B model.
- **Hosted models need no local install.** If your machine cannot run a model at all, use the
  hosted backend with any OpenAI/Anthropic-compatible API key instead:
  `AGENTSEC_LLM_BASE`, `AGENTSEC_LLM_KEY`, `AGENTSEC_LLM_MODEL`, then
  `--backend hosted:gpt-4o-mini`.
