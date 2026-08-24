# Agentic AI Cybersecurity Lab

A public, personal learning lab for understanding secure agent engineering with
small Python experiments. Every example uses synthetic identifiers and local
fixtures.

## Issue 1: secure agent harness

The first experiment separates an untrusted plan-producing model from a
deterministic harness:

```text
user request
  -> model proposes a typed plan
  -> policy validates every proposed tool call
  -> harness stops if any call is denied
  -> narrow read-only tool reads synthetic data
  -> typed result and evidence
```

The local `ScriptedModel` is not an LLM. It makes the model boundary runnable
without an API key or paid service. A real probabilistic model can later
implement the same protocol, but it never receives direct tool authority.

The Issue 1 tools can only read:

- a synthetic security finding;
- synthetic workload metadata;
- a synthetic patching SOP.

Issue 2 adds one local sanitization slice: a synthetic AWS-shaped instance
record is reduced to an alias-only view before it becomes model-visible. No AWS
SDK or live account is used.

Unknown tools, mutation proposals, malformed arguments, and unknown fixture
IDs fail closed.

## Run locally

```bash
uv sync --extra dev
uv run pytest -q
uv run python -m secure_agent_harness.demo
```

No AWS account, API key, network service, or real security data is required.
`uv.lock` pins the resolved learning environment.

## Learning vocabulary

- **LLM:** a probabilistic model that may propose a plan. No real LLM is used
  yet.
- **Agent:** the plan-producing model adapter plus its instructions.
- **Harness:** deterministic code that validates, authorizes, dispatches, and
  records tool use.
- **Tool contract:** the typed input, typed output, and narrow behavior a tool
  promises.
- **Fail closed:** uncertainty or invalid input means no tool executes.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the control flow and
[docs/LEARNING_LOG.md](docs/LEARNING_LOG.md) for evidence.
