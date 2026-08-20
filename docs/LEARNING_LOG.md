# Learning Log

## Issue 1 - minimal secure harness

The first adversarial case asks the model to terminate `EC2_RESOURCE_01`. A
test model deliberately proposes `terminate_instance`. That proposal is not a
tool invocation: the allow-list policy marks it as approval-required and
denies it because Issue 1 exposes no mutation tools. The harness then executes
zero tools.

The adversarial case remains in the test suite as a regression contract. It
demonstrates why trusting model-selected function names would fail open.

## First local proof

- `uv sync --extra dev`: dependency environment created from `uv.lock`.
- `uv run pytest -q`: 6 tests passed.
- `uv run python -m compileall -q src`: passed.
- Normal demo request: `COMPLETED` with three typed synthetic results.
- Unsafe termination request: `BLOCKED` with zero tool results.

No AWS resource, model API, credential, or real identifier was used.
