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

## Experiment 2 - validate model output at runtime

Python type annotations do not enforce an injected model's return value at
runtime. A deliberately malformed dictionary previously caused an
`AttributeError` before policy evaluation. The harness now validates model
output against `AgentPlan` and returns a generic `BLOCKED` result when
validation fails. No policy decision or tool execution occurs, and the raw
model output is not copied into evidence.

The focused regression test proves that malformed output fails closed with
zero tool results and zero executed calls.

## Experiment 3 - typed rejection audit event

Malformed model output now produces one typed audit event containing only the
fixed stage `MODEL_OUTPUT_VALIDATION`, outcome `BLOCKED`, and reason code
`MODEL_OUTPUT_REJECTED`. These stable fields are useful for filtering and
counting without copying untrusted model content into logs or evidence.

The existing malformed-output regression remains the canonical test. It now
also proves the event fields and confirms that an attacker-controlled fixture
value is absent from the serialized harness result.

## Experiment 4 - policy-denial audit event

Policy decisions now separate a stable machine-readable `reason_code` from the
short human-readable `reason`. A missing tool receives
`TOOL_NOT_ALLOWLISTED`; malformed arguments receive
`ARGUMENT_CONTRACT_MISMATCH`; an accepted call receives `TOOL_ALLOWED`.

Denied decisions produce typed `POLICY_AUTHORIZATION` audit events before the
harness returns `BLOCKED`. The event contains no prompt or argument values.
The unsafe-mutation regression proves the code and event while continuing to
prove zero executed tools.

## Issue 2 - local sanitization slice

The new `read_sanitized_instance` tool reads one synthetic AWS-shaped record
through a deterministic sanitizer. The raw fixture contains instance,
network, DNS, and tag-shaped fields using safe aliases. The model-visible
`SanitizedInstance` contains only `resource_alias`, `SYNTHETIC_LAB`, a
normalized state, and a coarse size class.

The regression test proves the allow-listed read completes and that every raw
fixture value is absent from the serialized result. No AWS SDK, account, or
live resource was used.
