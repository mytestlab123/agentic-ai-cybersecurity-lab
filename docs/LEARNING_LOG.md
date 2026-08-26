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

## Issue 5 - local Inspector-to-SSM visual proof

The FAST POC reuses the secure harness boundary and adds a dependency-free
browser adapter. A scripted plan proposes four read-only synthetic checks:
Inspector finding, instance context, SSM managed-node readiness, and patch
compliance. The result exposes aliases and typed state only, with stable
`policy_reason_codes` and `executed_calls` fields.

The browser stops at `APPROVAL_REQUIRED`. Reject records `HUMAN_REJECTED` and
Approve records `MOCK_REMEDIATION_NOOP`; both paths perform no mutation. An
unknown synthetic CVE is blocked before any tool runs. The local HTTP proof
used `CVE-2099-0001` and `SYNTHETIC_LAB`; no AWS, AgentCore, credentials, or
live sample deployment was used.

The browser surface was then upgraded to a ChatGPT-style workspace with a
conversation view, assistant tool cards, structured evidence cards, and inline
approval controls. The presentation change did not widen the tool registry or
change the approval/no-mutation contract.

## Issue 5 - read-only AWS evidence adapter

Milestone 2 now has a client-injected adapter for Inspector2, EC2, and SSM.
It filters one CVE, proves the finding binds to one exact instance, verifies
the required lab tags, and checks that the matching SSM node is online. Zero,
ambiguous, mismatched, or incomplete evidence returns `BLOCKED` before the
next call. Fake-client tests prove the request shapes and that raw IDs, IPs,
ARNs, titles, and backend exception text do not enter the result.

No live AWS profile, credentials, network call, SSM command, patch, reboot, or
mutation was used.

## Issue 5 - live-lab boundary and patch summary projection

The live path is now a repo-owned operator with separate `plan`, `apply`,
`collect`, and `cleanup` commands. `plan` is the safety gate: an available
AMI alone is not enough. The instance needs a private subnet with an existing
SSM path, a no-ingress security group, an existing instance profile, and
enabled Inspector EC2 coverage. Public IPs, new networking, new IAM, and
Inspector enablement are not silently added to make the demo pass.

The read-only adapter can optionally read SSM `AWS:PatchSummary` and projects
only patch counts plus strictly constrained package/version fields. The local
ChatGPT-style UI accepts a typed sanitized result upload; malformed or extra
fields produce a generic `REQUEST_REJECTED` response and are not echoed.

The current preflight found no complete launch plan, so no live instance,
SSM command, patch, reboot, or mutation was performed.
