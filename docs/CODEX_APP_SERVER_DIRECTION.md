# SecCop Codex App Server direction

Status: **active product direction**

Recorded: 8 September 2026

Primary Issue: #73
Primary PR: #74

## Owner decision

The immediate priority is **not** AgentGuard integration, AgentCore integration,
LibreChat migration, another policy framework, another MCP framework, or more
security features.

The immediate priority is to prove that the existing SecCop GUI is genuinely
using **Codex App Server** in a way the operator can see, understand, question,
and repeatedly verify.

Amit has confirmed that Codex App Server itself can run and complete a turn.
The remaining product problem is **visibility, repeatability, and trust in the
GUI integration**.

Until this proof is strong, treat further platform convergence as deferred.

## Why this is a last-chance milestone

The current application has accumulated scans, deterministic findings,
remediation controls, approval state, App Server lifecycle state, and a chat
composer. Those pieces are individually useful, but the operator still cannot
look at the page and answer these basic questions with confidence:

1. Did this exact GUI action call Codex App Server?
2. What exact sanitized prompt was sent?
3. What model text came back from that turn?
4. Was the answer generated from the current ECR, S3, or EC2 evidence, or was it
   only deterministic UI copy?
5. Can I type a new AWS/security question in the composer and see a new App
   Server answer?
6. Can I repeat the flow several times without stale-session or hidden-state
   confusion?

If SecCop cannot prove those things clearly, more features will only increase
complexity without increasing confidence.

## Product principle

For this milestone:

> **Provider facts are deterministic truth. Codex App Server explains and
> investigates. The GUI must make that boundary visible.**

Codex does not authorize remediation. Provider evidence, proposal binding,
human approval, deterministic execution, and provider verification retain their
existing authority.

## Target user experience

### 1. Finding first

The operator scans ECR, S3, or EC2 and receives the normal deterministic finding.

Example:

```text
S3_BUCKET_ALIAS_03
AWS Config
NON_COMPLIANT
Block Public Access absent
```

The finding card must not pretend that deterministic copy is an AI response.

### 2. Explicit `Investigate with Codex` action

Each supported finding exposes one obvious action such as:

```text
[ Investigate with Codex ]
```

The action is separate from `Remediate`, `Approve Once`, and `Reject`.

Clicking it starts or continues the source-bound read-only/no-tool App Server
investigation.

### 3. Visible Codex proof card

After a successful live turn, the GUI should show a compact proof card similar
to:

```text
CODEX APP SERVER — LIVE TURN

Source:             S3
Stage:              INVESTIGATE / BEFORE
Model:              gpt-5.6-luna
Status:             LIVE_TURN_COMPLETED

Prompt sent
-----------
<the exact sanitized text submitted to turn/start>

Model response
--------------
<the exact sanitized agent text returned by App Server>
```

Optional low-risk metadata may include elapsed time and completed-turn count.
Do not expose thread IDs, request IDs, local paths, credentials, account IDs,
ARNs, instance IDs, raw provider payloads, or raw JSON-RPC envelopes.

The important proof is the **exact sanitized prompt plus exact sanitized model
text**, not internal transport metadata.

### 4. Composer must be a real App Server test surface

The existing composer must no longer feel decorative.

The operator should be able to type a normal short question such as:

```text
Why is IMDSv2 better than IMDSv1?
```

or:

```text
What should I check next for this S3 finding?
```

or:

```text
Explain common security-group risks in AWS.
```

and receive a visible Codex App Server answer.

Two modes are acceptable:

- **source-bound question**: if an ECR/S3/EC2 investigation is active, continue
  the same sanitized thread;
- **general AWS/security question**: if no source investigation is active, use
  a fresh ephemeral no-tool App Server thread and clearly label the answer as
  general model knowledge, not live account evidence.

Do not claim knowledge of the user's actual AWS environment unless provider
facts or an explicitly approved read-only tool supplied that evidence.

## One-brain rule

Do not add another hidden LLM behind this flow.

For the current SecCop product proof:

```text
SecCop GUI
   -> Codex App Server
   -> OpenAI model
```

is enough.

Avoid designs such as:

```text
GUI -> LLM A -> MCP -> Codex App Server -> LLM B
```

because they increase tokens, latency, ambiguity, and debugging difficulty.

## Consolidated milestones for Issue #73 / PR #74

These checkpoints are capability milestones, not mandatory separate PRs. Keep
them in the current PR unless a real blocker requires a split.

### M1 — visible live-turn receipt

Goal: the user can prove one App Server turn happened.

Acceptance:

- `Investigate with Codex` is visible from a finding;
- the GUI shows `LIVE_TURN_COMPLETED` only after a real App Server response;
- the exact sanitized prompt submitted to App Server is visible;
- the exact sanitized model response is visible;
- deterministic fallback text is clearly labeled as fallback and never shown as
  a live model result;
- current App Server model is visible, preferably `gpt-5.6-luna` while this is a
  low-cost proof.

### M2 — ECR, S3, and EC2 investigation proof

Goal: the same mechanism works for all three current SecCop stories.

Acceptance:

- ECR finding -> Investigate -> visible prompt/result;
- S3 finding -> Investigate -> visible prompt/result;
- EC2 IMDSv2 finding -> Investigate -> visible prompt/result;
- prompts include only the trusted sanitized source facts already owned by the
  server;
- switching source requires an explicit New investigation/reset when needed;
- busy or continuity errors explain the exact recovery action.

### M3 — composer / freeform App Server proof

Goal: random operator text is genuinely processed by Codex App Server.

Acceptance:

- a short arbitrary question can be submitted without pretending it is a CVE;
- when a source investigation is active, the question continues that source
  thread;
- when no source investigation is active, a fresh general no-tool thread may
  answer general AWS/security questions;
- the exact prompt and returned model text remain inspectable;
- input limits stay bounded and unsafe/private values are rejected rather than
  logged or echoed.

### M4 — repeatability and session proof

Goal: prove the feature does not only work once.

Acceptance sequence:

```text
S3 scan
-> Investigate with Codex
-> ask one follow-up
-> New investigation
-> EC2 scan
-> Investigate with Codex
-> New investigation
-> general AWS/security composer question
```

All App Server turns must either return a visible completed receipt or a
truthful visible BLOCKED reason. No stale hidden response may be reused.

### M5 — test and presentation evidence

Goal: make the proof cheap to repeat and easy for Amit to inspect.

Use the repository testing policy:

```text
pytest / direct API / mock transport    primary regression proof
small Playwright golden GUI flow         browser proof
one live local App Server smoke path     integration proof
```

Keep Playwright cheap: headless, one worker, no video, screenshots/trace on
failure. Presentation screenshots are intentional exceptions.

Retain a small sanitized evidence set showing at least:

1. one deterministic finding before investigation;
2. one `Investigate with Codex` prompt/result card;
3. one composer question/result;
4. one source reset followed by a second successful investigation.

The README beside those screenshots must state what each image proves and what
it does not prove.

## Prompt transparency contract

The visible `Prompt sent` field must be the same sanitized text used in
`turn/start`.

Do not construct one prompt for the model and a different reconstruction for the
UI. Build the sanitized prompt once, send that value, and return that same value
as the public proof field after the turn completes.

Likewise, `Model response` should be the sanitized agent-message text returned
by App Server, not a deterministic summary written separately by SecCop.

The GUI may truncate only with an explicit `Show full response` control. For the
POC, a bounded response length is preferable.

## Model and cost direction

Use the cheapest model that reliably proves the integration. `gpt-5.6-luna` is
the current preferred App Server model for this POC.

Do not optimize cost by hiding whether the model was called. Transparency is the
point of this milestone.

Token/cost economy should come from:

- short sanitized prompts;
- bounded response length;
- no second LLM hop;
- no tools for general proof unless needed;
- deterministic tests for most regression coverage;
- one thin live App Server proof rather than repeated agent-driven browser runs.

## Deferred next phases

Only after M1-M5 are repeatably proven should we consider the following.

### Phase A — read-only AWS knowledge/tools

Potentially add narrowly allowlisted read-only capabilities for questions such
as:

- Inspector findings;
- ECR scan configuration;
- S3 public-access/config state;
- EC2 metadata/IMDSv2 state;
- security-group posture;
- AWS documentation/knowledge lookup.

Each tool must make it obvious whether the answer is **general model knowledge**
or **live provider evidence**.

### Phase B — stronger tool governance

If read-only tools prove useful, then evaluate:

- explicit MCP tool allowlists;
- deterministic tool argument validation;
- policy ALLOW/DENY;
- human approval for mutation;
- audit events for tool request -> decision -> effect -> verification.

### Phase C — portfolio convergence, currently deferred

The longer-term architecture direction remains:

```text
LibreChat or another shared operator shell
        -> one OpenAI/Codex reasoning brain
        -> bounded SecCop / AgentGuard domain tools
        -> human approval
        -> AgentCore Gateway / deterministic policy
        -> deterministic AWS action
        -> provider verification
```

Possible role split:

- LibreChat: shared operator/chat/approval UX;
- OpenAI/Codex: one reasoning brain;
- SecCop: security domain logic and ECR/S3/EC2 evidence/proposals;
- AgentGuard: compliance/policy/replay/drift patterns;
- AgentCore Gateway: independent authorization guardrail;
- AWS/provider systems: execution and final truth.

**Do not start this convergence while the basic SecCop App Server product proof
is still questionable.**

## Explicit non-goals for the current milestone

Do not add merely to make the project look more advanced:

- LibreChat migration;
- AgentGuard integration;
- AgentCore integration;
- FAST;
- RAG/vector database;
- memory;
- multi-agent orchestration;
- broad MCP server inventory;
- AWS mutation;
- new IAM permissions;
- production deployment;
- another custom frontend;
- another observability platform.

## Stop condition

This is a deliberately hard product gate.

If, after this consolidated milestone, Amit still cannot repeatedly do all of
these from the GUI:

```text
see finding
-> click Investigate with Codex
-> inspect exact prompt
-> inspect actual model response
-> type a follow-up
-> receive another App Server response
-> reset
-> repeat on another source
```

then stop feature development in this repository and reassess the implementation
rather than adding more integrations or features.

The acceptance test is the operator-visible product behavior, not the number of
PRs, tests, helper functions, or documentation files.