# ChatGPT STRICT / FOCUS contract — Issue #53 v2

Canonical Issue: https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/issues/53

Implementation PR: https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/pull/54

Collaboration protocol: https://gist.github.com/amitkarpe/c8d29ad89cafe3ba178fcae29de3c238

Implementation branch:

```text
chatgpt/issue53-ecr-codex-focus
```

The Issue defines **WHAT** must be proven. PR #54/this branch defines **WHERE** Codex implements it. Do not create a replacement implementation Issue, branch, or PR unless Amit explicitly asks.

## One outcome only

```text
real vulnerable ECR digest
  -> ECR Enhanced Scanning / Amazon Inspector finding
  -> real user request reaches Codex App Server
  -> SAME Codex thread gets sanitized real BEFORE facts
  -> Codex explains/recommends from those facts
  -> exact proposal-bound clean-digest promotion
  -> APPROVAL REQUIRED
  -> Reject = zero mutation
  -> fresh proposal + Approve Once
  -> existing bounded ECR promotion path
  -> demo-current == exact approved clean digest
  -> Inspector proves target CVE absent on THAT digest
  -> SAME Codex thread gets sanitized AFTER facts
  -> Codex explains truthful final state
```

Nothing else is the objective.

---

# Non-negotiable truth boundaries

- **Codex App Server** = conversation/reasoning layer.
- **Amazon ECR Enhanced Scanning / Amazon Inspector** = AWS-native vulnerability evidence source.
- **SecCop proposal + policy + one-time approval + executor** = only mutation authority.
- **AWS MCP / Agent Toolkit** = optional knowledge tooling only unless a real run proves more.
- **Local Trivy** may remain secondary evidence but cannot satisfy #53 scanner or verification acceptance by itself.

Do not call this autonomous AWS remediation. Do not give Codex generic shell/AWS CLI/AWS MCP write authority.

---

# Critical prior gaps that #53 must actually close

## PR #52 gap

PR #52 uses AWS ECR for storage but LOCAL_TRIVY as scanner. It also uses `_ECR_APPROVAL_READY` boolean state for the simple ECR operator lane.

For #53:

1. scanner evidence must be real ECR Enhanced Scanning / Amazon Inspector;
2. approval must become proposal-bound to exact target/action/pre-state, not just a readiness boolean.

## PR #46 gap

PR #46 proves a real Codex App Server connection plus AWS-MCP knowledge-only integration. It does not prove a full real AWS before/after journey through one Codex thread.

For #53:

1. user's natural-language request must actually participate in the Codex turn;
2. real sanitized BEFORE facts must be sent to the real thread;
3. Codex must generate the explanation/recommendation from those facts;
4. sanitized AFTER facts must go to the **same** thread;
5. no fixed backend sentence may be represented as Codex output.

---

# STRICT execution order

## Gate 0A — registry scanning safety

Enhanced Scanning is a private-registry scanning configuration for a Region and is narrowed with repository filters.

Before any real scanner configuration mutation:

1. privately read/snapshot the current registry scanning configuration;
2. determine whether the demo repository is already covered;
3. if a change is required, present Amit the exact BEFORE -> AFTER config;
4. prefer an exact/narrow repository filter with `SCAN_ON_PUSH` for this POC unless continuous scanning is required and justified;
5. do not enable wildcard/all-repository continuous scanning merely for the demo;
6. keep the exact restore configuration and cleanup command.

Official references:

- https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced-enabling.html
- https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-filters.html

No real change before Amit explicitly approves the exact profile/Region/config/cost/restore plan.

## Gate 0B — pre-scan BOTH digests for a fast demo

Prefer to establish this before wiring product behavior:

```text
VULNERABLE_DIGEST
  Enhanced Scan ready
  TARGET_CVE = PRESENT

CLEAN_DIGEST
  Enhanced Scan ready
  TARGET_CVE = ABSENT
```

Then the live approved action can promote/re-tag the already-scanned clean digest, avoiding avoidable Inspector wait time during the presentation.

Start with urllib3 / `CVE-2019-11324` only if Inspector actually reports it. Do not hard-code the CVE before proof. If it is not reproducible, choose one similarly small deterministic package CVE and record why.

If a practical AWS-native finding cannot be produced, **STOP**. Leave PR #54 draft and report the blocker. Never silently substitute Trivy and declare success.

## Gate 1 — exact digest correlation

Privately correlate:

```text
repository
current tag alias (demo-current or existing equivalent)
vulnerable digest
target CVE
package/version evidence
approved clean digest
```

Use Inspector's exact ECR image hash/digest correlation internally (`ecrImageHash` is available in Inspector finding filters).

Public rendering remains aliases only. Never expose repository URI, raw digest, ARN, account ID, raw Inspector payload, auth/session token, private path, or private log.

## Gate 2 — real user request + real Codex BEFORE turn

The natural-language GUI path is functional, not cosmetic.

Example:

```text
Investigate the vulnerable ECR image, explain the risk, and remediate it safely.
```

The user's bounded text must actually be part of the Codex turn. Do not ignore it and replace the interaction with only a fixed backend prompt.

The backend still owns resource identity and mutation authority. User text cannot supply repository URI, digest, AWS command, or write target.

Send only sanitized real facts to Codex:

```text
resource alias
storage = AWS_ECR
scanner = ECR_ENHANCED_SCANNING / AMAZON_INSPECTOR
target CVE
package/version evidence
severity
allowed clean-state recommendation
```

Codex's response must be the actual App Server response generated from these facts.

## Gate 3 — proposal-bound ECR authority

Do not carry `_ECR_APPROVAL_READY` boolean as the final authorization contract.

Reuse SecCop's existing proposal hash/expiry/one-time approval concepts and bind the ECR proposal privately to at least:

```text
proposal_id / version
repository alias
current tag alias
expected vulnerable digest
approved clean digest
target CVE
exact action = promote approved clean digest
expected pre-state hash
expiry
proposal hash
```

Required:

```text
Reject -> zero mutation
Approve Once -> one exact promotion
replay -> DENY
expired -> DENY
demo-current changed/drift -> DENY
wrong target/action -> DENY
```

Immediately before promotion, re-read `demo-current` privately and prove it still resolves to the proposal-bound vulnerable digest.

## Gate 4 — fast AWS-native AFTER verification

After approval:

1. promote/re-tag only the proposal-bound clean digest;
2. re-read `demo-current` and prove it equals that exact clean digest;
3. prove AWS-native scanner evidence for the clean digest is usable/current;
4. query Inspector findings for the exact clean `ecrImageHash` and target CVE;
5. select only a truthful final state.

```text
VERIFIED
  = demo-current == approved clean digest
    AND scanner evidence for that digest is ready
    AND target CVE is absent for that exact digest

PENDING_RESCAN
  = demo-current == approved clean digest
    BUT AWS-native scanner evidence is not ready/eligible

FAILED
  = digest mismatch, scan failure/ambiguity,
    CVE still present, or required correlation failed
```

**No findings returned** is not sufficient for `VERIFIED` unless scanner readiness/coverage for that exact digest is also proven.

## Gate 5 — same Codex thread AFTER

The exact App Server `threadId` used for BEFORE must also receive AFTER. Do not silently create a replacement thread and claim continuity.

Public UI may show a safe alias such as `THREAD_01`; raw thread IDs stay private.

If thread continuity is lost, return a truthful reason such as:

```text
CODEX_THREAD_UNAVAILABLE
```

For this single-user POC, one active ECR demo conversation at a time is acceptable. Concurrent sessions must fail closed rather than mix thread/global state.

Send sanitized AFTER facts only:

```text
resource alias
current image alias
scanner provider
promotion state
verification state
target CVE state
```

Codex then explains the actual after-state.

---

# Expected implementation files

Prefer reuse and keep product changes around existing paths:

```text
scripts/seccop_demo.py
src/secure_agent_harness/poc_server.py
web/poc_chat.html
tests/test_poc.py
```

A small setup/restore note may be added if needed. File/line counts are warning signals, not rigid limits; unrelated files are a drift signal.

---

# Minimum meaningful validation

Do not grow tests for count.

1. fake Inspector finding bound to exact vulnerable digest;
2. wrong digest / ambiguous evidence -> fail closed;
3. proposal-bound ECR approval happy path;
4. Reject / replay / expiry / drift / wrong-target negative paths;
5. clean exact digest + scanner ready + target CVE absent -> `VERIFIED`;
6. exact clean digest + scanner unavailable/pending -> `PENDING_RESCAN`;
7. same fake App Server `threadId` receives BEFORE and AFTER;
8. lost/mismatched thread -> fail closed;
9. user request is actually included in Codex input while AWS target/action remain server-owned;
10. existing relevant EC2/S3/ECR regressions;
11. build/diff/public-safety checks;
12. one separately approved real browser/AWS rehearsal.

---

# DO NOT build

- AgentGuard/S3/new EC2 work;
- OpenAI Agents SDK;
- AgentCore or Strands migration;
- Open WebUI/LibreChat;
- RAG/database/memory;
- multi-agent orchestration;
- custom generic MCP gateway;
- generic AWS MCP write path;
- unrestricted Codex shell/AWS CLI authority;
- second CVE/operator journey;
- production platform redesign.

---

# Ready-for-review gate

Do not mark PR #54 ready until all are true:

- [ ] exact repository scanning scope is safe and restorable;
- [ ] real vulnerable digest has a real Inspector finding;
- [ ] clean digest has usable AWS-native scan evidence;
- [ ] user's natural-language request reaches the real Codex turn;
- [ ] same App Server thread receives real sanitized BEFORE and AFTER;
- [ ] Codex generates actual explanations from those facts;
- [ ] ECR action is proposal-bound, not boolean-ready;
- [ ] Reject/replay/expiry/drift/wrong-target deny correctly;
- [ ] Approve Once promotes only the approved clean digest;
- [ ] `demo-current` is re-read and equals that clean digest;
- [ ] Inspector verification is tied to the exact clean digest + target CVE;
- [ ] final state is truthful;
- [ ] public output is sanitized;
- [ ] no unrelated scope is added;
- [ ] Amit accepts the visible demo.

## Terminal stop condition

Stop when exactly one repeatable journey proves:

```text
real ECR/Inspector finding
+ real user -> Codex interaction
+ same Codex thread BEFORE/AFTER
+ proposal-bound one-time human approval
+ exact clean-digest promotion
+ exact AWS-native digest/CVE verification
+ truthful operator result
```

If any proof cannot be achieved, leave PR #54 draft/open and document the blocker. Do not reinterpret #53 to obtain a green checkmark.
