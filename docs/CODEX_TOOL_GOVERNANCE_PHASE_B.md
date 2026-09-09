# SecCop Phase B — deterministic read-only tool governance

Status: **active implementation direction**

Recorded: 9 September 2026

Primary Issue: #77

Predecessor: merged PR #76, which proved genuine Codex App Server model-selected read-only tool use across EC2 IMDSv2, Security Group posture, S3 public access, and ECR/Inspector evidence with visible prompt/tool/arguments/provider result/model response.

## Objective

Add a deterministic **ALLOW / DENY policy gate** around those existing read-only tool calls.

North-star flow:

```text
operator question
-> Codex App Server
-> model selects bounded SecCop tool
-> typed alias-only arguments
-> deterministic policy
   -> ALLOW -> provider read -> sanitized evidence -> model response
   -> DENY  -> provider NOT called -> truthful BLOCKED result
```

Provider evidence remains truth. Codex selects and explains. Policy authorizes. For this phase only, execution means a bounded read-only provider query.

## Milestones

### B1 — policy decision contract

Every tool attempt yields an alias-only deterministic decision with `ALLOW` or `DENY`, a stable reason code, selected tool, and target alias. Unknown tool, wrong source, alias mismatch, or malformed arguments deny before provider execution.

### B2 — minimal allowlist

Only the four existing PR #76 tools are eligible:

```text
EC2 -> get_ec2_imdsv2
EC2 -> get_security_group_summary
S3  -> get_s3_public_access
ECR -> get_ecr_inspector_finding
```

Everything else denies. Do not introduce keyword routing; the App Server/model still selects the tool.

### B3 — visible governance receipt

The GUI must visibly separate:

```text
Prompt sent
Tool requested
Sanitized arguments
Policy decision
Provider executed: YES / NO
Provider/tool result
Model response
```

`Codex requested`, `policy allowed`, and `provider executed` are distinct facts.

### B4 — compact sanitized audit

Record only timestamp, source, tool, target alias, policy decision, provider-executed boolean, and turn result. No database, SIEM, OpenTelemetry, or external service.

### B5 — real acceptance proof

The repo-owned localhost:2222 path must prove ALLOW for EC2 IMDSv2, Security Group, S3, and ECR/Inspector, plus one deliberate DENY where the provider call does not execute.

Validation requires focused policy tests, full pytest, cheap Playwright, one real App Server proof, zero AWS writes, zero browser console errors, zero unexpected external browser requests, `git diff --check`, and public-safety review.

## Security boundary

Do not add remediation/write tools, SSM command execution, Config remediation execution, SG/S3/ECR mutation, IAM/networking changes, AgentCore, AgentGuard, LibreChat, broad AWS MCP/API access, generic AWS CLI/shell tools, RAG/memory, another LLM hop, or production deployment.

Existing Remediate / Reject / Approve semantics remain unchanged.

## Invariant

```text
Codex selects
Policy authorizes
Automation executes
Provider verifies
```

For Phase B, `Automation executes` means read-only provider query only.

## Handoff

When implementation is reviewable, leave one durable PR comment:

```text
HANDOFF: CHATGPT
Head: <exact SHA>
Result: PASS / READY
Next: complete-diff review
Accept: genuine App Server tool choice; deterministic ALLOW/DENY before provider call; visible policy receipt; DENY proves provider was not called; real localhost:2222 proof passes; zero AWS writes; public-safety pass.
```

Do not merge until ChatGPT reviews the final exact HEAD.