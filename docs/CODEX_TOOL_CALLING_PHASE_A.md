# SecCop Phase A — read-only Codex tool calling

Status: **active next direction**

Recorded: 9 September 2026

Primary Issue: #75

Predecessor: #73 / PR #74, which proved that the SecCop GUI can repeatedly run real Codex App Server turns for EC2, S3, ECR, follow-up chat, and general AWS/security questions while showing the exact sanitized prompt and actual model response.

## Objective

Move from **Codex explains evidence already supplied by SecCop** to **Codex chooses one tightly bounded read-only SecCop tool, receives sanitized live provider evidence, and explains it**.

The product must visibly prove the entire chain:

```text
operator question
-> Codex App Server
-> tool selected by Codex
-> alias-only typed arguments
-> SecCop resolves provider target privately
-> read-only provider evidence
-> sanitized tool result
-> Codex response
```

Provider evidence remains authoritative. Codex investigates and explains; it does not authorize remediation.

## One-brain rule

Keep:

```text
SecCop GUI
-> Codex App Server
-> OpenAI model
-> bounded SecCop read-only tools
```

Do not introduce another hidden LLM or hard-coded keyword router and call it model-driven tool selection.

## Initial tool catalog

The initial catalog is deliberately small:

```text
get_ec2_imdsv2(target_alias)
get_s3_public_access(target_alias)
get_ecr_inspector_finding(target_alias)
get_security_group_summary(target_alias)
```

The first three should reuse existing SecCop provider-read logic. Security Group posture is the one new investigation capability.

Never expose generic tools such as:

```text
run_aws_cli
execute_shell
call_any_aws_api
run_ssm_command
remediate
```

## Transparency contract

For a tool-assisted live turn, the GUI must distinguish:

```text
Prompt sent
Tool requested
Sanitized arguments
Provider/tool result
Model response
```

`LIVE_TURN_COMPLETED` means the App Server turn actually completed. A deterministic fallback, blocked tool, unavailable provider, or rejected argument must never be rendered as a successful live model/tool result.

The browser/model may see aliases such as:

```text
DEV_EC2_LAB_01
SG_LAB_01
S3_BUCKET_ALIAS_03
ECR_IMAGE_01
```

Real account identifiers, ARNs, resource IDs, credentials, raw provider payloads, request/thread IDs, and private paths stay server-side.

## Five milestones in one PR

### A1 — self-contained live E2E

Remove the default dependency on the sibling AgentCore checkout for Playwright. SecCop's repo-owned live proof must run from this repository alone, while keeping the listener ownership/check-out checks and cheap headless behavior.

### A2 — visible tool-call receipt

Extend the existing live-turn card to show tool name, alias-only arguments, sanitized provider/tool result, and final model response.

### A3 — bounded read-only tools

Implement the four-tool catalog with typed arguments, private alias resolution, fail-closed validation, sanitization, and no write authority.

### A4 — genuine App Server tool selection

Prove the model chooses/calls the appropriate bounded tool for EC2 IMDSv2, Security Group posture, S3 public access, and ECR/Inspector questions. Unsupported requests must be truthful rather than silently substituted.

### A5 — repeatable real GUI proof

Use the repo-owned runner to prove:

```text
EC2 question -> EC2 tool
SG follow-up -> SG tool
reset
S3 question -> S3 tool
reset
ECR question -> ECR/Inspector tool
unsupported case -> truthful blocked/no-tool result
```

The proof must assert expected tool name, sanitized alias, provider-evidence label, final model response, no AWS writes, no console errors, and no unexpected external browser requests.

## Testing economy

Use:

```text
pytest / API / mock transport
-> cheap Playwright GUI regression
-> one real localhost:2222 App Server tool-calling proof
```

Do not build another browser framework or a broad integration harness.

## Explicit non-goals

This phase does not authorize:

- remediation/write tools;
- changes to Approve Once / Remediate / Reject semantics;
- AgentCore, AgentGuard, or LibreChat integration;
- RAG/vector DB/memory;
- broad AWS MCP/API access;
- another LLM hop;
- production deployment;
- IAM/networking changes unless a concrete blocker is first demonstrated and separately approved.

## Next phase after this succeeds

Only after read-only model-driven tool calling is repeatable should the project evaluate stronger tool governance such as policy ALLOW/DENY, human-approved one-write-tool experiments, and later portfolio convergence with AgentCore/AgentGuard/LibreChat.