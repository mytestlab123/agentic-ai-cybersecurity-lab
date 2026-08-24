# FAST POC adaptation study

Status: Issue #5, Phase 0 study plus Milestone 1 local proof. This note does
not deploy an upstream sample, call AWS, create resources, or authorize a
remediation.

## Decision

Use the [AWS WAF Analyst sample](https://github.com/aws-samples/sample-building-a-conversational-ai-agent-for-aws-waf-analysis-with-agentcore)
as the visual shell for the first browser demo. It already provides the
shortest path to a chat experience with a React frontend, a streaming client,
and a FastAPI/AG-UI server lifecycle. Its WAF-specific domain logic is not the
security boundary and will not be carried into the new demo.

Keep this repository's secure harness as the deterministic control plane:

```text
browser request
  -> typed local proposal
  -> complete-plan validation
  -> deterministic policy
  -> allow-listed synthetic tools
  -> sanitized structured evidence
  -> explicit Approve/Reject gate
```

The first implementation target is a local, clearly-labelled synthetic demo.
The browser must prove the flow before any AgentCore deployment or real AWS
read is considered.

## Reuse boundary

| Upstream part | Decision for Milestone 1 | Reason |
| --- | --- | --- |
| React chat layout and message rendering | Reuse/adapt | Gives the demo a visible browser surface quickly. Keep output sanitization and do not expose raw tool payloads. |
| Streaming client and tool activity events | Reuse/adapt | Makes mock Inspector, EC2, and SSM calls visible as an event sequence. A local endpoint may replace AgentCore for the first run. |
| FastAPI/AG-UI request and stream lifecycle | Reuse/adapt | Provides a thin transport boundary around the existing deterministic harness. |
| Interrupt/resume idea (`ask_user`-style flow) | Reuse concept | Map it to a clear Approve/Reject decision. Approval cannot add a tool that policy or the registry does not contain. |
| WAF deployment stacks, Cognito, CloudFront, Memory, KB, DynamoDB, and IAM | Defer | These are deployment and cost surfaces, not prerequisites for a local visual proof. |
| WAF tools, WAF session state, JA4 analysis, Athena/log queries, WAF reports, and patrol logic | Remove from the POC path | They are unrelated to Inspector-to-SSM CVE triage and would make the demo harder to audit. |

## New deterministic POC slice

The first local adapter should expose only narrow synthetic readers and one
proposal operation. Names below are proposed contracts, not implemented tools:

- `find_inspector_finding(cve_id, lab_env)` - returns a typed synthetic
  finding summary, never a raw Inspector response.
- `get_instance_context(resource_alias)` - returns an alias-only instance
  view from a local fixture.
- `get_ssm_node_context(resource_alias)` - returns synthetic managed-node
  readiness and platform facts.
- `get_patch_compliance(resource_alias, cve_id)` - returns synthetic
  compliance evidence.
- `propose_mock_remediation(resource_alias, cve_id)` - returns a typed
  proposal only; it must not change a fixture or call SSM.

The typed result should include stable fields such as `cve_id`, `lab_env`,
`resource_alias`, `finding_state`, `patch_state`, `policy_decision`,
`reason_code`, and `executed_calls`. It should not include account IDs, ARNs,
hostnames, IP addresses, secrets, raw model output, or raw AWS-shaped
responses. A malformed model proposal stops before policy and tool execution.
Any policy denial is recorded with a stable reason code and must prove
`executed_calls == []`.

The browser proof should show, in order:

1. a user-entered CVE and a synthetic lab selector;
2. visible tool-call events for the four read-only checks;
3. a structured finding-to-asset result;
4. a deterministic remediation proposal and policy decision;
5. Approve and Reject controls, with Reject ending the flow and Approve only
   entering a mock remediation step.

The mock remediation step is deliberately a no-op with an explicit result. It
is not a disguised SSM call. Approval evidence must say what was proposed,
what policy allowed, and which calls actually ran.

## What to borrow from the other samples

The [Sentinel Harness sample](https://github.com/aws-samples/sample-sentinel-harness)
is a reference for ideas, not the application shell. Its useful patterns are
clearly-labelled mock/live backends, deterministic CVE-to-asset correlation,
structured evidence, and a mandatory human-review pause/resume loop. Its
broader harness, registry, specialist, evaluation, MCP, and infrastructure
surface is too large for this fast POC.

The [MSP Ops Automation sample](https://github.com/aws-samples/sample-MSP-Ops-Automation-V2)
is remediation architecture reference only. Its multi-agent, ECS/Fargate,
AgentCore, MCP, cross-account, and asynchronous operations surface would add
deployment and authorization complexity before the local learning objective
is proven.

## Fastest browser path

1. Keep the current Python harness and fixtures as the source of truth for
   contracts, policy, registry, and evidence.
2. Add a small local HTTP adapter that emits the same event vocabulary the
   browser needs (`run`, `tool start`, `tool end`, `result`, `approval`).
3. Adapt the WAF shell's chat and event components to the adapter, removing
   WAF labels and report actions.
4. Run a deterministic fixture scenario end to end: known CVE plus one
   synthetic affected resource, then the Reject and Approve branches.
5. Capture browser/demo evidence and test the blocked branches before any
   cloud deployment work.

If the upstream frontend build becomes a material blocker, use a smaller
local HTML/JavaScript surface that consumes the same adapter. That fallback
must preserve the contracts and event evidence; it must not bypass the
harness.

The current Milestone 1 implementation uses that fallback: `web/poc_chat.html` and
the dependency-free `secure_agent_harness.poc_server` expose the same bounded
ChatGPT-style conversation, tool activity, evidence cards, and approval flow
without copying the upstream cloud deployment. The
WAF Analyst shell remains the selected expansion path if a later milestone
needs its React/AG-UI packaging.

## AWS resources and cost drivers

Milestone 1 uses no AWS resources and has no AWS spend. A later read-only
Milestone 2 would need only the explicitly selected AWS evidence adapters and
their IAM permissions; the exact resource list and account are intentionally
not chosen here.

If the WAF shell is deployed unchanged, likely cost and operational drivers
include Bedrock model inference, AgentCore Runtime and optional Memory,
Cognito, CloudFront/S3, DynamoDB, knowledge-base/vector storage, API Gateway
or Lambda, and CloudWatch/Athena usage. These are estimates of categories,
not evidence that this repository has deployed any of them. No estimate is
approved until a region, retention, traffic, and deployment plan exist.

Milestone 3 (one real approved SSM patch) is out of scope for this change. It
requires successful read-only evidence, an exact target allow-list, an
explicit approval record, a rollback/cleanup plan, and a separate go/no-go
review.

## Attribution and public-safety obligations

The inspected upstream samples identify themselves as MIT-0/MIT No Attribution
projects. Any copied or materially adapted file must retain its applicable
license and copyright notice, and this repository should identify the source
and adapted paths. Do not copy upstream deployment state, account data, logs,
screenshots, credentials, or environment-specific identifiers.

All POC fixtures remain synthetic and use aliases such as `SYNTHETIC_LAB` and
`EC2_RESOURCE_01`. Raw payloads stay inside the tool boundary. Browser output
and durable evidence contain projections and reason codes, not attacker-
controlled model text or sensitive fields.

## Gates before widening scope

- **Go:** the local proof suite (browser flow plus harness regressions) proves
  normal, malformed-output, policy-deny, Reject, and mock-Approve paths with
  typed evidence.
- **No-go:** a zero-check or empty finding is treated as proof of safety, a
  malformed proposal reaches policy, or any denied plan executes a tool.
- **No-go:** live AWS, AgentCore deployment, real credentials, or an SSM
  mutation is introduced before the user approves the exact next milestone.
- **No-go:** the demo needs real account IDs, hostnames, IPs, ARNs, logs, or
  employer/client material to look convincing.

## Acceptance for this study

- The WAF Analyst shell is the selected base.
- Reuse, removal, and additions are explicit.
- Sentinel and MSP are constrained to named reference patterns.
- The fastest browser path is local and synthetic.
- Cost categories and attribution obligations are recorded.
- No AWS call, deployment, mutation, or live sample execution was performed.

## Milestone 1 proof recorded

- `CVE-2099-0001` in `SYNTHETIC_LAB` reaches four read-only mock checks and a
  typed approval proposal.
- Reject records `HUMAN_REJECTED` and performs no mock remediation.
- Approve records `MOCK_REMEDIATION_NOOP` and explicitly reports
  `mutation_performed: false`.
- An unknown synthetic CVE stops with `CVE_NOT_FOUND` and
  `executed_calls: []`.
