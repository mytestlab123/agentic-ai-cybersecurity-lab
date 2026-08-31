# Portfolio presentation handoff: Security Copilot

## Purpose and ownership boundary

This handoff supplies the Security Copilot evidence for one combined management
deck covering Security Copilot, Compliance Copilot, and the AI API Platform.
It does not prove capabilities owned by the other two projects. Their owners
must provide equivalent current evidence before the combined deck labels their
claims as proven.

The intended audience is a nontechnical manager, director, security leader, or
operations leader. The portfolio story is governed AI assistance: AI helps
people understand and progress work, while deterministic controls and human
accountability govern sensitive actions.

## Current repository truth

- Baseline branch: `main`; Issue 36 checkpoint branch:
  `codex/issue36-real-aws-golden-path`
- Current commit: `cd45402e1aa46327a4c175f1e273f57d3de6352c`
- Commit subject: `Merge: refresh SecCop lifecycle context`
- Latest closed issue: [Issue 34 - Refresh SecCop lifecycle context](https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/issues/34)
- Latest merged PR: [PR 35 - Refresh SecCop lifecycle context](https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/pull/35)
- PR 35 was documentation-only. It recorded the verified clean lifecycle state,
  repeatable DEMO start and cleanup commands, and the separate approval gate
  for EC2 package remediation. It performed no AWS mutation.
- The latest capability merges before that were PR 33 for repeatable DEMO
  start/cleanup and PR 30 for the one-CVE composer.

Current state: the local SecCop interface and deterministic browser proof are
available. One disposable AWS DEMO is active and pending separate cleanup
after human review. Issue 36 locally proves server-side proposal binding,
approval-bypass denial, and a verification result that remains pending while
Inspector still reports a finding. The live remediation remains blocked. The
repository contains no capability key and the current deterministic journey
does not use GovTech inference or another LLM.

## Management problem

Security and operations teams receive vulnerability findings from scanners,
advisories, tickets, and messages. The difficult work begins after detection:
confirm whether the environment is affected, understand the relevant asset,
agree on a safe response, obtain approval, and verify the outcome. These
hand-offs can make response slow and inconsistent.

## Proposed solution

Security Copilot demonstrates a governed agentic workflow that brings the
decision into one guided conversation:

```text
Find -> Explain -> Recommend -> Approve or Stop -> Act -> Verify
```

The agentic component can help gather and explain evidence. Typed inputs,
deterministic policy, exact target binding, human approval, narrow tools, and
post-action verification control sensitive work. A model proposal is never
authorization.

## One operator journey

1. The operator copies one CVE from an advisory, email, or ticket into SecCop.
2. SecCop checks the synthetic server package, stored artifact, and container
   image sources and explains where the CVE appears.
3. The operator opens the exact server finding and reviews the proposed next
   step. No change has happened at this point.
4. The operator approves or rejects the proposal. The visible synthetic DEMO
   records a no-op decision; it does not claim a real package update.
5. Invalid or unknown input stops with a stable reason code before any tool
   runs.
6. A future bounded live milestone can connect the same approval experience to
   one exact EC2 package update and a verified clean re-scan.

Management takeaway: the agent accelerates investigation and explanation;
policy and the operator retain control of action.

## Honest evidence claims

### DEMO-PROVEN

- The current browser application accepts one synthetic CVE and shows results
  across the server, stored-artifact, and container-image demo sources.
- One **Scan environment** action presents three alias-only finding cards.
- The visible server journey stops for human approval and records a no-op
  approval or rejection without claiming an AWS package change.
- The visible unknown-CVE journey returns `CVE_NOT_FOUND` and shows that no
  tools executed.

### TEST-PROVEN

- Typed contracts and deterministic tests reject malformed, unknown, or
  ambiguous requests before AWS calls.
- Tests prove that the synthetic approval result has
  `mutation_performed=false`.
- The repeatable browser runner checks API and DOM states, reports zero
  external browser requests and zero console errors, captures evidence, and
  cleans up its owned local processes.
- SSM success alone cannot produce `VERIFIED`; Inspector must independently
  show the finding resolved.

### READ-ONLY PROVEN

- A bounded rehearsal collected exact-target Inspector, EC2, and SSM evidence
  and exposed sanitized aliases and summaries rather than raw cloud
  identifiers to the browser.
- The repository records a successful start, scan, and cleanup rehearsal for
  the disposable DEMO lifecycle. Exact private evidence remains outside Git.
- Current read-only inspection confirms one active alias-only DEMO server is
  SSM Online. Its public network path and unavailable Inspector coverage block
  real remediation under Issue 36.

### PLANNED

- Connect one exact, human-approved EC2 package change to the visible journey,
  then verify the new package state and clean re-scan.
- Evaluate a scheduled scan only after the interactive fix-and-verify journey
  is reliable.
- Define a common portfolio approval and evidence pattern across Security
  Copilot, Compliance Copilot, and the AI API Platform after each owning
  project supplies its own proof.

### NOT PROVEN

- Production readiness, enterprise scale, broad vulnerability coverage,
  autonomous remediation, or a production IAM and operating model.
- A visible end-to-end EC2 package mutation followed by a clean re-scan.
- That GovTech AI, Bedrock, AgentCore, or another LLM performed the current
  deterministic SecCop journey.
- Any Compliance Copilot or AI API Platform capability. This repository cannot
  provide their proof.

## Public-safe screenshot candidates

Use no more than two images on one portfolio slide. These existing captures
were visually reviewed and contain synthetic CVEs and aliases only.

1. [Three-source scan](../demo-proof/SecCop-Scan-02.png)
   - Repository path: `docs/demo-proof/SecCop-Scan-02.png`
   - Caption: **One security question checks a server package, stored artifact,
     and container image in one guided view.**
   - Claim supported: `DEMO-PROVEN` multi-source scan and plain-language next
     steps.

2. [Human approval boundary](../demo-proof/SecCop-Scan-03.png)
   - Repository path: `docs/demo-proof/SecCop-Scan-03.png`
   - Caption: **The operator reviews the exact finding before any sensitive
     action is allowed.**
   - Claim supported: `DEMO-PROVEN` review and approval gate. This image does
     not prove a real package mutation.

3. [Safe blocked result](../demo-proof/SecCop-Scan-05-blocked.png)
   - Repository path: `docs/demo-proof/SecCop-Scan-05-blocked.png`
   - Caption: **Unknown input stops with a stable reason and no tool
     execution.**
   - Claim supported: `DEMO-PROVEN` visible blocked path and `TEST-PROVEN`
     fail-closed behavior.

## Management value

- Reduce repetitive first-pass investigation and coordination.
- Give operators one clear explanation and one bounded next step.
- Improve consistency by applying the same approval and policy checks.
- Keep human accountability visible for sensitive actions.
- Make verification and evidence part of the workflow rather than an
  afterthought.
- Create a reusable governed pattern that other portfolio products may adopt
  after separate validation.

These are expected management benefits, not measured savings or production
outcomes.

## Limitations and prohibited claims

The combined deck must not claim:

- unrestricted or fully autonomous AI access to infrastructure;
- that AI fixes all vulnerabilities or guarantees a clean environment;
- production readiness, enterprise scale, incident prevention, guaranteed
  savings, or 100 percent compliance;
- that the current visible DEMO performed a real EC2 package update;
- that a local synthetic screenshot proves an AWS mutation;
- that S3 or ECR remediation is proven through the current GUI;
- that GovTech AI, Bedrock, AgentCore, or an LLM executed the deterministic
  SecCop flow;
- that Security Copilot evidence proves Compliance Copilot or the AI API
  Platform;
- that real malware, private cloud identifiers, customer data, or employer
  information was used.

Do not place raw logs, account identifiers, ARNs, resource IDs, hostnames, IP
addresses, credentials, private evidence paths, or live vulnerability data in
the deck.

## Recommended content for three portfolio slides

### Portfolio slide 1: AI. Guarded. Useful.

**Message:** Three focused copilots can share one governed AI operating
principle: help people understand work, constrain sensitive action, and retain
evidence.

Use three short product panels:

- **Security Copilot:** investigate a vulnerability and guide a controlled
  response.
- **Compliance Copilot:** proposed portfolio role is to turn control evidence
  into clear review work; the owning project must supply proof.
- **AI API Platform:** proposed portfolio role is governed access to approved
  AI models; the owning project must supply proof.

Label the latter two as portfolio framing until their repositories provide
validated evidence. Do not place a SecCop proof label across all three panels.

### Portfolio slide 2: One governed operating pattern

**Message:** The same management control pattern can support different AI use
cases.

```text
Request or signal -> Evidence -> Explanation -> Recommendation
                  -> Policy -> Human approval -> Action -> Verification
```

Use the three-source scan screenshot as the large proof image and one small
callout: **Security Copilot proves the visible investigation and approval
boundary today.** Present the cross-portfolio reuse as `PLANNED`.

### Portfolio slide 3: Proof today, decision tomorrow

**Message:** The portfolio should expand from verified small proofs, not from
unrestricted autonomy.

- **Proven now:** SecCop one-CVE review, multi-source scan, human decision gate,
  safe blocked path, and bounded read-only AWS evidence.
- **Next:** prove one visible EC2 fix and verified clean re-scan; obtain separate
  evidence from Compliance Copilot and the AI API Platform.
- **Decision requested:** approve one small cross-portfolio evaluation of the
  common approval, evidence, and verification pattern. This is not production
  authorization.

Use either the approval screenshot or blocked screenshot, not both, if the
slide becomes crowded.

## Validation and evidence references

Repository truth:

- [`README.md`](../../README.md)
- [`CONTEXT.md`](../../CONTEXT.md)
- [`docs/demo.md`](../demo.md)
- [`docs/SECCOP_OPERATOR_DEMO.md`](../SECCOP_OPERATOR_DEMO.md)
- [`docs/PROJECT1_RESOURCE_RECORD.yaml`](../PROJECT1_RESOURCE_RECORD.yaml)

Evidence:

- [`docs/evidence/seccop-demo/report.md`](../evidence/seccop-demo/report.md)
- [`docs/evidence/seccop-demo/aws-live-rehearsal.md`](../evidence/seccop-demo/aws-live-rehearsal.md)
- [`scripts/browser-e2e.sh`](../../scripts/browser-e2e.sh)
- [`tests/test_poc.py`](../../tests/test_poc.py)
- [`tests/test_aws_read_only.py`](../../tests/test_aws_read_only.py)
- [`tests/test_harness.py`](../../tests/test_harness.py)
- [`tests/test_policy.py`](../../tests/test_policy.py)

Handoff validation requirements:

- Reconfirm the current commit and latest merged PR before producing the final
  combined deck.
- Verify every cross-project claim in its owning repository.
- Use the evidence labels exactly as defined in the management POC
  presentation protocol.
- Confirm every selected image is readable at normal presentation size.
- Recheck the final deck for private identifiers and unsupported claims.
- Keep the combined management story to no more than three portfolio slides
  from this handoff.
