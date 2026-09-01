# Specification

## Original Issue 1 baseline

Build a minimal secure Python agent harness with typed contracts and three
deterministic read-only tools backed by synthetic fixtures.

## Required behavior

- The model may only propose tool calls.
- The deterministic policy validates the complete plan before execution.
- Unknown, malformed, or mutation-capable calls block the whole plan.
- Tool results are typed and evidence is returned to the caller.
- Tests cover a normal request and an unsafe mutation request.

## Issue 2 local slice

- A synthetic AWS-shaped instance response is read through an allow-listed
  local tool.
- Deterministic sanitization exposes only an alias, synthetic environment,
  normalized state, and coarse size class.
- Raw instance, network, DNS, tag, and profile values never reach the typed
  result returned to the model boundary.

## Original Issue 1 stop gates

- No real LLM or paid API.
- No AWS SDK call or resource.
- No mutation tool.
- No real identifiers or private data.
- Human review is required before widening beyond Issue 1.

## Current SecCop DEV authority

SecCop is now a working real-AWS MVP. Repo-owned disposable SecCop DEV
rehearsals and retries are pre-approved on profile `amit` in
`ap-southeast-1`; use Project1 only when the required AWS service is eligible.

No repeated approval is required for one-at-a-time, repo-owned runs using:

- one `t3.small`-or-smaller EC2 instance with an encrypted root volume;
- one zero-ingress security group, the approved public subnet/public IPv4,
  and the existing SSM instance profile;
- Inspector reads, one exact approval-bound package update without reboot,
  Playwright evidence, and deterministic same-day cleanup.

The monthly AWS learning budget is USD 10-20. Estimate and record usage, aim
near USD 10, and stop before projected monthly spend exceeds USD 20. Do not
apply an artificial per-run USD 0.04 cap. Normal TTL, tags, private evidence,
and same-day cleanup remain mandatory unless Amit explicitly asks to retain a
demo target.

Standing authority excludes PROD, GCC, client, protected, and unrelated
resources; broad IAM expansion; new VPC, NAT, ALB, RDS, EKS, or OpenSearch;
arbitrary commands; SSH; reboot; multi-account mutation; ECR/S3 mutation; and
unowned cleanup.
