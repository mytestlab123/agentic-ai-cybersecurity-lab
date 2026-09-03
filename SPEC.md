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
`ap-southeast-1`, which is the sole current SecCop AWS authority. There is no
Project1 or `vagent` fallback; if `amit` is unavailable, stop.

## Issue #55 approved mutation envelope

Amit approved this bounded envelope on 2026-09-02 for a later, separate
mutation phase using only `amit`/`ap-southeast-1`. The exact allowlist is:

- one AWS Config recorder and one delivery channel;
- the two named controls `s3-bucket-level-public-access-prohibited` and
  `ec2-imdsv2-check`, or a published pack containing only those controls;
- manual remediation only (no automatic remediation);
- the AWS-managed Automation documents
  `AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock` and
  `AWSConfigRemediation-EnforceEC2InstanceIMDSv2`;
- one least-privilege Automation execution role scoped to this envelope;
- one retained S3 drift alias; and
- one disposable SSM-managed EC2 target only if separately prepared with the
  required tags and TTL.

This does not authorize generic IAM, arbitrary SSM, new networking, unrelated
resources, or any ECR behavior change. This approval records scope only; no
AWS resource has changed in the documentation phase.

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

## Issue #55 retained DEV IMDSv2 slice

The approved DEV exception uses only `ihis_dev` in `ap-southeast-1` and the
exact target alias `DEV_EC2_RESOURCE_01`. It reuses the existing
`AMI_FACTORY_DEV_DEMO_ROLE` unchanged as `AutomationAssumeRole` and proves
caller PassRole, SSM trust, and unchanged role trust/policy/attachment shape.
The one direct `ec2-imdsv2-check` rule is scoped to that target and binds only
manual AWS-managed `AWSConfigRemediation-EnforceEC2InstanceIMDSv2` version 4.
The happy path is NON_COMPLIANT -> Reject/no mutation -> one approved
StartRemediationExecution -> terminal Automation Success -> HttpTokens=required
and fresh Config COMPLIANT. The target and Config resources remain retained;
`cleanup=keep` is a retention marker, TTL is review-only, and deletion or
termination requires a new explicit Amit approval. The prior partial role is
not modified, and package/CVE, S3, ECR, networking, and automatic-remediation
work remain outside this slice.

## Manual remediation UI contract

The SecCop management UI uses one five-stage workflow for every configured
source: **Scan**, **Review one exact proposal**, **human Remediate or Reject**
(ECR may use the label **Approve Once**), **Verify provider truth**, then an
optional reopen only after a verified outcome. The browser never authorizes a
target, action, or provider result.

For fixed `DEV_EC2_LAB_01`, the sole EC2 journey is
`NON_COMPLIANT -> Review -> Remediate/Reject -> StartRemediationExecution ->
COMPLIANT`. Review shows the exact AWS Config IMDSv2 proposal. Reject changes
nothing; Remediate consumes that one proposal and invokes only the existing
manual `AWSConfigRemediation-EnforceEC2InstanceIMDSv2` binding before checking
terminal Automation success, `HttpTokens=required`, and fresh Config
`COMPLIANT`. Only after a fresh clean EC2 scan may the GUI reveal an optional
fixed-LAB_01 **Reopen Finding** R&D loop. It explicitly confirms IMDSv1 and
fresh Config `NON_COMPLIANT`, remains hidden while a finding is open, and is
idempotent with `FINDING_ALREADY_OPEN` and no mutation/wait when already open.
The CLI reopen command remains the operator fallback.
