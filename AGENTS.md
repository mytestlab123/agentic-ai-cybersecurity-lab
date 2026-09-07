# AGENTS.md

This is a public personal-learning repository.

## Scope

- Use synthetic local data first.
- Keep one learning objective per change.
- Prefer small typed Python components and deterministic tests.
- Record useful lessons in `docs/LEARNING_LOG.md`.

## KISS POC boundary

- Follow KISS: **Keep It Short and Stupid**. This is a short, demonstrable
  POC, not an enterprise platform.
- Prefer one clear operator journey, small fixtures, and the existing approval
  path over new services, abstractions, or infrastructure.
- Make only the EC2 path real when the issue explicitly requires mutation;
  keep other sources read-only until a separate bounded issue proves the need.
- The approved three-source DEMO may use small, tagged S3/ECR baseline artifacts
  with deterministic scanners. GuardDuty, real malware, AgentCore, and new
  networking are not DEMO requirements.
- Defer AgentCore, multi-agent orchestration, broad IAM, networking, and
  integrations unless a small POC cannot work without them.

## Public safety

- Never add real credentials, tokens, `.env` content, account IDs, ARNs,
  resource IDs, hostnames, IP addresses, DNS names, logs, screenshots, state,
  vulnerabilities, or employer/client material.
- Use aliases such as `ACCOUNT_A`, `EC2_RESOURCE_01`, and `ROLE_READONLY_01`.
- Review every diff for public safety before commit and push.
- Stop when publication safety is uncertain.

## AWS and cost boundary

- Local fixtures and mocks are the default.
- Current SecCop AWS work is explicitly pinned to the `amit` profile in
  `ap-southeast-1`. Set `AWS_PROFILE=amit`, `AWS_DEFAULT_PROFILE=amit`,
  `AWS_REGION=ap-southeast-1`, and `AWS_DEFAULT_REGION=ap-southeast-1` for
  every live SecCop command.
- There is no implicit `vagent`/Project1 or other-profile fallback for SecCop.
  If the explicit `amit` STS check fails, stop and request credential renewal;
  do not switch profiles or run `aws sso login`.
- Amit explicitly approved the existing public VPC/subnet path for personal
  AI/agentic POCs. A public IPv4 address is allowed for a disposable target
  when its dedicated security group has no ingress and operation uses SSM
  instead of SSH. Do not create new networking merely to make the target
  private.
- This public-network exception does not apply to PROD, TRUST, GCC, GovTech,
  restricted, employer/client, or otherwise private-only environments.
- Never run `aws sso login`.
- Do not create or mutate AWS resources without explicit approval for the exact
  experiment and a same-day cleanup plan.

### Issue #55 approved mutation envelope

Amit approved this exact, later mutation envelope on 2026-09-02, using only
`AWS_PROFILE=amit`/`AWS_DEFAULT_PROFILE=amit` in `ap-southeast-1`:

- one AWS Config recorder and one delivery channel;
- the standalone AWS-managed rules `s3-bucket-level-public-access-prohibited`
  and `ec2-imdsv2-check`, selected from the AWS Operational Best Practices
  baselines. Each is an AWS Config AWS-managed rule selected from the AWS
  Operational Best Practices baseline; no full Conformance Pack is deployed
  for this KISS MVP;
- manual remediation only;
- `AWSConfigRemediation-ConfigureS3BucketPublicAccessBlock` and
  `AWSConfigRemediation-EnforceEC2InstanceIMDSv2`;
- one least-privilege Automation execution role;
- one retained S3 drift alias; and
- one disposable SSM-managed EC2 target only when separately prepared with
  required tags and TTL.

Reject generic IAM, automatic remediation, arbitrary SSM, new networking,
unrelated resources, and ECR changes. This is an approved scope envelope, not
evidence that any AWS resource has changed; each mutation phase must remain
manual, exact-target, and separately validated.

### Issue #55 retained DEV IMDSv2 exception

For the approved retained DEV rehearsal only, use `ihis_dev` in
`ap-southeast-1` and the exact target alias `DEV_EC2_RESOURCE_01`. Reuse the
existing `AMI_FACTORY_DEV_DEMO_ROLE` unchanged as the AWS Config Automation
role; do not alter its trust, policies, attachments, instance profile, or
tags. The path is limited to the direct `ec2-imdsv2-check` rule, manual
`AWSConfigRemediation-EnforceEC2InstanceIMDSv2` version 4, and one exact
human-confirmed execution. Retain the target, Config rule, remediation, and
existing role with `cleanup=keep`; TTL is review-only and cleanup needs new
explicit Amit approval. The prior partial Issue #55 role remains untouched,
and package/CVE, S3, ECR, networking, and automatic-remediation paths remain
excluded.

### SecCop manual-remediation UI contract

Use one five-stage journey for configured sources: **Scan**, **Review one
exact proposal**, **human Remediate/Reject** (ECR may say **Approve Once**),
**Verify provider truth**, then optional reopen only after a verified outcome.
The UI cannot authorize an unbound target, proposal, or AWS action.

For fixed `DEV_EC2_LAB_01`, the EC2 GUI path is
`NON_COMPLIANT -> Review -> Remediate/Reject -> StartRemediationExecution ->
COMPLIANT`. Reject is non-mutating. Remediate must use the existing manual
`AWSConfigRemediation-EnforceEC2InstanceIMDSv2` binding and verify terminal
Automation success, `HttpTokens=required`, and fresh Config `COMPLIANT`. The
fixed LAB_01 GUI always shows **Scan EC2 compliance** and **Reopen Finding**.
Reopen's confirmation intentionally permits IMDSv1 and waits for Config
`NON_COMPLIANT`; when already open it returns `FINDING_ALREADY_OPEN` without
mutation or a Config wait. CLI Reopen remains the operator fallback.

## Validation

- Run focused tests, Python compilation, and `git diff --check`.
- Browser/Playwright checks are optional and run only after an explicit Amit
  request; retain the existing helpers for that future request and never treat
  them as an automatic or mandatory final-review gate.
- Preserve unsafe requests as regression tests.
- A model proposal is never authorization.
