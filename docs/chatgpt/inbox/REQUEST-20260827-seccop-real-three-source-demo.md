# ChatGPT review request: SecCop repeatable three-source DEMO

Date: 2026-08-27

Repository: https://github.com/mytestlab123/agentic-ai-cybersecurity-lab

## Goal

Build one small, repeatable DEMO that starts three known non-compliant AWS
resources, scans them, proposes a plain-language fix, waits for human approval,
applies the exact fix, and rescans to show a clean result.

The operator journey must be:

```text
Start DEMO -> Scan -> Review -> Approve -> Fix -> Rescan -> Compliant
```

## Resource baseline

Use only resources tagged for SecCop and the existing Project1 shared VPC/SSM
profile. Do not create new networking, GuardDuty configuration, AgentCore, or
real malware.

1. **EC2 package** - reuse one pinned old-package AMI or the existing tagged
   old-package target. SSM Patch Manager/read-back is the authoritative fast
   check; Inspector is optional asynchronous evidence.
2. **S3 artifact** - one small versioned current bucket and one reset bucket in
   the same region. The bad object contains a harmless old dependency with a
   known CVE. Scan with Trivy/OSV-style deterministic evidence. Fix by copying
   the approved clean object after approval.
3. **ECR image** - one small repository with a known-bad image and a clean image
   digest. Scan with a deterministic image scanner. Fix by promoting the clean
   digest; never mutate an image digest in place.

## Required behavior

- `start-demo` is idempotent and restores the known-bad baseline.
- It verifies the profile, region, permissions, exact tags, SSM readiness, and
  scanner availability before mutation.
- Browser evidence uses aliases only: `LAB_SERVER_01`, `ARTIFACT_01`, and
  `IMAGE_01`.
- Each fix has a typed proposal, exact target binding, stable reason code, and
  explicit human approval.
- Rescan must show `NON_COMPLIANT` before approval and `COMPLIANT` after the
  approved fix.
- A failed or unavailable source is visible and does not cause an unsafe call.
- `stop-demo` may terminate only the exact disposable EC2 target and remove its
  unused security group. The VPC, shared SSM profile, S3 reset bucket, and ECR
  repository are retained unless a separate cleanup approval is given.

## GuardDuty decision

GuardDuty Malware Protection for S3 is explicitly out of scope. The free AWS
account may not have it enabled, and it is not needed to demonstrate a
non-compliant artifact and an approved clean replacement.

## Review request

Recommend one bounded issue and PR. Keep the implementation small, explain the
scanner choice and cost/latency risks, define contracts/reason codes, and give
one automated state-machine test plus one controlled live rehearsal. Do not
add a general agent framework or broad IAM.
