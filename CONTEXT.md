# Context

Current SecCop AWS execution profile: use only `AWS_PROFILE=amit` and
`AWS_DEFAULT_PROFILE=amit` in `ap-southeast-1` (also set the matching region
variables). There is no `vagent`/Project1/default-profile fallback; stop if the
explicit `amit` STS check fails.

Issue #55 approved mutation envelope (Amit approval: 2026-09-02; pre-mutation
state): a later phase may use only `amit`/`ap-southeast-1` for one Config
recorder and delivery channel; the standalone AWS-managed S3 public-access and
EC2 IMDSv2 rules selected from the AWS Operational Best Practices baselines;
manual remediation; the two named AWS-managed Automation documents; one
least-privilege execution role; one retained S3 drift alias; and one separately
prepared, tagged/TTL'd disposable SSM-managed EC2 target. No full S3 or EC2
Operational Best Practices Conformance Pack is deployed for this KISS MVP. Each
control is an AWS Config AWS-managed rule selected from the AWS Operational
Best Practices baseline.
Generic IAM, auto remediation, arbitrary SSM, new networking, unrelated
resources, and ECR changes remain outside scope.

Pre-mutation truth remains unchanged: Config recorder/rules/packs are absent,
the two Automation documents are active (default versions 8 and 4), three
retained private S3 aliases exist with one missing bucket-level BPA, and no
project-owned reusable EC2 target was found. No AWS resource has changed from
this approval or documentation phase.

Current objective: persistent Security Copilot (SecCop) live demo after the
local visual POC and fake-tested read-only adapter.

The local harness remains deterministic, default-deny, and no-op on approval.
The read-only adapter projects constrained Inspector package fields and SSM
patch state. The browser now accepts a strict Inspector CSV plus an exact EC2
instance ID and selected CVE through `/api/live-csv`; raw AWS payloads remain
outside the browser/model boundary.

`scripts/issue5_live_lab.py` owns the live workflow: exact-target `plan`,
explicit `apply --confirm`, read-only `collect`, and tag-checked
`cleanup --confirm`. It refuses public IPs and requires an existing private
SSM path, no-ingress security group, IAM instance profile, available AMI, and
enabled Inspector EC2 coverage.

Historical Project1 facts (preserved for record, not current SecCop authority):
Project1 reuses the existing Singapore default public VPC and
shared SSM profile. The SecCop rehearsal has no running EC2 target, tagged EBS
volume, dedicated security group, or new network. The three private empty S3
demo buckets and the private `seccop-ecr-operator-mvp` repository are retained
for the approved scanner demos. The default VPC, `redemption-eks-vpc`, and
shared SSM IAM remain retained.

The repo now owns repeatable wrappers: `./scripts/start-demo.sh --confirm`
applies a pinned older Amazon Linux 2 target, waits for a scan-only Patch
Manager summary, and seeds S3/ECR; `./scripts/cleanup-demo.sh --confirm`
uses Terraform destroy plans and tag checks to remove only the disposable
SecCop resources. A live start -> scan -> cleanup rehearsal passed. Evidence is
under `~/.AGENTS-temp/agentic-ai-cybersecurity-lab/`; the public resource
record is `docs/PROJECT1_RESOURCE_RECORD.yaml`.

## Scanner-backed ECR fixture truth (Issue #53)

Future vulnerability/compliance demos must use scanner-supported fixtures, not
labels or local-only output. The retained ECR proof uses public-safe aliases:

- `ECR_IMAGE_VULNERABLE_DIGEST` is the exact digest behind the
  `issue53-vulnerable` trigger tag.
- `ECR_IMAGE_CLEAN_DIGEST` is the paired newer clean fixture behind the
  existing `demo-clean` tag (and its `issue53-clean` trigger tag).
- Both aliases are queried by exact digest/hash in the retained
  `seccop-ecr-operator-mvp` repository. The AWS-native provider is Amazon
  Inspector ECR Enhanced Scanning with a repository-scoped `SCAN_ON_PUSH`
  rule; scanner coverage/readiness must be present before a result is shown as
  `NON_COMPLIANT`, `COMPLIANT`, or `VERIFIED`.
- The currently observed Inspector finding is `CVE-2019-11324` in the old
  vulnerable fixture. It is evidence-backed only by the paired Phase 1 result;
  the clean digest must show exact absence of that CVE in the Phase 2 result.
- Local Trivy is secondary guidance for fixture selection, never Inspector
  proof. An unsupported or ambiguous fixture, missing coverage, or missing
  exact finding is a blocker; do not infer state from a tag name.
- Keep the vulnerable and clean artifacts retained for reuse. Do not clean them
  up in the normal demo loop without a new explicit approval.

Durable proof records: `issue53-phase1-ecr-native-finding/RESULT.md` and
`issue53-phase2-ecr-clean-proof/RESULT.md`. Private AWS IDs, hashes, ARNs,
URIs, raw findings, and private evidence paths stay outside this repository.

GovTech PlatformAI non-inference gates pass through `gtx check` and
`gtx models`. No capability key is stored in this repository and no inference
is required for the read-only comparison.

Validation: 32 tests, Python compilation, Terraform validate/plan, private
network preflight, live target preflight, real Inspector export, and browser
`/api/live-csv` comparison pass locally.

Next gate: run `start-demo.sh --confirm` only when a live DEMO is needed, then
use the GUI scan/review path. Any EC2 package remediation remains a separate
human approval-gated milestone; run `cleanup-demo.sh --confirm` after the DEMO.

## Current Issue #55 DEV EC2 partial arm (2026-09-03)

The superseding DEV run used only `ihis_dev`/`ap-southeast-1` and the
explicitly approved Nessus target alias `DEV_EC2_RESOURCE_01`. The target
remains running as a `t3.medium`, private (no public IPv4), SSM Online,
zero-ingress, and `HttpTokens=optional`. No EC2 metadata or network mutation
was performed. Its existing scanner ownership and unencrypted gp2 root are
unchanged and must not be repurposed outside Amit's exact approval.

The run created and retained the tagged role alias
`AUTOMATION_ROLE_ISSUE55_DEV_01`, but the profile was denied the exact
`iam:PutRolePolicy` call, so the narrow policy is not attached. No
`ec2-imdsv2-check` rule or remediation binding was created; no Config proof
ran. The role is retained for reconciliation, with `cleanup=keep` and
`TTL=01-10-26`; TTL is review-only and cleanup requires new explicit Amit
approval naming the resource class and scope. The old package/CVE path remains
excluded.

## Current Issue #55 DEV EC2 retained IMDSv2 proof (2026-09-03)

The approved follow-up used only `ihis_dev`/`ap-southeast-1` and the exact
target alias `DEV_EC2_RESOURCE_01`. The existing `AMI_FACTORY_DEV_DEMO_ROLE`
was reused unchanged: caller PassRole for SSM was allowed, SSM trust was
present, and before/after trust, inline-policy names, managed-policy
attachments, and tags matched. The earlier partial role remains retained and
untouched.

The direct AWS-managed `ec2-imdsv2-check` rule is active and target-scoped,
with manual `AWSConfigRemediation-EnforceEC2InstanceIMDSv2` version 4. The
repo-owned API proof recorded proposal-less and wrong/cross-source blocks,
Reject with no mutation, one approved remediation with terminal Automation
Success, `HttpTokens=required`, replay protection, and fresh Config
`COMPLIANT`. The existing all-supported Config recorder stayed active; no
delivery or unrelated resource changed.

The existing DEV EC2 target, its existing zero-ingress security group and SSM
registration, the direct rule, remediation binding, reused role, and prior
partial role are retained. No new compute was created; cost is the existing
target's ongoing usage plus negligible Config/IAM overhead. Retention is
`cleanup=keep` with `TTL=01-10-26` as review-only; deletion or termination
requires new explicit Amit approval. Package/CVE, S3, ECR, networking, and
automatic-remediation work remain excluded.
