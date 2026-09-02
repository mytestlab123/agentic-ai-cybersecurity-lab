# Context

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

Current truth: Project1 reuses the existing Singapore default public VPC and
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
