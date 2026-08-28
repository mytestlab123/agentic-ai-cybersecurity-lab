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
shared SSM profile. The disposable SecCop rehearsal is currently clean: no
running SecCop EC2 target, no tagged SecCop EBS volume, no dedicated SecCop
security group, no SecCop S3 demo bucket, and no SecCop ECR demo repository.
The default VPC, `redemption-eks-vpc`, and shared SSM IAM remain retained.

The repo now owns repeatable wrappers: `./scripts/start-demo.sh --confirm`
applies a pinned older Amazon Linux 2 target, waits for a scan-only Patch
Manager summary, and seeds S3/ECR; `./scripts/cleanup-demo.sh --confirm`
uses Terraform destroy plans and tag checks to remove only the disposable
SecCop resources. A live start -> scan -> cleanup rehearsal passed. Evidence is
under `~/.AGENTS-temp/agentic-ai-cybersecurity-lab/`; the public resource
record is `docs/PROJECT1_RESOURCE_RECORD.yaml`.

GovTech PlatformAI non-inference gates pass through `gtx check` and
`gtx models`. No capability key is stored in this repository and no inference
is required for the read-only comparison.

Validation: 32 tests, Python compilation, Terraform validate/plan, private
network preflight, live target preflight, real Inspector export, and browser
`/api/live-csv` comparison pass locally.

Next gate: run `start-demo.sh --confirm` only when a live DEMO is needed, then
use the GUI scan/review path. Any EC2 package remediation remains a separate
human approval-gated milestone; run `cleanup-demo.sh --confirm` after the DEMO.
