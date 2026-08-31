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
shared SSM profile. The disposable SecCop DEMO is active for human review: one
tagged `t3.small` EC2 target is running and SSM Online, its dedicated security
group has no ingress, two protected/versioned S3 baseline buckets are present,
and the tagged ECR repository contains the three small DEMO image tags. All
disposable resources have TTL `01-09-26`. The default VPC,
`redemption-eks-vpc`, and shared SSM IAM remain retained.

The canonical future startup is now one command: `./scripts/demo-ready.sh`.
Invoking it is the bounded startup authorization; it internally applies the
pinned Amazon Linux 2 target, waits for Patch Manager, refreshes S3/ECR,
verifies three non-compliant findings, and ensures the AWS GUI is running in
tmux. It performs no remediation or cleanup. If the disposable EC2 target is
already compliant, the startup contract permits replacing only that tagged
instance from the pinned old AMI. The lower-level guarded wrappers remain
available, and `./scripts/cleanup-demo.sh --confirm` removes only the disposable
SecCop resources after the DEMO. A live start -> scan -> cleanup
rehearsal passed. Evidence is under
`~/.AGENTS-temp/agentic-ai-cybersecurity-lab/`; the public resource record is
`docs/PROJECT1_RESOURCE_RECORD.yaml`.

GovTech PlatformAI non-inference gates pass through `gtx check` and
`gtx models`. No capability key is stored in this repository and no inference
is required for the read-only comparison.

Issue 36 now has a local code-owned checkpoint: the exact proposal keeps its
binding data server-side, the browser can submit only a proposal decision, and
independent verification cannot report `VERIFIED` from SSM success alone. The
Playwright Core proof covers proposal review, approval-required, bypass denied,
and Inspector-rescan-pending states without AWS mutation.

Current live gate: read-only inspection confirms the disposable server is SSM
Online, but it is publicly addressed and Inspector EC2 coverage is not enabled
for this account. Patch Manager non-compliance counts are not accepted as a
real CVE finding. A real package remediation is therefore blocked.

The existing ECR scan remains the KISS fallback: AWS ECR stores the retained
image, while local Trivy produces the dependency finding. The scan output names
both providers explicitly and performs no AWS mutation.

Next gate: move or replace the disposable target with an approved private SSM
path and enable Inspector coverage, then obtain one exact proposal-specific
approval. Do not infer a CVE from Patch Manager counts. Cleanup remains a
separate operator action after Amit finishes the DEMO.
