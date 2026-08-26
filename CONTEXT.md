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

Current truth: a Singapore private SecCop VPC is applied through Terraform
with private Inspector, SSM, and S3 endpoints and no public exposure. One old
Amazon Linux target is running privately with the existing SSM profile. The
repo-owned exporter produced a real Inspector CSV with active package findings;
the selected exact-target CVE comparison returns `READY` with HIGH severity
and one vulnerable package. The infrastructure and instance remain held for
the human demo; cleanup has not been run.

GovTech PlatformAI non-inference gates pass through `gtx check` and
`gtx models`. No capability key is stored in this repository and no inference
is required for the read-only comparison.

Validation: 32 tests, Python compilation, Terraform validate/plan, private
network preflight, live target preflight, real Inspector export, and browser
`/api/live-csv` comparison pass locally.

Next gate: Amit reviews the SecCop GUI with the exported CSV; remediation and
SSM mutation remain a separate approval-gated milestone.
