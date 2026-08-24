# Context

Current objective: Issue 5 live-lab preparation after the local visual POC and
fake-tested read-only adapter.

The local harness remains deterministic, default-deny, and no-op on approval.
The read-only adapter now optionally projects constrained Inspector package
fields and SSM `AWS:PatchSummary` counts. The browser accepts only a typed,
sanitized evidence result through `/api/live-evidence`.

`scripts/issue5_live_lab.py` owns the live workflow: exact-target `plan`,
explicit `apply --confirm`, read-only `collect`, and tag-checked
`cleanup --confirm`. It refuses public IPs and requires an existing private
SSM path, no-ingress security group, IAM instance profile, available AMI, and
enabled Inspector EC2 coverage.

Current truth: the tested account has an available self-owned legacy Linux AMI
and enabled Inspector EC2 coverage, but no complete launch plan. The cached
instance profile is absent and the discovered subnets do not provide a private
SSM path. No instance or AWS mutation was performed.

Validation: 24 tests, Python compilation, live-operator preflight, and
`git diff --check` pass locally; the preflight correctly returns
`LAUNCH BLOCKED`.

Next gate: provide an exact existing private SSM-capable subnet and instance
profile (or explicitly approve a separately reviewed infrastructure change).
