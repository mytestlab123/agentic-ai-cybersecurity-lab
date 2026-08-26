# SecCop Phase 2B - allow-listed SSM remediation

## Objective

Execute one approved package remediation on the exact live target through a
repo-owned SSM adapter. This is the first phase allowed to mutate AWS, and it
requires a separate exact-target approval.

## Required gates

- The Phase 2A proposal is `READY` and approved for the exact CVE/package.
- The EC2 target, region, project/environment tags, and SSM managed node are
  revalidated immediately before execution.
- The package repository path is reachable from the private instance. SSM
  endpoints alone do not prove that an OS package can be downloaded.
- The SSM document and package scope are allow-listed; model text cannot form
  an arbitrary shell command.
- Default reboot behavior is `NoReboot`; a reboot is a separate explicit
  approval and maintenance-window decision.

## Demo steps

1. Open the Phase 2A approved proposal and confirm the target alias, package,
   fixed version, and `EXPLICIT_APPROVAL_REQUIRED` reboot policy.
2. Click **Run approved SSM remediation** and confirm the confirmation dialog
   repeats the exact target, package, document, and reboot choice.
3. Observe the SSM execution card; it must show a stable command status and
   sanitized stdout/stderr summary, never a raw payload.
4. Capture a screenshot of the running/completed SSM evidence and the
   `mutation_performed` result.
5. Stop if the package source, SSM readiness, target binding, or command
   status is not proven; do not widen scope to every Inspector finding.

## Acceptance

- Only the explicitly approved package action can run.
- No arbitrary command, public network path, or unapproved reboot is used.
- The result is not called fixed until Phase 2C performs independent closure.

## Evidence

Save captures as:

```text
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2B-01.png
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2B-02.png
```
