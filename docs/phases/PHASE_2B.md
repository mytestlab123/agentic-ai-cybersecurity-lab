# SecCop Phase 2B - allow-listed SSM remediation

## Objective

Complete the “wow” journey for one finding: show the proposed fix, wait for
the human approval, apply one package change to the exact live target, and
return with an honest follow-up result. This is the first phase allowed to
mutate AWS, and the approval button is the only mutation boundary.

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
2. Click **Approve and run fix**. The screen starts one package update with no
   reboot request.
3. Observe the progress and the follow-up result: fixed, waiting for the
   security scan to refresh, or not completed.
4. Capture a screenshot of the completed fix and follow-up result.
5. Stop if the package source, SSM readiness, target binding, or command
   status is not proven; do not widen scope to every finding.

## Acceptance

- Only the explicitly approved package action can run.
- No arbitrary command, public network path, or unapproved reboot is used.
- The result is not called fixed unless the follow-up security check confirms
  that the finding is gone.

## Evidence

Save captures as:

```text
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2B-01.png
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2B-02.png
```
