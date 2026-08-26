# SecCop Phase 2A - deterministic proposal and approval

## Objective

Turn one successful live read-only comparison into a typed remediation
proposal and an explicit human decision. Phase 2A never calls SSM patching,
reboot, or any other AWS mutation.

## What changed

- `/api/live-proposal` re-runs the exact CSV and AWS read-only gates.
- Exactly one matching package row is required.
- The proposal exposes only the resource alias, CVE, package, installed and
  fixed versions, action, reboot policy, and read-call summary.
- `/api/live-decision` records Approve or Reject as a no-op decision.
- The UI shows `Live read-only` mode and `GovTech inference: not used`.

## Demo steps

1. Open `http://127.0.0.1:8765` and upload the selected Inspector CSV.
2. Enter the exact EC2 instance ID, selected CVE, and `Singapore`; click
   **Compare live target**.
3. Confirm the live card says `SECCOP_COMPARISON_READY`, then click
   **Generate remediation suggestion**.
4. Review the package, fixed version, action, reboot policy, and the
   `GovTech inference: not used` indicator; capture a screenshot.
5. Click **Approve proposal** and confirm the result says that approval was
   recorded with `mutation_performed: false`; capture a second screenshot.

## Acceptance

- A malformed CSV, target mismatch, ambiguous CVE, unavailable AWS read, or
  missing fixed version blocks with a stable reason code.
- Approval does not add a tool, call SSM, or mutate the EC2 instance.
- The browser never receives raw AWS payloads, credentials, or model output.

## Evidence and presentation

Save screenshots in the Windows folder using these names:

```text
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2A-01.png
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2A-02.png
```

The controller copies and renames them into the offline presentation
workspace with `scripts/build_seccop_presentation.py`. Screenshots stay out of
the public repository.
