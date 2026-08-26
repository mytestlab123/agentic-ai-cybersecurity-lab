# SecCop Phase 2C - post-remediation verification

## Objective

Prove whether the selected Inspector finding is actually closed after Phase
2B. A successful SSM command is only an execution result; it is not a
vulnerability-closure result.

## Verification sequence

1. Read the exact target's SSM patch state and pending-reboot state.
2. Collect a fresh Inspector result for the same CVE and exact target.
3. Compare before and after package/version evidence.
4. Emit one stable outcome:
   - `VERIFIED` - the selected finding is independently resolved.
   - `PENDING_RESCAN` - the package changed but Inspector has not refreshed.
   - `FAILED` - the target, patch state, or finding did not meet the contract.
5. Preserve sanitized before/after evidence and the approval/command IDs
   outside the public repository.

## Demo steps

1. Open the completed Phase 2B execution card and click **Verify finding**.
2. Confirm the card shows patch state, pending reboot, and a fresh Inspector
   timestamp/status for the same target and CVE.
3. Expand the before/after summary and confirm no raw AWS payload is shown.
4. Capture a screenshot of the final `VERIFIED`, `PENDING_RESCAN`, or `FAILED`
   result and its reason code.
5. Do not claim that all findings are fixed unless every finding has its own
   independent closure evidence.

## Acceptance

- The verification request is bound to the approved target and CVE.
- `VERIFIED` requires a fresh Inspector result, not only SSM success.
- A pending Inspector refresh is visible as `PENDING_RESCAN`, never silently
  upgraded to success.

## Evidence

Save captures as:

```text
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2C-01.png
C:\Users\ISSUser\Pictures\Screenshots\SecCop-Phase-2C-02.png
```
