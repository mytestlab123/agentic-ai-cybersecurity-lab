# SecCop operator DEMO

This is a short POC story for a non-technical audience. It shows one Scan
button, three source cards, and one real controlled fix.

## What the operator sees

```text
[ Scan environment ]

Checking server packages       complete
Checking stored artifact       complete
Checking container image       complete

3 findings
HIGH    Server package       Review live fix
MEDIUM  Stored artifact      View suggested fix
HIGH    Container image      View suggested fix
```

The server card opens the existing live advisory check. Approval remains
exact, expiring, one-time, and proposal-bound. The stored-artifact and
container cards are fixture-backed and read-only in this POC; they never show
a fake approval or claim a successful change.

## Five-minute DEMO

1. Open `http://127.0.0.1:8765`.
2. Press **Scan environment**.
3. Show the three source checks and the three finding cards.
4. Open the stored-artifact and container suggestions. Point out: “Suggested
   fix only — no AWS change is enabled.”
5. Open **Review live fix** on the server card. Confirm the live advisory,
   review the exact package change, and approve only if the current target is
   intentionally available for the demo.
6. Show **Before -> Action -> After** and the final verification state.

## Screenshot placeholders

Save captures in:

```text
C:\Users\ISSUser\Pictures\Screenshots
```

Suggested captures:

```text
SecCop-Scan-01.png  landing page with Scan environment
SecCop-Scan-02.png  scan progress and three finding cards
SecCop-Scan-03.png  server proposal and approval boundary
SecCop-Scan-04.png  Before -> Action -> After result
```

Do not commit screenshots or live AWS identifiers to this public repository.

## POC boundary

The goal is a clear operator experience, not three production remediation
engines. EC2 is the only real mutation lane. S3 and ECR become real only in a
separate issue after the operator flow is useful and the exact AWS cost,
permission, rollback, and verification contract is approved.
