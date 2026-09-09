# SecCop operator DEMO

This is a short POC story for a non-technical audience. The current operator
entrypoint is the unified fixed-loopback server, not the historical CVE demo.

## Current three-source journey

Start only with `./scripts/start-unified-seccop.sh`, then open
`http://127.0.0.1:2222`. For ECR, S3, or fixed EC2 LAB_01: scan provider facts,
review one exact deterministic proposal with a no-tool Codex explanation,
human Remediate/Reject, verify provider truth, then optionally reopen the
configured demo state. Codex explains only source-bound sanitized facts; it
cannot authorize a target, action, approval, or verification result.

The remaining CVE content is historical POC background.

## What the operator sees

The composer starts with **Check a CVE**. Paste one CVE from an email, ticket,
or advisory, then press the arrow. SecCop checks all three demo sources and
shows where the CVE was found. Paste one CVE at a time so the result stays
exact.

```text
Paste: CVE-2099-0001

Server packages       Found       Review fix
Stored artifact       Found       View suggestion
Container image       Found       View suggestion
```

The check is read-only. Only the existing server path can open the separate
live advisory and approval flow.

Use **Run guided example** in the composer only when you want to show the
original synthetic Inspector-to-SSM conversation.

The separate **Scan environment** button still runs the complete three-source
DEMO summary:

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
2. Paste `CVE-2099-0001` and press the arrow.
3. Show the three source results and the match count.
4. Open the stored-artifact and container suggestions. Point out: “Suggested
   fix only — no AWS change is enabled.”
5. Press **Scan environment** to show the full finding cards, then open
   **Review live fix** on the server card. Confirm the live advisory,
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

## Unified runtime restart

Start the configured unified review server with one repo-owned command:

```bash
./scripts/start-unified-seccop.sh
```

It reads the private, mode-600 runtime file at
`$HOME/.AGENTS-temp/agentic-ai-cybersecurity-lab/seccop-unified/runtime.env`
and starts the single listener in detached tmux session
`seccop-unified-2222`, bound only to `127.0.0.1:2222`. Repeating the command
verifies and reports the existing owned listener instead of starting another.
Use `./scripts/start-unified-seccop.sh --check` for a no-listener, no-AWS
preflight. Missing or incomplete ECR, S3, or EC2 configuration fails before
the listener starts as `RUNTIME_CONFIG_INVALID:<field-name>`.
