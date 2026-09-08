# SecCop v0.1 manager runbook

SecCop is a short, approval-bound demo. It presents provider evidence for one
configured source, a single exact recommendation, a human decision, and then
provider verification. It is not permission to run arbitrary cloud actions.

## One-command startup

Run the configured local listener:

```bash
./scripts/start-unified-seccop.sh
```

Open the loopback URL reported by the command. The launcher reads its private
runtime configuration outside this repository and fails closed if a required
binding is missing. Do not replace that configuration with values copied into
the repository.

## Five-minute talk track

1. Select **ECR**, **S3**, or the fixed EC2 LAB_01 source and press **Scan**.
   The result shows sanitized provider evidence and one proposal at most.
2. Point to the manager governance timeline: evidence, recommendation, human
   decision, deterministic action, and verification remain separate facts.
3. Choose **Remediate** (or **Approve Once** for ECR) only after reviewing the
   exact source-bound proposal. **Reject** records no provider change.
4. Read the returned verification state. `VERIFIED`/`COMPLIANT` is provider
   truth; `PENDING` means reconcile the exact provider state before retrying.
5. Use **New Chat** to discard local Codex conversation state. It changes no
   provider evidence, approval, target, or remediation state.

Existing sanitized presentation evidence is in
[`demo-proof/issue69-live-governance-timeline`](demo-proof/issue69-live-governance-timeline/).

## Control boundary

```text
Manager -> SecCop GUI -> typed source adapter -> provider evidence
                 |              |                  |
                 |              +-> exact proposal  +-> verification only
                 +-> human approve/reject

Codex explanation: sanitized, source-bound context only
```

The UI cannot authorize an unbound source, target, proposal, action, or
verification result. Submission uncertainty is `PENDING` with
`RECONCILE_BEFORE_RETRY`; it never becomes a claimed remediation success.

## Reset and cleanup

**New Chat** is the safe local session reset. It closes the local Codex
investigation and keeps provider and approval state unchanged.

Where the configured demo exposes **Reopen Finding**, it is a deliberate,
confirmed demo-state operation. Do not use it as general cleanup. Retained
demo resources stay retained; any deletion or cloud reset needs its own
explicit approval and runbook gate.

## Repeatable release proof

Before review, run the deterministic tests first, then the thin synthetic
browser proof:

```bash
uv run pytest
./scripts/golden-gui-e2e.sh
```

The golden proof uses one headless browser, no video, no screenshots on a
passing run, and its own temporary loopback server. It proves the three-source
scan, approval boundary, New Chat/reset, and a truthful blocked path without
AWS calls. Live provider proof remains a separately approved operation.
