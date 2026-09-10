# Issue #81 validation result

**PASS — implementation ready for ChatGPT review, not merge/acceptance.**
Date: 2026-09-10. Base: merged main `24cf06c0514e438aabfeb78ddd52e5f9fd211363`.
Scope: isolated Config console; no existing SecCop behavior/runtime changes.

## Checks actually completed

| Check | Observed result |
| --- | --- |
| TypeScript + Vite production build | PASS |
| ESLint | PASS |
| Node focused tests | 8 passed, 0 failed |
| Playwright Core + existing Chromium | PASS, synthetic server, zero AWS calls |
| Browser journey | DEV/PROD, category, search, status filter, sort/reverse, four cards, capped count, lazy drawer, second resource page, token exclusion, no page errors |
| DEV live paginated inventory | PASS; rules, compliance, recorder status present |
| PROD live paginated inventory | PASS; rules, compliance, recorder status present |
| DEV live HTTP inventory + lazy resource detail | HTTP 200 + HTTP 200; resource evaluations present, ResultToken omitted |
| Production dependency audit | 0 known vulnerabilities reported by npm audit at validation time |
| Public-safety inspection | Only synthetic fixtures/screenshots and sanitized proof committed; no private Config payloads or identities |
| Existing SecCop port 2222 | Not touched by this work |

## Live proof (sanitized, no provider payloads)

Explicit profile identity gates succeeded for both authorized environments;
no login or fallback was attempted.

DEV inventory proof ended `2026-09-10T04:12:45.386Z`; PROD inventory proof ended
`2026-09-10T04:14:42.881Z`. Each reported:

```json
{
  "rulesPresent": true,
  "compliancePresent": true,
  "recorderStatusPresent": true,
  "apiCalls": {
    "describe-config-rules": 20,
    "describe-compliance-by-config-rule": 7,
    "describe-config-rule-evaluation-status": 5,
    "describe-configuration-recorder-status": 1
  },
  "awsWrites": 0,
  "result": "PASS"
}
```

Final DEV HTTP proof ended `2026-09-10T04:23:30.607Z`:

```json
{
  "result": "PASS",
  "inventoryHttp": 200,
  "detailHttp": 200,
  "detailsLazy": true,
  "resourceEvaluationsPresent": true,
  "resultTokenOmitted": true,
  "apiCalls": {
    "describe-config-rules": 20,
    "describe-compliance-by-config-rule": 7,
    "describe-config-rule-evaluation-status": 5,
    "describe-configuration-recorder-status": 1,
    "get-compliance-details-by-config-rule": 1
  },
  "awsWrites": 0
}
```

These are runner-observed API counts and booleans, not a CloudTrail audit.
Only the five allowlisted Config reads and the initial read-only STS gates were
used. No rule/evaluation trigger, remediation, AWS creation, update, cleanup,
credential or IAM change occurred. PROD detail was not live-tested; its GUI
selection/detail contract shares the synthetic-tested path. No live provider
screenshot is claimed.

## Reviewed screenshots — synthetic only

Both final PNGs were opened and visually reviewed by Codex. They show invented
control/resource aliases, the SYNTHETIC label, four cards, the compact rule
table, and the read-only detail drawer. The drawer scrolls for lower content.

1. [Control inventory](01-synthetic-control-inventory.png)
2. [Control detail](02-synthetic-control-detail.png)

## Corrections during validation

- Fixed initial TypeScript inference before the successful build.
- Node fetch normalized a test Host header; used native HTTP to actually prove
  hostile Host rejection. Final HTTP boundary test passes.
- Default Playwright browser revision was not installed. Reused an existing
  Chromium executable with `CHROMIUM_EXECUTABLE`; installed no browser.
- Visual review caught a frequency label displaying source-details JSON.
  It now shows only provider frequency values or Not reported; regression added.
- Detail pagination binds cached inventory without refetching all inventory;
  stale drawer responses are discarded after source/selection changes.

## Local review runtime / rollback

Owner-requested port correction: moved the same owned console from 2231 to
1111 after checking the shared local port protocol and registry. Verified the
new listener command/cwd, HTTP 200 page and health, and old 2231 release;
registered 1111. ESLint and all 8 focused tests passed again. No AWS reread,
browser rerun, or screenshot regeneration was needed for this port-only change.

The experiment launcher is healthy in `AWS_READ_ONLY` mode at
**http://localhost:1111/**, in dedicated tmux session `refine-config-console`.
Its command is the repo-owned `npm start` from this experiment directory.
Listener process/cwd and `/api/health` were checked. No external exposure or
existing-port takeover was used. Health proof is not a substitute for the live
provider checks recorded above.

Stop only this experiment's owned process; revert/remove the experiment in a
reviewed Git change to roll back. There are no newly created AWS resources to
clean up. See [README](../README.md) for exact repeatable commands.
