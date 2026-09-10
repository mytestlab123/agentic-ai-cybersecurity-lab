# Refine Config console · Issue #81

Isolated, deletable **Refine + shadcn/ui** control explorer. One row is one
AWS Config rule; affected resources load only when its detail drawer opens.
This does not replace or change the existing SecCop server on port 2222.

## Run

On the shared host, read `~/.codex/port.md` before configuring or starting a
listener. Check its registry and live listeners, verify process ownership before
stopping anything, and register the actual loopback port after startup. Prefer
the memorable default 1111; existing SecCop retains 2222.

From this directory, with Node 22.12+ and AWS CLI v2 available:

```bash
npm ci
npm run build
npm start -- --fixture
```

Open **http://localhost:1111/**. `--fixture` uses invented local data and
never calls AWS. Stop this process with Ctrl-C. A busy port is an error;
the launcher never stops another process. `PORT` may select another free
unprivileged port, but 2222 is rejected.

For the owner-authorized Issue #81 live read-only experiment, omit `--fixture`:

```bash
npm start
```

DEV maps server-side to `ihis_dev`; PROD to `ihis_pro`; both are pinned to
`ap-southeast-1`. Profiles must already be authenticated and authorized.
No login, fallback, credential change, AWS write, evaluation trigger, or
remediation action exists here. Do not use this profile exception for other
SecCop work. The browser receives friendly environment labels, not credentials.

Use an owned terminal or a dedicated tmux session when keeping the console
running. Example from this directory: `tmux new-session -s refine-config-console
'npm start'`. This is process lifecycle only, never agent prompt delivery.
Do not run synthetic and live listeners on the same port or repurpose port 2222.

## Data flow and boundaries

- React/Refine `useOne` and the read-only data provider load a complete inventory
  snapshot. shadcn Button/Sheet are local adapted Radix compositions; see
  [NOTICE.md](NOTICE.md). Tailwind styles and dependencies stay here.
- Loopback-only Node HTTP backend, same-origin/Host checks, GET-only API,
  no CORS, no telemetry, no credentials or provider dumps written to disk.
  This is a trusted-local-operator POC, not a multi-user authenticated service.
- Initial load / explicit Refresh reads all pages of `DescribeConfigRules`,
  `DescribeComplianceByConfigRule`, `DescribeConfigRuleEvaluationStatus`, and
  `DescribeConfigurationRecorderStatus`. A 30-second per-environment process
  cache and in-flight coalescing limit duplicate reads; explicit refresh bypasses
  the cache except for a 2-second burst guard. No background polling.
- Opening a known inventory rule calls `GetComplianceDetailsByConfigRule`
  with `NON_COMPLIANT`, 100 results/page. **Load more resources** uses NextToken.
  Detail pagination does not refresh/fan out inventory. `ResultToken` is omitted
  by an explicit field projection. No optional remediation lookup is included.
- Only five read API operation names are allowlisted. AWS runs without a shell,
  with fixed server-owned profiles/region, inherited AWS key/endpoint overrides
  removed, configured endpoint URLs ignored, and bounded per-call timeouts.
  Failed reads return a generic actionable error, never raw AWS CLI stderr.
- Classification precedence: explicit scope types, observed detail types, then
  small known AWS identifier mappings/prefixes. Unknown/custom descriptions
  never drive categorization. Security Groups precedes generic EC2. Unrecognized
  explicit resource types remain Other instead of overriding provider scope.

## Truthful counts and health

All summary counts come from the full paginated rule inventory, not the capped
summary API. The attention card is the union of insufficient/missing compliance
and recent evaluation/invocation failures; it can overlap other cards. Unknown
compliance is **NOT REPORTED**, not compliant. NOT_APPLICABLE is preserved.
For non-compliant contributors, `CapExceeded` renders `N+`; compliant contributors
are never displayed as non-compliant counts. Missing counts/times stay unknown.
Warnings compare failure timestamps to the corresponding successful timestamp;
old error text alone is not a current failure. Detail timestamps are current
provider fields, not an invented historical timeline. Empty resource results
do not rewrite a rule's compliance. The table supports all specified filters
and sorts, with a reverse-order control; horizontal scrolling preserves columns
on smaller screens.

## Repeatable validation

```bash
npm run build
npm run lint
npm test
npm run test:browser
```

Browser proof uses the root repo's existing `playwright-core` and installed
Chromium. If its default browser revision is absent, set `CHROMIUM_EXECUTABLE`
to an existing compatible executable; the runner installs nothing. It starts
and closes only its own ephemeral **synthetic** server/browser, never the live
1111 or existing 2222 listener. Optional `SCREENSHOT_DIR=./evidence` captures
synthetic screenshots only. Browser checks are explicit, not a startup action.

Explicit live proof (read-only, sanitized booleans/API counts only):

```bash
npm run proof:live -- DEV
npm run proof:live -- PROD
npm run proof:http -- DEV
```

See [evidence/RESULT.md](evidence/RESULT.md) for the actual validation record and
reviewed synthetic screenshots. Live data may contain private company resource
identities: do not screenshot, save, upload or commit it. Synthetic screenshots
are UI proof, **not live provider screenshots**.

`proof:http` starts its own ephemeral loopback server, reads the inventory, and
opens one non-compliant rule to prove lazy affected-resource reads over HTTP.
It closes only that server and emits no resource identities.

## Remove / rollback

Stop only this experiment's owned process/session. Revert the implementation
commit (or remove this experiment directory in a reviewed change). No AWS
cleanup is needed: nothing was created or mutated. No existing SecCop files,
runtime configuration, dependency lockfile, or listener need to change.

## API references

- [AWS Config API reference](https://docs.aws.amazon.com/config/latest/APIReference/Welcome.html)
- [DescribeComplianceByConfigRule](https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeComplianceByConfigRule.html)
- [GetComplianceDetailsByConfigRule](https://docs.aws.amazon.com/config/latest/APIReference/API_GetComplianceDetailsByConfigRule.html)
- [Refine data provider](https://refine.dev/core/docs/data/data-provider/)
