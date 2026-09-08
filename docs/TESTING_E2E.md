# SecCop Testing and GUI E2E Policy

This is the long-term test policy for the SecCop POC.

## Goal

Keep validation cheap, deterministic and reviewable while still proving the real browser journey.

Use this order:

`pytest / direct functions -> API + mock fixtures -> thin Playwright GUI E2E -> bounded live provider proof`

Codex should spend most effort on deterministic tests and use Playwright as the final browser proof, not as the primary debugging interface.

## Allowed test tools

- **Mock API / fixtures: preferred** for most GUI states and negative paths.
- **pytest / direct Python tests: preferred** for policy, routing, proposal, approval and lifecycle logic.
- **HTTP/API tests (`urllib`, `httpx`, `curl` or existing repo helpers): preferred** for endpoint contracts.
- **Playwright: allowed** for a small set of browser golden flows and presentation screenshots.
- **Chrome DevTools/CDP: debug-only** when a failing Playwright run needs deeper DOM/network/console inspection.
- Postman is optional for manual exploration, not a required dependency or CI layer.

Do not add another browser framework or broad test harness unless the existing path cannot prove the required behavior.

## Cheap Playwright defaults

For routine Codex validation prefer:

- headless browser;
- one worker;
- no video;
- concise/line output;
- screenshots only on failure;
- trace retained only on failure;
- no repeated screenshot/vision loop when a DOM/API assertion can prove the same thing.

Codex should first read the small PASS/FAIL result. Inspect trace, screenshot, console or DevTools only for the failing flow.

## Golden GUI flows

Keep the browser suite intentionally small. Cover the manager-visible journeys only:

1. ECR finding -> explanation/recommendation -> human decision -> terminal/verification state.
2. S3 finding -> explanation/recommendation -> human decision -> terminal/verification state.
3. EC2 IMDSv2 finding -> explanation/recommendation -> human decision -> terminal/verification state.
4. New Chat/reset -> fresh source-bound Codex investigation.
5. One important fail-closed case showing a truthful blocked/pending state.

Prefer mocked/synthetic provider responses for routine E2E. Run live AWS/provider proof only for the bounded milestone that requires it and only within the applicable explicit mutation gate.

## Presentation screenshot mode

Presentation screenshots are a separate proof mode, not a reason to enable screenshots for every test.

For an active milestone, store only sanitized, presentation-worthy captures under:

`docs/demo-proof/<milestone>/`

Use numbered descriptive names, for example:

- `01-ecr-provider-evidence.png`
- `02-ecr-recommendation-and-approval.png`
- `03-s3-human-reject-no-action.png`
- `04-ec2-approved-action-verified.png`
- `05-codex-session-reset.png`

The milestone folder must contain a `README.md` explaining, for each screenshot:

- sequence / operator step;
- expected behavior;
- what sanitized output is visible;
- which button was clicked and its effect;
- where the human approval boundary is;
- any refresh, eventual-consistency or verification limitation.

Screenshots must not expose credentials, account IDs, ARNs, raw resource IDs, private paths, tokens, provider payloads, or internal logs. If safe sanitization cannot be proven, keep the capture outside Git.

## Evidence economy

A normal code change does not need screenshots if tests prove it. A manager-demo milestone does need a small curated screenshot sequence.

Prefer one useful proof per behavior over large screenshot sets, exhaustive browser matrices, or repeated agent-driven clicking.

## Merge evidence

Before ChatGPT complete-diff review, record:

- relevant pytest/API result;
- Playwright golden-flow result when GUI behavior changed;
- live-provider result only when the milestone requires it and authority exists;
- `git diff --check`;
- public-safety check;
- exact PR HEAD.

ChatGPT reviews the exact HEAD. If the HEAD moves after review, reconcile and review the new complete diff before merge.
