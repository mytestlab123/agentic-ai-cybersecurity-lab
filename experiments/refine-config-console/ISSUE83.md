# Issue #83 / PR #84 implementation checkpoint

Status: four-account model and themed UI implemented with synthetic data.
The PR remains Draft. This is not a live four-account deployment.

## Implemented

- All Accounts plus ACCOUNT_A, ACCOUNT_B, ACCOUNT_C and ACCOUNT_D selection.
- Account-labelled inventory and detail drawer. Identical rule names in different
  accounts have different opaque keys and count as separate account/control checks.
- Independent caching, explicit partial/unavailable state, and oldest included
  fetch time. Missing accounts never count as compliant. Failed refreshes invalidate
  affected detail bindings; all-unavailable differs from successful empty inventory.
- Lazy details and opaque page handles bind to one account/control. Resource IDs
  become account-scoped aliases; raw scope IDs, parameters and creator/rule ARNs
  remain withheld by the existing four-account projection.
- Local vector icons, navy navigation, account cards and semantic status chips.
  These are interface/service cues, not official AWS logos. Attribution: NOTICE.md.
- Saved light/dark mode. System preference applies before a saved choice; denied
  localStorage does not break the page. A same-origin head script applies the theme
  before React. Theme changes do not request inventory or change compliance state.
- Responsive category navigation, scrollable table, keyboard focus indicators and
  themed detail sheet. Drawer close restores focus to the selected control.
- Existing search, filters, sort, four summary cards and legacy DEV/PROD paths remain.

## Synthetic validation

The console workflow uses pinned actions, read-only repository permissions and no
AWS credentials, OIDC or deployment steps. It runs 24 provider/HTTP/theme tests,
TypeScript/Vite build, ESLint and whitespace checks.

It also runs the legacy browser journey and `test/theme-browser.mjs` using the
repository's existing locked Playwright Core dependency and runner-installed
Chromium-compatible browser. No browser installation or AWS call is performed.
The new journey checks:

- both themes, saved reload, system default and denied storage;
- Enter/Space toggle, drawer close/focus and no API side effects from the theme;
- All Accounts, single account, category/search/filter/sort and lazy pagination;
- partial failure, all-unavailable and recovery without invented compliance;
- 1600px, 390px and 320px layouts; no page overflow or external browser requests;
- text contrast for the body, summary text, status chips and sidebar hint.

Run 35418560541 passed the initial icon/theme checkpoint. Visual review then
identified a layers-icon geometry issue, drawer focus restoration and screenshot
framing improvements; all are corrected in this branch. The latest PR check is
the authority for the final revised head, not this earlier run.

Synthetic screenshots are short-lived CI preview artifacts, not live AWS proof.
They show invented accounts and counts only. No real account screenshots are used.

## Running the synthetic mode

After the existing dependency installation and production build:

```bash
npm start -- --four-account-fixture
```

The SYNTHETIC label is mandatory. Fixtures contain 22 account/control checks;
these counts do not describe any live AWS account. Existing `--fixture` and
legacy startup remain preserved. No default live reader or legacy-profile
fallback is added to four-account mode. Unknown startup flags still fail closed.

The server binds only to loopback port 1111. Same-origin/Host and GET-only API
restrictions are unchanged. No retained-host process or SecCop port 2222 changed.

## Remaining work in the same PR

1. Verify all four intended personal-LAB accounts against existing authorized
   private mappings. ACCOUNT_A-D are synthetic labels, not proven live mappings.
   Do not carry office DEV/PROD credentials or provider data into the hosted LAB
   console, and do not infer account identities from old profile labels.
2. Wire the bounded live reader only after each account passes STS/read validation.
3. Configure and verify authenticated HTTPS through the approved hosting/proxy
   path, including separate DNS/TLS/authentication checks and live acceptance.

The theme checkpoint does not deploy hosting or widen AWS authority. No AWS calls,
IAM/Config changes, remediation, resize, stop or termination were performed.
The instruction to keep the LAB host running remains in force.
