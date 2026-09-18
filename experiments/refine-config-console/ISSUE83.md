# Issue #83 / PR #84 implementation checkpoint

Status: four-account model implemented and tested with synthetic data. The PR
remains Draft. This is not a live four-account deployment.

## Implemented

- All Accounts plus ACCOUNT_A, ACCOUNT_B, ACCOUNT_C and ACCOUNT_D selection.
- Account-labelled inventory and detail drawer; identical rule names in different
  accounts have different opaque keys and count as separate account/control checks.
- Independent per-account caching and explicit partial/unavailable state. Missing
  accounts never count as compliant; all-unavailable differs from an empty inventory.
- Combined fetch time is the oldest included successful snapshot, not the time of
  the latest request. A failed refresh invalidates that account's detail bindings.
- Resource details are lazy, bound to one account/control, and use opaque page
  handles. Resource IDs are replaced with account-scoped aliases. Raw scope IDs,
  input parameters and creator/Config rule ARNs are not forwarded in this view.
- Existing search, filters, sorting, four summary cards and drawer are retained.
- Credential-free GitHub checks run the existing eight tests plus twelve new
  synthetic tests, TypeScript/Vite build, ESLint and the whitespace command.

## Running the synthetic mode

After the existing dependency installation and production build, use:

```bash
npm start -- --four-account-fixture
```

This mode is explicitly labelled SYNTHETIC and never invokes AWS. It uses invented
fixtures: 22 account/control checks, with compliant, non-compliant and unknown
states. These counts do not describe any live AWS account.

The existing `--fixture` and legacy DEV/PROD startup path are preserved. Four-account
mode requires an explicitly supplied reader and cannot inherit those live profiles.
Unknown startup flags are rejected, rather than falling through to live mode.

The server still binds only to loopback port 1111. The same-origin/Host and GET-only
API restrictions are unchanged. No process was started on the retained host and
SecCop port 2222 was not touched.

## Validation evidence

At implementation head `6edc01afb7699154d829a751d0491885f75c31da`, GitHub Actions
run [35389150180](https://github.com/mytestlab123/agentic-ai-cybersecurity-lab/actions/runs/35389150180)
passed after correcting one unnecessary regex escape flagged by ESLint.
The suite contains 20 passing synthetic tests; the production build and lint pass.
See the PR's latest check for subsequent revisions.

Coverage includes aggregation, duplicate rule names across accounts, failure
isolation, all-unavailable versus empty, refresh recovery, pagination, account-bound
resource pages, identity-field projection and the unchanged legacy provider.
These are provider/HTTP tests and a frontend build, not a new browser visual test.

## Remaining work in the same PR

1. Icons, saved light/dark appearance and synthetic browser acceptance, including
   account switching, failed refresh, drawer pagination and responsive layouts.
2. Verify the intended four personal-LAB aliases against existing authorized
   server-side mappings. ACCOUNT_A-D are synthetic labels, not evidence of any
   mapping. Do not carry the legacy office DEV/PROD profiles into the hosted LAB
   console or infer account identities from earlier experiment names.
3. Wire the bounded live reader only after per-account STS/read authorization;
   then configure and verify authenticated HTTPS through the approved proxy path.

Hosting, DNS/TLS/authentication, real four-account reads and browser acceptance are
not complete. No IAM, Config, remediation, deployment, resize, stop or termination
was performed for this checkpoint. The instruction to keep the LAB host running
remains in force.
