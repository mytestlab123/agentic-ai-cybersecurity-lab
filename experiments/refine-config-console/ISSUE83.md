# Issue #83 implementation checkpoint

This branch extends the merged Issue #81 / PR #82 Config console.

## Public contract

- UI shows `All Accounts` plus exactly four friendly account aliases.
- Public fixtures use only `ACCOUNT_A`, `ACCOUNT_B`, `ACCOUNT_C`, `ACCOUNT_D`.
- Real AWS profile/account mapping stays server-owned and outside the browser/public repository.
- Region remains `ap-southeast-1`.
- Existing Config provider stays read-only.
- No remediation, evaluation trigger, IAM change, or generic AWS API access.
- `localhost:1111` remains loopback-only.
- SecCop `127.0.0.1:2222` remains untouched.

## Implementation order

1. Generalize the provider/UI from DEV/PROD to four configured friendly aliases plus All Accounts.
2. Add icon polish and saved light/dark appearance without changing the information architecture.
3. Add the trusted reverse-proxy/auth deployment contract for `config.astromedicomp.org` and validate unauthenticated fail-closed behavior.

## Mapping gate

Only the existing DEV/PROD mappings are currently proven.

Do not invent or commit the other two live profile names. Live four-account validation starts only after the private server mapping is supplied and each configured account passes its own identity/read-only gate.

## Acceptance focus

Synthetic first:
- four aliases + All Accounts;
- one-account failure remains visible;
- aggregation never converts missing/unknown state into compliant;
- search/filter/sort/detail work;
- light/dark + icons;
- no browser credentials/profile names/account IDs;
- zero AWS writes.

Hosted proof later:
- authenticated HTTPS only;
- proxy to loopback 1111;
- live read-only proof for all four configured accounts;
- SecCop 2222 unchanged.
