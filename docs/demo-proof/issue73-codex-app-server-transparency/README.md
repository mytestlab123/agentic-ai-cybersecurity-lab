# Codex App Server transparency evidence

`01-s3-busy-fallback.png` is a sanitized local UI observation supplied for
Issue #73. It contains aliases only and no credentials, account identifiers,
resource identifiers, or provider payloads.

It shows an S3 screen whose status strip reports that the Codex App Server is
enabled and that one S3 BEFORE turn completed, followed by
`CODEX_INVESTIGATION_BUSY`. It proves the fail-closed busy-session UI state;
it does **not** prove that a model response was displayed for that scan.

The expected safe recovery is **New investigation**. That clears only the
local source-bound conversation. It does not alter provider evidence, an
approval, or a remediation state. See Issue #73 for the evidence limits and
the acceptance plan for a future, public-safe live-turn receipt.
