# Issue #87 implementation checkpoint

Single hosted product surface:
- Config Dashboard is the dashboard.
- Compliance Agent remains the separate agent.
- Demo controls are a small admin-only drawer in Config Dashboard.
- Demo re-arm uses only the four-account Issue #82 CodeBuild prepare path.
- Legacy 100-S3 / 10-SG Operator preparation is not used.
- Persist sanitized aggregate history locally.
- Group controls by simple operational domains only: Storage, Network, Compute, Identity, Other.
- No CIS/NIST/ISO mapping and no invented severity.
