# SecCop AWS DEMO rehearsal

Date: 2026-08-27

This is sanitized evidence from the Project1 rehearsal. It contains aliases
and counts only; no AWS identifiers or raw payloads are included.

## Result

The repeatable workflow worked for the three-source DEMO:

```text
Start baseline -> Scan -> Approve S3 -> Fix S3 -> Approve ECR -> Fix ECR -> Rescan
```

### Initial scan

| Source | Result | Evidence |
| --- | --- | --- |
| EC2 package (`LAB_SERVER_01`) | NON_COMPLIANT | 1 missing patch; 41 security-noncompliant patches |
| S3 artifact (`ARTIFACT_01`) | NON_COMPLIANT | 12 Trivy vulnerabilities in the old dependency file |
| ECR image (`IMAGE_01`) | NON_COMPLIANT | 12 Trivy vulnerabilities in the old image |

### Approved fixes

- S3: `SECCOP_S3_FIX_APPLIED`
- ECR: `SECCOP_ECR_FIX_APPLIED`

### Rescan

| Source | Result |
| --- | --- |
| EC2 package (`LAB_SERVER_01`) | NON_COMPLIANT — waiting for the existing EC2 human approval path |
| S3 artifact (`ARTIFACT_01`) | COMPLIANT |
| ECR image (`IMAGE_01`) | COMPLIANT |

The baseline was restored after the rehearsal, so the next DEMO starts with
the S3 and ECR findings again. No EC2 mutation or termination was performed.

The same sequence is now a repo-owned command:

```bash
uv run python scripts/seccop_demo.py verify --profile vagent --region ap-southeast-1 --confirm
```

## What this proves

- The account can hold a small, known-bad and clean S3 artifact pair.
- The account can hold a small, known-bad and clean ECR image pair.
- The GUI and CLI use the same deterministic scan/fix commands.
- S3 and ECR fixes require explicit approval and produce a clean rescan.
- GuardDuty is not required for this POC.
