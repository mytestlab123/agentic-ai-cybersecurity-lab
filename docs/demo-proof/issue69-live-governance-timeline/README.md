# Issue #69 live governance timeline

This is a small presentation guide for the existing unified SecCop journey:
**Provider evidence -> Recommendation -> Human decision -> Deterministic
action -> Verification**.

The screenshots are alias-only local UI evidence. They do not prove an AWS
mutation and must be refreshed before any live-provider claim.

1. `01-ecr-inspector-review.png` — ECR / clean Inspector review. The viewer
   should see Amazon Inspector evidence, a clean/compliant result, and the
   governance timeline saying no remediation proposal, human decision, or
   action is required. This followed **Scan ECR image**; **Reopen Finding** is
   visible for a separate repeatable demo and was not clicked. A future digest
   promotion remains a separate human approval action.
2. `02-s3-config-remediation-review.png` — S3 / configuration-risk review.
   The viewer should see a public bucket alias, Block Public Access absent, the
   recommendation to enable all four controls, and **Review exposure-risk
   remediation**. That button opens the exact human review boundary; it was
   not clicked and this screenshot is read-only. Any remediation requires a
   separate human decision and bound provider verification.
3. `03-ec2-imdsv2-remediation-review.png` — fixed EC2 / IMDSv2 review. The
   viewer should see the public fixed-LAB alias, optional-token/non-compliant
   state, the IMDSv2 recommendation, and **Remediate**. Remediate is the
   separate human approval boundary and was not clicked. The demonstrated scan
   is read-only; deterministic action and verification occur only after that
   later decision.
4. `04-three-source-navigation.png` — unified ECR, S3, and EC2 navigation.
   The viewer should see the three source controls and the selected ECR review
   boundary before a scan. **Scan ECR image** is read-only; **Reopen Finding**
   is a separate repeatable-demo action and was not clicked.

Every retained image was visually reviewed for public-safe aliases and
sanitized state. No account, resource, network, path, hash, CVE, raw provider
payload, or model output is retained.
