# SecCop MVP presentation evidence pack

Status: **collection in progress**

Owning Issue: #79

Accepted MVP baseline: merged PR #76 (`92702f27bf7b129c7e1010a98b8fabe883ea991c`).

Product development is frozen. This folder exists only to collect truthful, readable, public-safe evidence for a later ChatGPT-created presentation.

## Codex collection task

Follow Issue #79 exactly.

Priority order:

1. Reuse existing local screenshots from `C:\Users\ISSUser\Pictures\Screenshots\` and existing repo evidence.
2. Rename/copy only the strongest, readable, truthful screenshots into this folder.
3. Recapture with the existing repo-owned runner only when necessary; do not change application behavior for presentation purposes.
4. Do not perform new AWS mutation merely to obtain an AFTER screenshot.
5. Do not create PowerPoint files in this PR.

## Target evidence map

| File | Story | What it proves | Source/PR | Live vs historical | Public-safety checked | Suggested slide use |
| --- | --- | --- | --- | --- | --- | --- |
| `00-architecture-overview.png` or `.svg` | Architecture | TODO | TODO | TODO | TODO | Opening architecture/demo flow |
| `01-ec2-finding.png` | EC2 | TODO | TODO | TODO | TODO | EC2 issue found |
| `02-ec2-codex-investigation.png` | EC2 | TODO | TODO | TODO | TODO | Codex explanation/investigation |
| `03-ec2-verified-result.png` | EC2 | TODO | TODO | TODO | TODO | EC2 verified result |
| `04-ecr-finding.png` | ECR | TODO | TODO | TODO | TODO | Inspector vulnerability found |
| `05-ecr-codex-investigation.png` | ECR | TODO | TODO | TODO | TODO | Codex explanation/investigation |
| `06-ecr-verified-result.png` | ECR | TODO | TODO | TODO | TODO | ECR verified result |
| `07-s3-finding.png` | S3 | TODO | TODO | TODO | TODO | S3 compliance issue found |
| `08-s3-codex-investigation.png` | S3 | TODO | TODO | TODO | TODO | Codex explanation/investigation |
| `09-s3-verified-result.png` | S3 | TODO | TODO | TODO | TODO | S3 verified result |

Delete rows for screenshots that cannot be supported truthfully. Do not fabricate missing states.

## Public-safety contract

Allowed:
- AWS service names;
- generic/public aliases such as `DEV_EC2_LAB_01`, `SG_LAB_01`, `S3_BUCKET_ALIAS_03`, `ECR_IMAGE_01`;
- sanitized Codex prompt/response text already approved by the product.

Do not commit screenshots containing:
- account IDs;
- ARNs;
- real instance, image, repository, bucket, VPC, or security-group IDs/names beyond approved aliases;
- local private paths;
- tokens, credentials, auth/session material;
- customer/private environment data.

## Presentation intent

The later deck should feel like a live demo:

```text
Architecture / what to expect
→ EC2 finding
→ EC2 Codex investigation
→ EC2 verified result
→ ECR finding
→ ECR Codex investigation
→ ECR verified result
→ S3 finding
→ S3 Codex investigation
→ S3 verified result
→ operational value / what was proved
```

ChatGPT will discuss 2-3 storyboard options with Amit after this PR is reviewed. No PPTX should be created before that approval.

## Handoff

When complete, replace `collection in progress` with `ready for ChatGPT review`, fill the evidence table, note excluded/stale screenshots, then leave on the PR:

```text
HANDOFF: CHATGPT
Head: <exact SHA>
Result: PASS / READY
Next: review screenshot pack and discuss presentation storyboards with Amit
Accept: screenshots are readable, truthful, public-safe, properly named, documented in README, and no product development/AWS mutation was required.
```
