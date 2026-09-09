# SecCop MVP presentation evidence pack

Status: **ready for ChatGPT review**

Owning Issue: #79

Accepted MVP baseline: merged PR #76 (`92702f27bf7b129c7e1010a98b8fabe883ea991c`).

Product development is frozen. This folder exists only to collect truthful, readable, public-safe evidence for a later ChatGPT-created presentation.

## Collection outcome

This pack contains eight deliberately selected screenshots and one optional
architecture visual. Each asset was visually reviewed at its original
resolution. The set favors accepted-baseline live Codex evidence and clearly
labels older provider-state captures as historical. No AWS call, runtime
change, feature change, or screenshot regeneration was performed for this PR.

## Evidence map

| File | Story | What it proves | Source/PR | Live vs historical | Public-safety checked | Suggested slide use |
| --- | --- | --- | --- | --- | --- | --- |
| [`00-architecture-overview.svg`](00-architecture-overview.svg) | Architecture | Separates read-only provider evidence and Codex explanation from human approval, deterministic action, and provider verification. | Current repository contracts and merged PR #76 | New documentation-only visual; no live call | Yes: service names and public aliases only; accessible, portable SVG | Optional starting point for ChatGPT; ChatGPT may revise or replace it in the approved storyboard |
| [`01-ec2-finding.png`](01-ec2-finding.png) | EC2 | AWS Config reported fixed `DEV_EC2_LAB_01` as IMDSv2 `NON_COMPLIANT` and exposed one exact remediation proposal. | Existing Issue #69 / merged PR #70 evidence | Historical provider-state capture | Yes: approved aliases only; no account, ARN, or raw resource ID | EC2 issue-found slide |
| [`02-ec2-codex-investigation.png`](02-ec2-codex-investigation.png) | EC2 | A completed live Codex App Server turn received the exact sanitized EC2 prompt and explained the bounded next step; model and read-only status are visible. | Existing repo-owned live runner at merged PR #76 | Accepted-baseline live Codex capture | Yes: alias-only facts; no private payload, path, or credential | EC2 investigation slide |
| [`03-ec2-verified-result.png`](03-ec2-verified-result.png) | EC2 | The GUI displayed fresh AWS Config evidence as IMDSv2 compliant with zero findings. | Existing Issue #55 provider E2E evidence / PR #56 lineage | Historical provider-verification capture | Yes: no raw instance ID, account, ARN, IP, or hostname | EC2 verified-result slide; note that it predates the final cosmetic cleanup |
| [`04-ecr-finding-and-codex-investigation.png`](04-ecr-finding-and-codex-investigation.png) | ECR | One accepted-baseline screen shows the sanitized Inspector finding and the completed source-bound Codex tool call for that same image alias and CVE. | Existing repo-owned live runner at merged PR #76 | Accepted-baseline live Inspector read and live Codex capture | Yes: `ECR_IMAGE_01` alias only; provider payload is sanitized | Two-step ECR story in one image: finding first, then zoom to Codex evidence |
| [`06-ecr-verified-result.png`](06-ecr-verified-result.png) | ECR | Amazon Inspector provider evidence was rendered as compliant/clean with zero active findings and no human decision required. | Existing Issue #69 / merged PR #70 evidence | Historical provider-verification capture | Yes: no registry, account, digest, ARN, or private repository value | ECR verified-result slide; this proves the clean provider state, not a new mutation in PR #80 |
| [`07-s3-finding.png`](07-s3-finding.png) | S3 | AWS Config reported bucket-level Block Public Access absent for approved alias `S3_BUCKET_ALIAS_03`. | Existing Issue #69 / merged PR #70 evidence | Historical provider-state capture | Yes: alias only; no real bucket name, account, policy, or ARN | S3 exposure-risk finding slide |
| [`08-s3-codex-investigation.png`](08-s3-codex-investigation.png) | S3 | A completed live Codex App Server turn received sanitized AWS Config facts and explained the exact Block Public Access recommendation without using tools beyond the bounded read. | Existing repo-owned live runner at merged PR #76 | Accepted-baseline live Codex capture | Yes: alias-only facts; no private payload, path, or credential | S3 investigation slide |
| [`09-s3-verified-result.png`](09-s3-verified-result.png) | S3 | The historical GUI journey shows human approval, Block Public Access remediation wording, and a terminal protected state with zero findings. | Existing local S3 demo evidence from the Issue #47 lineage | Historical local synthetic UI capture; not live AWS provider proof | Yes: approved bucket aliases only; no account, ARN, real bucket name, path, or credential | S3 verified-result slide, with the synthetic-mode limitation stated in speaker notes |

## Source summary

- `01`, `03`, `06`, `07`, and `09` reuse existing recorded state evidence.
- `02`, `04`, and `08` reuse existing local captures created by the repo-owned
  accepted PR #76 live runner.
- No screenshot was newly recaptured, generated, or cosmetically altered for
  this PR; files were copied and given descriptive presentation names only.
- `00` is a new documentation-only, public-safe visual retained at Amit's
  request after a two-pass render review. ChatGPT owns the final presentation
  diagram and may revise or replace it.

## Evidence limits and exclusions

- `09-s3-verified-result.png` completes the visual sequence with an existing
  historical local synthetic capture. It proves the manager-visible approval
  and protected terminal UI state only; it does not prove a live AWS provider
  action or verification at PR #80.
- No separate ECR investigation image is included. The strongest PR #76 image
  already shows the real sanitized Inspector finding and its matching live
  Codex turn. An available cropped card referred to a synthetic
  `CVE-2099-0001`, so combining it with the real Inspector finding would have
  created a false sequence.
- Screenshots showing deterministic fallback, `NOT_FOUND`, unavailable AI,
  stale synthetic UI, or failed/blocked investigations were excluded from the
  positive demo sequence.
- Captures containing account identifiers, raw AWS resource identifiers,
  private environment names, local paths, or unrelated customer/work material
  were excluded.
- Historical verified-state images demonstrate manager-visible provider truth
  from the recorded milestone. They are not evidence that PR #80 performed an
  AWS action or that the three screenshots form one newly executed transaction.

## Architecture facts for ChatGPT

These are the source-grounded facts behind the optional SVG. ChatGPT retains
ownership of the final presentation diagram and storyboard:

1. The operator uses one unified SecCop GUI and selects EC2, ECR, or S3.
2. Deterministic adapters obtain provider truth: AWS Config for EC2 IMDSv2 and
   S3 Block Public Access; Amazon Inspector for ECR package findings.
3. Only sanitized, source-bound facts are exposed to an allow-listed,
   read-only Codex App Server tool call.
4. Codex explains evidence and recommends a safe next step; it does not
   authorize or execute AWS changes.
5. A human reviews one exact proposal and chooses Remediate/Approve Once or
   Reject.
6. Any approved action and the fresh provider verification are deterministic;
   the manager-visible result must reflect provider truth.

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

## Suggested presentation sequence

The later deck should feel like a live demo:

```text
ChatGPT-created architecture / what to expect
→ EC2 finding
→ EC2 Codex investigation
→ EC2 verified result
→ ECR finding + Codex investigation
→ ECR verified result
→ S3 finding
→ S3 Codex investigation
→ S3 verified result, explicitly labeled historical local synthetic evidence
→ operational value / what was proved and what was not
```

ChatGPT will discuss 2-3 storyboard options with Amit after this PR is reviewed. No PPTX should be created before that approval.

## Handoff contract

The PR handoff must name the exact committed HEAD:

```text
HANDOFF: CHATGPT
Head: <exact SHA>
Result: PASS / READY
Next: review screenshot pack and discuss presentation storyboards with Amit
Accept: screenshots are readable, truthful, public-safe, properly named, documented in README, and no product development/AWS mutation was required.
```
