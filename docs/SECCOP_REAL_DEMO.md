# SecCop real DEMO

This is a small POC, not an enterprise scanner. It uses one known old
dependency (`urllib3`) as a harmless non-compliant example. It does not use
real malware and does not require GuardDuty.

## Prepare the DEMO

The command is idempotent for the resources it owns:

```bash
./scripts/start-demo.sh --profile vagent --region ap-southeast-1 --confirm
```

It checks that the existing tagged EC2 target is still non-compliant, creates
or refreshes two private, versioned S3 buckets, and creates or refreshes one
ECR repository containing a known-bad and a clean image. The shared VPC and
SSM profile are not changed. It refuses to downgrade an already-clean EC2
target; restoring that host from the pinned old AMI is a separate approval.

## Start the GUI with the AWS backend

Use a different local port if an older server is already using `8765`:

```bash
AWS_PROFILE=vagent AWS_REGION=ap-southeast-1 \
SECCOP_DEMO_BACKEND=AWS POC_PORT=8766 \
uv run python -m secure_agent_harness.poc_server
```

Open `http://127.0.0.1:8766`, choose **Start AWS DEMO**, and then **Scan
environment**.

The normal operator story is:

```text
Start DEMO -> Scan -> Review -> Approve -> Fix -> Scan again
```

- **EC2:** the existing live advisory and SSM approval path is used. No
  package change starts without the approval controls already in the GUI.
- **S3:** approve replacing the old requirements file with the clean file.
- **ECR:** approve promoting the clean image digest to the DEMO tag.

The browser receives aliases only: `LAB_SERVER_01`, `ARTIFACT_01`, and
`IMAGE_01`. Raw AWS identifiers, credentials, and scanner payloads stay
outside the browser result.

## Scan and fix from the CLI

```bash
uv run python scripts/seccop_demo.py scan --profile vagent --region ap-southeast-1
uv run python scripts/seccop_demo.py fix --source s3 --profile vagent --region ap-southeast-1 --confirm
uv run python scripts/seccop_demo.py fix --source ecr --profile vagent --region ap-southeast-1 --confirm
uv run python scripts/seccop_demo.py rescan --profile vagent --region ap-southeast-1
uv run python scripts/seccop_demo.py verify --profile vagent --region ap-southeast-1 --confirm
```

`--confirm` is required for preparation and fixes. The EC2 package remains a
separate exact-target approval because it changes a running host.

`verify` runs one bounded S3/ECR approval and clean-rescan rehearsal, then
restores the non-compliant baseline. It reports EC2 approval as pending rather
than changing the running server.

## GuardDuty decision

GuardDuty Malware Protection for S3 is intentionally out of scope. It is not
needed to scan this controlled artifact, may not be available on a free AWS
account, and would add service configuration and cost. Trivy provides the
small, repeatable artifact and image evidence for this POC.

## Cleanup boundary

The shared VPC, public subnet, and SSM instance profile are retained. Do not
terminate the DEMO EC2 target until the manual DEMO is complete. When cleanup
is approved, terminate only the exact tagged EC2 target and remove its unused
security group; retain the reset S3 bucket and ECR repository for the next
five-minute DEMO unless a separate cleanup approval is given.
