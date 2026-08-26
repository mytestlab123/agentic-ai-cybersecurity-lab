# SecCop live demo lane

SecCop is the Security Copilot browser lane for one exact Project1 AWS EC2
target. The shared network is retained; the disposable target is owned by
`infra/project1-seccop-ec2/` and the reusable SSM profile by
`infra/project1-seccop-shared/`.

Use the shared local profile and region:

```bash
export AWS_PROFILE=vagent
export AWS_REGION=ap-southeast-1
```

The Project1 account must have Amazon Inspector EC2 scanning activated before
the exporter can produce a real finding CSV. If the AWS API returns
`SubscriptionRequiredException`, activate Inspector from the account's
Inspector console and then rerun the exporter.

## Simple GUI journey

Open the local server and use the **LIVE SECOP CHECK** panel. Upload one typed
advisory JSON file, choose Singapore, and click **Check live server**. The
server selects the one tagged `LAB_SERVER_01` target; the browser never asks
for an EC2 instance ID.

The small input shape is:

```json
{
  "advisory_id": "ALAS2-YYYY-NNNN",
  "cve_id": "CVE-YYYY-NNNN",
  "severity": "MEDIUM",
  "package_name": "example-package",
  "installed_version": "old-version",
  "fixed_version": "new-version"
}
```

SecCop performs only these read checks first: exactly one tagged running
server, SSM online, and the advisory present in `yum updateinfo`. It then
shows a plain-language one-package proposal. **Prepare update** rechecks the
same target, and **Approve and run fix** is the only path that can call SSM to
update that exact package. No reboot is requested. The final result reports
the before and after package versions; Inspector refresh remains a separate
follow-up because its finding cache is not immediate.

The server-side target name can be changed for a different disposable lab
host with `SECCOP_TARGET_NAME`; the browser contract stays alias-only.

The older technical Inspector CSV route remains under **Technical Inspector
CSV path** for comparison work. It still requires an exact instance ID and is
not needed for the simple one-package demo.

## Canonical CSV

```text
instance_id,cve_id,severity,package_name,installed_version,fixed_version,status
```

Generate one from the exact target with the repo-owned exporter:

```bash
uv run python scripts/seccop_export_inspector_csv.py \
  --profile vagent \
  --region ap-southeast-1 \
  --instance-id INSTANCE_ID \
  --output /path/outside/repo/inspector-findings.csv
```

The exporter rejects an empty result. The CSV is evidence for the next
remediation phase; it is not authorization to patch.

## Start the UI

```bash
uv run python -m secure_agent_harness.poc_server
```

Open `http://127.0.0.1:8765`. The local synthetic flow remains available, and
the SecCop live panel is read-only until the human approval button is used.

## GovTech model boundary

The optional hosted-model session uses the GovTech handoff in the sibling
`govtechai` repository:

```bash
gtx check
gtx models
```

The capability key stays in `~/.config/gtx/config.env` with mode `600`. It is
never placed in this repository, a prompt, a process argument, browser data,
or evidence. Model output remains untrusted input and must pass typed
validation before policy or tool dispatch. No inference is required for the
read-only CSV comparison.

## Safety boundary

- The existing shared VPC and public subnet are retained; no route or gateway
  is created or changed by SecCop.
- The disposable security group has no inbound rules; the target has outbound
  HTTPS and an approved public IP for this learning lane.
- SSM and Inspector use the target's outbound HTTPS path.
- The browser never receives raw AWS payloads or identifiers from the live
  adapter.
- A successful read comparison does not claim remediation success.
- Cleanup is a separate, explicit Terraform destroy of only the EC2 stack; the
  shared VPC and SSM profile remain.
