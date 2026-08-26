# SecCop live demo lane

SecCop is the Security Copilot browser lane for one exact, private AWS EC2
target. The infrastructure is owned by
`infra/issue5-private-ssm-vpc/` and is held for the human demo until the
repo-owned cleanup command is explicitly approved.

## GUI inputs

Open the local server and use the **LIVE SECOP COMPARISON** panel:

1. **AWS Inspector CSV** - a CSV with the canonical header below.
2. **EC2 instance ID** - the exact target, for example `i-...`.
3. **CVE from CSV** - one CVE to compare.
4. **AWS region** - Singapore or Mumbai.
5. Click **Compare live target**.

The browser sends the CSV and target request to `/api/live-csv`. The server
validates the CSV, binds the selected CVE to the exact instance, then runs
the existing fail-closed Inspector/EC2/SSM read adapter. It returns only a
resource alias, counts, severity, package projections, check outcomes, and
stable reason codes.

## Canonical CSV

```text
instance_id,cve_id,severity,package_name,installed_version,fixed_version,status
```

Generate one from the exact target with the repo-owned exporter:

```bash
uv run python scripts/seccop_export_inspector_csv.py \
  --profile amit \
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
the SecCop live panel is read-only until a separate mutation milestone is
approved.

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

- The VPC has no IGW, NAT, public subnet, public IP, EIP, or public default
  route.
- SSM and Inspector access uses private endpoints.
- The browser never receives raw AWS payloads or identifiers from the live
  adapter.
- A successful read comparison does not claim remediation success.
- Cleanup is a separate, explicit Terraform operation after the human demo.
