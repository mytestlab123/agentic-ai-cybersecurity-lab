# Agentic AI Cybersecurity Lab

A public, personal learning lab for understanding secure agent engineering with
small Python experiments. Every example uses synthetic identifiers and local
fixtures.

## POC boundary

This is a KISS (Keep It Short and Stupid) learning POC, not an enterprise
platform. Each change should demonstrate one operator outcome with the fewest
moving parts. The SecCop multi-source scan is fixture-backed by default; the
separate DEMO preparation script can create small, tagged S3/ECR baselines for
an approved live rehearsal. The existing EC2 path remains the authoritative
server remediation lane. GuardDuty, real malware, new networking, broad IAM,
and AgentCore are not required for this POC.

## Issue 1: secure agent harness

The first experiment separates an untrusted plan-producing model from a
deterministic harness:

```text
user request
  -> model proposes a typed plan
  -> policy validates every proposed tool call
  -> harness stops if any call is denied
  -> narrow read-only tool reads synthetic data
  -> typed result and evidence
```

The local `ScriptedModel` is not an LLM. It makes the model boundary runnable
without an API key or paid service. A real probabilistic model can later
implement the same protocol, but it never receives direct tool authority.

The Issue 1 tools can only read:

- a synthetic security finding;
- synthetic workload metadata;
- a synthetic patching SOP.

Issue 2 adds one local sanitization slice: a synthetic AWS-shaped instance
record is reduced to an alias-only view before it becomes model-visible. No AWS
SDK or live account is used.

Unknown tools, mutation proposals, malformed arguments, and unknown fixture
IDs fail closed.

## Run locally

```bash
uv sync --extra dev
uv run pytest -q
uv run python -m secure_agent_harness.demo
```

No AWS account, API key, network service, or real security data is required.
`uv.lock` pins the resolved learning environment.

## Issue 5: local Inspector-to-SSM visual proof

The first FAST POC milestone is local and synthetic. Start the dependency-free
browser server with:

```bash
uv run python -m secure_agent_harness.poc_server
```

Open `http://127.0.0.1:8765`, enter the synthetic CVE
`CVE-2099-0001`, and run the triage. The page shows the Inspector, instance,
SSM readiness, and patch-compliance checks, then requires Approve or Reject.
Approval records a no-op mock remediation; it never calls SSM or changes a
fixture. See [docs/FAST_POC_ADAPTATION.md](docs/FAST_POC_ADAPTATION.md) for
the reuse boundary and the gates before any AWS work.

The interface is a ChatGPT-style local workspace with a conversation view,
tool activity cards, structured evidence cards, and inline approval controls.
If port `8765` is already occupied, use `POC_PORT=8766 uv run python -m
secure_agent_harness.poc_server` and open `http://127.0.0.1:8766`.

Milestone 2 also includes a client-injected read-only Inspector/EC2/SSM
evidence adapter in `secure_agent_harness.aws_read_only`. Its fake-client
tests prove exact finding binding, required tags, SSM readiness, and
fail-closed reason codes. It also projects sanitized Inspector package data and
SSM `AWS:PatchSummary` counts when explicitly requested. The browser has an
**Upload read-only evidence** control: it validates a sanitized result and
never accepts raw AWS payloads or model text.

The repo-owned `scripts/issue5_live_lab.py` is the bounded live-lab operator:

```bash
# read-only preflight; every target boundary is explicit
uv run python scripts/issue5_live_lab.py plan \
  --image-id AMI_ID \
  --image-owner IMAGE_OWNER \
  --subnet-id SUBNET_ID \
  --security-group-id SG_ID \
  --iam-instance-profile PROFILE_NAME

# only after the plan is READY and the same-day TTL is accepted
uv run python scripts/issue5_live_lab.py apply ... --confirm

# exact-target, read-only Inspector + EC2 + SSM evidence
uv run python scripts/issue5_live_lab.py collect --cve-id CVE-YYYY-NNNN

# exact tagged target only; explicit cleanup confirmation is required
uv run python scripts/issue5_live_lab.py cleanup --confirm
```

The historical Issue 5 operator remains private-only and refuses public
networking. The current Project1 SecCop lane is owned by
`infra/project1-seccop-shared/` and `infra/project1-seccop-ec2/`: it reuses the
existing shared public VPC, keeps one SSM profile, and holds one tagged demo
target. Cleanup destroys only the EC2 stack; the shared VPC and profile remain.

The persistent **SecCop** demo lane is documented in
[docs/SECCOP_LIVE_DEMO.md](docs/SECCOP_LIVE_DEMO.md). Its simple GUI accepts
one typed package advisory, discovers the tagged lab server without asking for
an EC2 ID, checks the package through SSM, and waits for explicit approval
before the one-package update. No reboot is requested. The older Inspector CSV
route remains available under the technical panel. The GovTech PlatformAI
handoff is consumed through the sibling `govtechai` repository's `gtx`
launcher, never through a key in this repository.

The operator-facing multi-source POC is documented in
[docs/SECCOP_OPERATOR_DEMO.md](docs/SECCOP_OPERATOR_DEMO.md). One Scan action
shows server, stored-artifact, and container findings. Only the server card
can open the existing real approval and SSM path; the other two are explicitly
read-only suggestions. The composer also starts with a one-CVE check: paste a
single CVE to see which of the three demo sources contains it. This lookup is
read-only and does not start approval or remediation.

The latest browser proof is in the
[SecCop DEMO evidence report](docs/evidence/seccop-demo/report.md), with
sanitized screenshots beside it.

To reproduce the local browser proof with the existing Windows Chrome and
`playwright-core` installation, run:

```bash
./scripts/browser-e2e.sh
```

The runner saves JSON evidence in the operator-local temporary evidence area,
copies review screenshots to the requested Windows folder, and cleans up only
the app and browser profile it created.

## Repeatable three-source DEMO

Issue 32 adds guarded start and cleanup commands for the approved live
rehearsal. The normal operator path is one command:

```bash
./scripts/demo-ready.sh
```

Invoking that exact script is the bounded startup authorization. It does not
ask for a second confirmation. It prepares and verifies the three findings,
starts or reuses the AWS-backed GUI in tmux, and prints the URL. It performs no
remediation and no cleanup. If a previous demo already fixed the disposable
server, it may recycle only that tagged EC2 target from the pinned old AMI so
the server finding is ready again; shared infrastructure is retained.

Internally, `start-demo.sh` applies the existing Terraform EC2 stack with a
pinned older Amazon Linux 2 image, waits for a scan-only Patch Manager summary,
then creates or refreshes two small versioned S3 buckets and one ECR repository
with known old and clean artifacts. It does not enable GuardDuty or create
network resources.

Lower-level operator and validation commands remain available:

```bash
./scripts/start-demo.sh --profile vagent --region ap-southeast-1 --confirm
uv run python scripts/seccop_demo.py scan --profile vagent --region ap-southeast-1
uv run python scripts/seccop_demo.py verify --profile vagent --region ap-southeast-1 --confirm
./scripts/cleanup-demo.sh --profile vagent --region ap-southeast-1 --confirm
```

The lower-level first command is the preparation mutation. The cleanup command creates
Terraform destroy plans and removes only the three tagged demo EC2 targets,
their dedicated security groups, and the tag-owned S3/ECR artifacts. The shared
VPC and SSM profile are never owned by these commands. S3 and ECR fixes remain
explicit commands with `--confirm`; the EC2 package remains behind the
existing SecCop approval screen. `verify` runs one bounded S3/ECR fix and clean
rescan rehearsal, then restores the non-compliant baseline. Evidence is written
under the operator-local `~/.AGENTS-temp/` directory and contains aliases rather
than AWS identifiers.

## Learning vocabulary

- **LLM:** a probabilistic model that may propose a plan. No real LLM is used
  yet.
- **Agent:** the plan-producing model adapter plus its instructions.
- **Harness:** deterministic code that validates, authorizes, dispatches, and
  records tool use.
- **Tool contract:** the typed input, typed output, and narrow behavior a tool
  promises.
- **Fail closed:** uncertainty or invalid input means no tool executes.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the control flow and
[docs/LEARNING_LOG.md](docs/LEARNING_LOG.md) for evidence.
