# Agentic AI Cybersecurity Lab

A public, personal learning lab for understanding secure agent engineering with
small Python experiments. Every example uses synthetic identifiers and local
fixtures.

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

`plan` refuses public networking, requires a private SSM path, an existing
no-ingress security group, an existing instance profile, an available AMI,
and enabled Inspector EC2 coverage. Current account discovery found no
complete launch plan, so no live instance or AWS mutation has been performed.

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
