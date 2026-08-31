# Specification

## Current scope

Build a KISS Security Copilot POC with a typed deterministic harness, local
synthetic fixtures, and one bounded Project1 AWS DEMO. The AWS DEMO presents
three non-compliant sources in one operator journey: an EC2 package summary, a
stored S3 artifact, and an ECR image.

## Required behavior

- The model may only propose tool calls.
- The deterministic policy validates the complete plan before execution.
- Unknown, malformed, or mutation-capable calls block the whole plan.
- Tool results are typed and evidence is returned to the caller.
- Tests cover a normal request and an unsafe mutation request.

## Issue 2 local slice

- A synthetic AWS-shaped instance response is read through an allow-listed
  local tool.
- Deterministic sanitization exposes only an alias, synthetic environment,
  normalized state, and coarse size class.
- Raw instance, network, DNS, tag, and profile values never reach the typed
  result returned to the model boundary.

## Stop gates

- No real LLM or paid API.
- No real identifiers or private data.
- No AgentCore, GuardDuty, malware, new networking, or broad IAM.
- A model proposal is never authorization.
- Real package remediation, reboot, and cleanup remain separate operator
  actions; DEMO preparation never performs them.

## One-command AWS DEMO readiness

The canonical operator command is:

```bash
./scripts/demo-ready.sh
```

Running this exact repo-owned script is the operator's authorization for the
bounded DEMO startup below. It must not ask for another chat approval or an
interactive confirmation. Its internal call may retain `--confirm` so the
lower-level mutation command remains fail-closed when used directly.

The command is fixed to the existing `vagent` Project1 identity in Singapore.
It may create or refresh only:

- one named, tagged EC2 DEMO target and its no-ingress security group;
- two small, tagged, versioned S3 DEMO buckets; and
- one small, tagged ECR DEMO repository.

It reuses the existing VPC, subnet, and SSM instance profile. It must not
create a VPC, route, internet gateway, NAT gateway, load balancer, inbound
rule, IAM role, GuardDuty detector, or any unrelated resource.

If the disposable EC2 target is already compliant after a previous approved
fix, the command may replace only that exact tagged EC2 instance with the
pinned old AMI. This bounded recycle is part of the startup authorization so
the next DEMO again has one server finding. It must preserve the dedicated
security group and every shared resource.

Before returning `SECCOP_DEMO_READY`, the command must:

1. verify the exact Project1 operator identity and Terraform scope;
2. wait for SSM and a non-empty Patch Manager state;
3. verify exactly three aliased `NON_COMPLIANT` DEMO sources;
4. start or reuse the AWS-backed GUI in the repo-owned tmux window; and
5. verify `http://127.0.0.1:8766/api/health` reports `AWS_DEMO`.

The command is idempotent and saves private evidence under
`~/.AGENTS-temp/agentic-ai-cybersecurity-lab/`. It prints only aliases and
operator-safe state. Any identity mismatch, widened plan, ambiguous source,
unexpected port owner, or missing readiness evidence blocks the run.

## Actions outside startup authorization

- EC2 remediation still requires the exact approval in the SecCop GUI.
- S3 and ECR fixes still require their explicit approval action.
- Cleanup is never automatic. It remains the separate repo-owned command
  `./scripts/cleanup-demo.sh --profile vagent --region ap-southeast-1 --confirm`
  after Amit finishes the DEMO.
- Shared VPC, subnet, and SSM IAM resources are retained by cleanup.
