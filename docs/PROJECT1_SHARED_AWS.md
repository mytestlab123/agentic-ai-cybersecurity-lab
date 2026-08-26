# Project1 shared AWS lab context

This repository uses the existing Project1 learning account only for the
disposable Security Copilot demo. The network is shared; the demo compute is
not.

## Canonical local access

- AWS CLI profile: `vagent`
- IAM user represented by that profile: `project1`
- Region: `ap-southeast-1` (Singapore)
- Credentials live only in the operator's `~/.aws/credentials` file.
- Do not copy keys into this repository or create a second credential copy
  under another profile name.

The profile name and IAM user name are different. Other repositories should
use the same local profile:

```bash
export AWS_PROFILE=vagent
export AWS_REGION=ap-southeast-1
aws sts get-caller-identity
```

Before any mutation, verify that the caller is the Project1 learning account.
If the identity is different, stop.

## Shared network contract

Singapore already has a shared default VPC with public subnets and an Internet
Gateway. Reuse it; do not create, delete, or repoint its VPC, subnets, route
tables, or Internet Gateway for this demo.

The shared network is infrastructure for multiple repositories. A repository
may read it and launch a tagged, disposable EC2 target in an existing public
subnet, subject to the account owner's approval.

## Disposable demo contract

The only expected per-demo AWS resources are:

- one EC2 instance;
- one dedicated security group for that instance; and
- optional read-only evidence objects approved for the run.

The security group must have no inbound rules. Outbound HTTPS is allowed only
for the approved demo path. No SSH key or inbound administrative port is
needed; use SSM when the target is managed and online.

Required tags include `project=Security Copilot`, `owner=amit`,
`environment=dev`, `tools=cdx`, a short `TTL`, and a unique `Name`. Add a
cleanup marker such as `cleanup=terminate-ec2-only`.

At the end of the demo, terminate the exact tagged EC2 instance and remove
its dedicated security group when no longer referenced. Leave the shared VPC,
public subnets, routes, and Internet Gateway intact.

## Read-only preflight

```bash
AWS_PROFILE=vagent AWS_REGION=ap-southeast-1 aws sts get-caller-identity
AWS_PROFILE=vagent AWS_REGION=ap-southeast-1 aws ec2 describe-vpcs
AWS_PROFILE=vagent AWS_REGION=ap-southeast-1 aws ec2 describe-subnets
AWS_PROFILE=vagent AWS_REGION=ap-southeast-1 aws ssm describe-instance-information
```

The concrete resource IDs belong in local evidence under
`~/.AGENTS-temp/agentic-ai-cybersecurity-lab/`, not in this public repository.

## Ownership and cleanup rule

Every repository or agent must identify its own EC2 and security group by
tags before changing or deleting anything. Never use a broad account-wide
termination or VPC cleanup command. The shared VPC is retained for future
SecCop and other learning repositories.

This file is the sanitized, repository-level contract. The operator-local
environment notes at `~/.codex/dev_env.md` may contain account-specific IDs;
those notes must never be committed here.
