# SecCop private SSM VPC

This stack creates one persistent, private-only Singapore VPC for the
Security Copilot Inspector-to-SSM demo lane. It remains until Amit explicitly
approves the repo-owned cleanup command:

- one VPC and one private subnet;
- no Internet Gateway, NAT Gateway, public route, or public IP mapping;
- no-ingress instance security group;
- five interface endpoints: `inspector2`, `inspector-scan`, `ssm`,
  `ssmmessages`, and `ec2messages`;
- one private S3 gateway endpoint for Amazon Linux repository metadata;
- required agent tags, including `project=Security Copilot` and `TTL=01-09-26`.

Public exposure check: IGW=no, NAT=no, public subnet=no, public IP=no, EIP=no,
internet-facing LB=no, default route to IGW/NAT=no

The CIDR was selected after checking current `amit` VPCs in Singapore and
Mumbai. Existing VPCs used overlapping `172.30.0.0/16` or `172.31.0.0/16`
ranges and had no private SSM endpoint path.

## Apply and destroy

Run from this directory with the personal `amit` profile only:

```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

After Amit's browser demo is complete, use the same local state and destroy
the exact stack:

```bash
terraform plan -destroy -out=destroy.tfplan
terraform apply destroy.tfplan
```

Do not use a broad account cleanup. Keep raw Terraform state and AWS outputs
outside the public repository; `.gitignore` excludes them.

## Reference

The sibling `/home/user/git/localai` repo records the earlier Singapore
private-subnet SSM readiness failure in `PLANS.md` and the follow-up recommendation
to use interface endpoints in `plans/cloud/aws/aws-ec2-proof-execution-checklist.md`.
This stack addresses that exact missing path without copying its stale resource
IDs or using public SSM access.
