# Project1 shared SecCop IAM

This stack creates the one reusable EC2 instance profile needed by the
Security Copilot learning targets. It does not create or manage networking.

The role and instance profile are intentionally retain-protected. Disposable
EC2 stacks may reference the profile, while VPCs, subnets, routes, and the
profile remain available to other repositories.

```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Use the `vagent` profile in `ap-southeast-1`. Do not store credentials or
generated Terraform state in the repository.
