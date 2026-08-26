# Project1 disposable SecCop EC2

This stack reuses the existing Project1 default public VPC. It creates only a
dedicated no-ingress security group and one SSM-managed Amazon Linux 2 target.
The VPC, subnet, route table, Internet Gateway, and shared SSM profile are not
owned by this stack and must remain in place.

Public exposure is deliberate and approved for this disposable learning lane:

`Public exposure check: IGW=yes (existing/approved), NAT=no, public subnet=yes (existing/approved), public IP=yes (approved), EIP=no, internet-facing LB=no, default route to IGW=yes (existing/approved)`

There is no inbound SSH or RDP rule. Use SSM after the instance registers.

Apply:

```bash
terraform init
terraform fmt -check
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

Destroy only the disposable target and its dedicated security group:

```bash
terraform plan -destroy -out=destroy.tfplan
terraform apply destroy.tfplan
```

Use profile `vagent` and region `ap-southeast-1`. Keep generated state and
outputs outside the repository.
