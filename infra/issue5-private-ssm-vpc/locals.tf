locals {
  name = "seccop-private-ssm-vpc-r01"

  required_tags = {
    Name        = local.name
    dev         = "amit"
    project     = "Security Copilot"
    created     = "2026-08-25"
    tools       = "cdx"
    environment = "dev"
    owner       = "amit"
    version     = var.revision
    TTL         = var.ttl
    purpose     = "persistent Security Copilot Inspector to SSM demo"
    phase       = "seccop-live-demo"
  }

  interface_services = toset([
    "inspector2",
    "inspector-scan",
    "ssm",
    "ssmmessages",
    "ec2messages",
  ])
}
