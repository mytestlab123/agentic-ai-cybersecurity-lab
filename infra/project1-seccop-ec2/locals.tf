locals {
  required_tags = {
    Name        = var.name
    Project     = "Security Copilot"
    project     = "Security Copilot"
    Repo        = "agentic-ai-cybersecurity-lab"
    dev         = "amit"
    created     = "2026-08-26"
    tools       = "cdx"
    environment = "dev"
    Environment = "seccop-demo"
    owner       = "amit"
    version     = "seccop-project1-r01"
    TTL         = var.ttl
    Purpose     = "Inspector-to-SSM old-package learning demo"
    purpose     = "Inspector-to-SSM old-package learning demo"
    phase       = "seccop-project1-demo"
    Cleanup     = "terminate-ec2-only"
  }
}
