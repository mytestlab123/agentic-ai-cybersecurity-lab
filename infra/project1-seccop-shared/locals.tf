locals {
  required_tags = {
    Name        = var.role_name
    dev         = "amit"
    project     = "Security Copilot"
    created     = "2026-08-26"
    tools       = "cdx"
    environment = "dev"
    owner       = "amit"
    version     = "seccop-project1-r01"
    TTL         = var.ttl
    purpose     = "shared SSM access for disposable Security Copilot targets"
    phase       = "seccop-project1-shared"
  }
}
