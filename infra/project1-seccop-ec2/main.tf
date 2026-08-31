locals {
  runtime_tags = {
    Project     = "Security Copilot"
    project     = "Security Copilot"
    Repo        = "agentic-ai-cybersecurity-lab"
    dev         = "amit"
    created     = var.created
    tools       = "cdx"
    environment = "dev"
    Environment = "seccop-demo"
    owner       = "amit"
    version     = "seccop-${var.operator}-r01"
    TTL         = var.ttl
    Purpose     = "Inspector-to-SSM old-package learning demo"
    purpose     = "Inspector-to-SSM old-package learning demo"
    phase       = "seccop-${var.operator}-demo"
    Cleanup     = "terminate-ec2-only"
    cleanup     = "delete"
  }
}

resource "aws_security_group" "target" {
  name        = "${var.name}-sg"
  description = "No-ingress SecCop demo target; outbound HTTPS only"
  vpc_id      = data.aws_vpc.selected.id

  egress {
    description = "HTTPS to AWS and package repositories"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "UDP DNS to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  egress {
    description = "TCP DNS fallback to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  tags = merge(local.runtime_tags, { Name = "${var.name}-sg" })
}

resource "aws_instance" "target" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnet.selected.id
  vpc_security_group_ids      = [aws_security_group.target.id]
  iam_instance_profile        = data.aws_iam_instance_profile.shared.name
  associate_public_ip_address = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    encrypted             = true
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  volume_tags = merge(local.runtime_tags, { Name = "${var.name}-root" })

  tags = merge(local.runtime_tags, {
    Name      = var.name
    Issue     = var.issue
    ExpiresAt = var.expires_at
  })
}
