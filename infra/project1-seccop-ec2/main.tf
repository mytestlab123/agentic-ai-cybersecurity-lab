resource "aws_security_group" "target" {
  name        = "${var.name}-sg"
  description = "No-ingress SecCop demo target; outbound HTTPS only"
  vpc_id      = data.aws_vpc.shared.id

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
    cidr_blocks = [data.aws_vpc.shared.cidr_block]
  }

  egress {
    description = "TCP DNS fallback to the VPC resolver"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.shared.cidr_block]
  }

  tags = {
    Name = "${var.name}-sg"
  }
}

resource "aws_instance" "target" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnet.public.id
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

  tags = {
    Name      = var.name
    Project   = "Security Copilot"
    Repo      = "agentic-ai-cybersecurity-lab"
    Issue     = "17"
    Cleanup   = "terminate-ec2-only"
    Purpose   = "Inspector-to-SSM old-package learning demo"
    ExpiresAt = "2026-09-01T23:59:00+08:00"
  }
}
