data "aws_iam_policy" "ssm_managed_core" {
  arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "seccop" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  lifecycle {
    prevent_destroy = true
  }

  tags = local.required_tags
}

resource "aws_iam_role_policy_attachment" "ssm_managed_core" {
  role       = aws_iam_role.seccop.name
  policy_arn = data.aws_iam_policy.ssm_managed_core.arn
}

resource "aws_iam_instance_profile" "seccop" {
  name = var.role_name
  role = aws_iam_role.seccop.name

  lifecycle {
    prevent_destroy = true
  }

  tags = local.required_tags
}
