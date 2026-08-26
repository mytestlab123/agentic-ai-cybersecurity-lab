output "role_name" {
  description = "Reusable EC2 role name."
  value       = aws_iam_role.seccop.name
}

output "instance_profile_name" {
  description = "Reusable EC2 instance profile name."
  value       = aws_iam_instance_profile.seccop.name
}
