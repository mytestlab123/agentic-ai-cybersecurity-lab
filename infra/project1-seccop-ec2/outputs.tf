output "instance_id" {
  description = "Disposable SecCop target instance ID."
  value       = aws_instance.target.id
}

output "instance_private_ip" {
  description = "Private address for local evidence only."
  value       = aws_instance.target.private_ip
}

output "instance_public_ip" {
  description = "Public address for local evidence only."
  value       = aws_instance.target.public_ip
}

output "security_group_id" {
  description = "Dedicated target security group ID."
  value       = aws_security_group.target.id
}

output "ami_id" {
  description = "Selected Amazon Linux 2 AMI ID."
  value       = data.aws_ami.amazon_linux_2.id
}
