output "vpc_id" {
  description = "Private lab VPC ID."
  value       = aws_vpc.lab.id
}

output "private_subnet_id" {
  description = "Private subnet for the exact Inspector host target."
  value       = aws_subnet.private.id
}

output "instance_security_group_id" {
  description = "No-ingress security group for the exact Inspector host target."
  value       = aws_security_group.instance.id
}

output "endpoint_security_group_id" {
  description = "Security group attached to the three private SSM endpoints."
  value       = aws_security_group.endpoints.id
}

output "interface_endpoint_ids" {
  description = "Private interface endpoints for Inspector and SSM services."
  value       = { for service, endpoint in aws_vpc_endpoint.interface : service => endpoint.id }
}

output "s3_endpoint_id" {
  description = "Private S3 gateway endpoint used for Amazon Linux repository access."
  value       = aws_vpc_endpoint.s3.id
}
