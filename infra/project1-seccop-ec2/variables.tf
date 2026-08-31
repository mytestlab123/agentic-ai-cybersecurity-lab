variable "profile" {
  description = "AWS CLI profile for the Project1 learning account."
  type        = string
  default     = "vagent"
}

variable "region" {
  description = "AWS region for the disposable target."
  type        = string
  default     = "ap-southeast-1"
}

variable "availability_zone" {
  description = "Existing public-subnet AZ in the shared default VPC."
  type        = string
  default     = "ap-southeast-1a"
}

variable "instance_profile_name" {
  description = "Reusable SSM instance profile created by the shared stack."
  type        = string
  default     = "seccop-project1-ssm-r01"
}

variable "instance_type" {
  description = "Small learning target instance type."
  type        = string
  default     = "t3.small"
}

variable "ami_name_pattern" {
  description = "Pinned older Amazon Linux 2 image pattern for the old-package demo."
  type        = string
  default     = "amzn2-ami-hvm-2.0.20260608.0-x86_64-gp2"
}

variable "name" {
  description = "Unique disposable target name."
  type        = string
  default     = "seccop-project1-inspector-host-r01"
}

variable "ttl" {
  description = "Required cleanup deadline in DD-MM-YY form."
  type        = string
  default     = "01-09-26"

  validation {
    condition     = can(regex("^[0-9]{2}-[0-9]{2}-[0-9]{2}$", var.ttl))
    error_message = "ttl must use DD-MM-YY format."
  }
}

variable "created" {
  description = "Resource creation date in YYYY-MM-DD form. The start wrapper supplies the current date."
  type        = string
  default     = "2026-08-26"

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", var.created))
    error_message = "created must use YYYY-MM-DD format."
  }
}
