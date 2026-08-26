variable "profile" {
  description = "AWS CLI profile for the Project1 learning account."
  type        = string
  default     = "vagent"
}

variable "region" {
  description = "AWS region for the shared Project1 resources."
  type        = string
  default     = "ap-southeast-1"
}

variable "role_name" {
  description = "Reusable EC2 role name for SSM-managed demo targets."
  type        = string
  default     = "seccop-project1-ssm-r01"
}

variable "ttl" {
  description = "Review date for the learning-account shared role."
  type        = string
  default     = "01-09-26"

  validation {
    condition     = can(regex("^[0-9]{2}-[0-9]{2}-[0-9]{2}$", var.ttl))
    error_message = "ttl must use DD-MM-YY format."
  }
}
