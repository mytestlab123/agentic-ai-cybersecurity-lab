variable "profile" {
  description = "AWS CLI profile for the personal lab account."
  type        = string
  default     = "amit"
}

variable "region" {
  description = "AWS region for the private lab VPC."
  type        = string
  default     = "ap-southeast-1"
}

variable "availability_zone" {
  description = "One AZ is sufficient for this short-lived learning lane."
  type        = string
  default     = "ap-southeast-1a"
}

variable "vpc_cidr" {
  description = "Non-overlapping lab CIDR selected after current-account discovery."
  type        = string
  default     = "10.250.0.0/16"
}

variable "private_subnet_cidr" {
  description = "Private subnet CIDR for the disposable Inspector host."
  type        = string
  default     = "10.250.1.0/24"
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

variable "revision" {
  description = "Repo revision or lane version marker."
  type        = string
  default     = "seccop-demo-r01"
}
