terraform {
  required_version = "~> 1.15.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.76.0"
    }
  }
}

provider "aws" {
  profile = var.profile
  region  = var.region

  default_tags {
    tags = local.required_tags
  }
}
