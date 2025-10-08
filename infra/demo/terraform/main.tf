terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
# Intentionally minimal placeholder; real misconfigs added later.
provider "aws" {
  region = "us-east-1"
}
