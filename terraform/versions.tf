terraform {
  backend "s3" {
    bucket         = "tdr-terraform-state"
    key            = "antivirus.state"
    region         = "eu-west-2"
    encrypt        = true
    dynamodb_table = "tdr-terraform-state-lock"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.72"
    }
  }
  required_version = ">= 1.1.3"
}
