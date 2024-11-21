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
      version = ">= 5.76.0"
    }
  }
  required_version = ">= 1.9.8"
}
