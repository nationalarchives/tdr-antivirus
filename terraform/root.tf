data "aws_ssm_parameter" "cost_centre" {
  name = "/mgmt/cost_centre"
}

locals {
  environment = "mgmt"
  aws_region  = var.default_aws_region
  common_tags = tomap(
  {
    "Environment"     = local.environment,
    "Owner"           = "TDR",
    "Terraform"       = true,
    "TerraformSource" = "https://github.com/nationalarchives/tdr-jenkins/tree/master/terraform",
    "CostCentre"      = data.aws_ssm_parameter.cost_centre.value
  }
  )
}

provider "aws" {
  region = local.aws_region
}

variable "default_aws_region" {
  default = "eu-west-2"
}

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

module "upload_bucket" {
  source      = "./tdr-terraform-modules/s3"
  project     = "tdr"
  function    = "antivirus-test-files"
  common_tags = local.common_tags
  access_logs = false
}
