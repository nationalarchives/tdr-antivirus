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

module "upload_bucket" {
  source      = "./tdr-terraform-modules/s3"
  project     = "tdr"
  function    = "antivirus-test-files"
  common_tags = local.common_tags
  access_logs = false
}
