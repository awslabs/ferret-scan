# Terraform + provider version constraints.
#
# Pinned to 1.5+ for the `nullable = false` variable validation feature
# we use in variables.tf. AWS provider pinned to 5.x because the
# `aws_apigatewayv2_*` resources moved out of beta in 5.0 and the
# 6.x preview introduced unrelated breaking changes that aren't worth
# tracking for a v1 example.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
