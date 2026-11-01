variable "aws_role_arn" {
  type      = string
  sensitive = true
  ephemeral = true
}
variable "aws_external_id" {
  type      = string
  sensitive = true
  ephemeral = true
}

# Manual registration/name only, not drift-managed access configuration.
# Bootstrap fields are submission-only. Write-only arguments require Terraform >= 1.11; saved-plan ephemeral examples require Terraform >= 1.16.1.
resource "algosec_ace_cloud_account_registration" "aws" {
  cloud_provider      = "aws"
  account_id          = "123456789012"
  name                = "Example manual account"
  unified_onboarding  = true
  role_arn_wo         = var.aws_role_arn
  external_id_wo      = var.aws_external_id
  support_changes_wo  = false
  flow_logs_wo        = false
  replacement_version = "1"
}
