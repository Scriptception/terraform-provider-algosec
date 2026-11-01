variable "jira_api_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

# Replacement loses alert-ticket associations; Jira tickets are not deleted.
# Do not use create_before_destroy. Write-only arguments require Terraform >= 1.11; saved-plan ephemeral examples require Terraform >= 1.16.1.
resource "algosec_ace_jira_integration" "alerts" {
  server_url          = "https://example.atlassian.net"
  user_name           = "security@example.invalid"
  project_key         = "SEC"
  default_issue_type  = "Task"
  default_priority    = "High"
  api_token_wo        = var.jira_api_token
  replacement_version = "1"
}
