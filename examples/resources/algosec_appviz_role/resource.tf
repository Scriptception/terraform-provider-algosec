# Requires provider 0.3.0 or later; 0.2.0 lacks this resource.
# Configure ALGOSEC_APPVIZ_SAAS_URL and ALGOSEC_APPVIZ_SAAS_TOKEN in the environment.
provider "algosec" {
  experimental_appviz_roles   = true
  appviz_whole_role_ownership = true
  read_only                   = false
}

resource "algosec_appviz_role" "example" {
  name        = "Example application reviewers"
  enabled     = true
  users       = []
  permissions = []
  # Keys are application REVISION IDs, not stable application IDs.
  application_permissions = {}
}
