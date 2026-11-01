provider "algosec" {
  # Set ALGOSEC_FIREFLOW_URL and ALGOSEC_FIREFLOW_SESSION externally.
  experimental_fireflow_bindings = true
  read_only                      = false
}

resource "algosec_fireflow_role_permission" "example" {
  role_id         = 42
  permission_name = "VIEW_CHANGE_REQUESTS"
  object_type     = "System"
  object_id       = 0
}
