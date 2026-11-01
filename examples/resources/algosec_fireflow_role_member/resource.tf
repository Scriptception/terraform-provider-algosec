provider "algosec" {
  # Set ALGOSEC_FIREFLOW_URL and ALGOSEC_FIREFLOW_SESSION externally.
  experimental_fireflow_bindings = true
  read_only                      = false
}

resource "algosec_fireflow_role_member" "example" {
  role_id     = 42
  member_id   = 101
  member_type = "User"
}
