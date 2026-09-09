provider "algosec" {
  # Set ALGOSEC_URL and ALGOSEC_SESSION_ID outside configuration.
  experimental_tags = true
  read_only         = false
}

resource "algosec_tag" "example" {
  name  = "Example department"
  scope = "Department"
}
