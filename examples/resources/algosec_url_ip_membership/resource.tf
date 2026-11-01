provider "algosec" {
  # Set ALGOSEC_URL and ALGOSEC_SESSION_ID outside configuration.
  experimental_url_ip_memberships = true
  read_only                       = false
}

# Existing category and URL, without algosec_url_category ownership.
resource "algosec_url_ip_membership" "example" {
  category = "Example"
  url      = "www.example.com"
  ip       = "192.0.2.1"
}
