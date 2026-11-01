# Use exact server destination spelling and exclusive ownership.
resource "algosec_ace_threat_list_entry" "exception" {
  threat_type = "domains"
  list_type   = "allow-list"
  destination = "example.invalid"
  description = "Approved example domain"
}
