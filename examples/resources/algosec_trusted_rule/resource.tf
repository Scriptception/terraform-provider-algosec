# Published v0.2.0 experimental A33.20 public contract; no live appliance acceptance.
# Configure experimental_trusted_rules = true and read_only = false on the provider.
resource "algosec_trusted_rule" "example" {
  device_name = "branch-firewall-01"
  rule_id     = "rule-987"
  comment     = "Reviewed partner access"
  # Optional expiration_date must be a future YYYY-MM-DD when creating.
}
