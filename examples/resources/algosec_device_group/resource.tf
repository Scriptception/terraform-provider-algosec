# EXPERIMENTAL ASMS A33.20 Early Availability; vendor does not recommend production use.
provider "algosec" {
  # Supply credentials through ALGOSEC_* environment variables.
  experimental_device_groups = true
  read_only                  = false
}

resource "algosec_device_group" "example" {
  display_name = "Example Group"
  members      = ["Example Firewall A", "Example Firewall B"]
}
