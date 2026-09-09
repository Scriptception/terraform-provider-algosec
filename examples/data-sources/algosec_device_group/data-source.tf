# EXPERIMENTAL ASMS A33.20 Early Availability; vendor does not recommend production use.
provider "algosec" {
  experimental_device_groups = true
  read_only                  = true
}

data "algosec_device_group" "example" {
  display_name = "Example Group"
}
