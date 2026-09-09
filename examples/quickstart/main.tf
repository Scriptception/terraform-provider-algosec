terraform {
  required_version = ">= 1.11.0"
  required_providers {
    algosec = {
      source  = "Scriptception/algosec"
      version = "= 0.1.4"
    }
  }
}

# Supply ALGOSEC_URL and one authentication mode through the process environment.
provider "algosec" {
  read_only = true
  insecure  = false
}

data "algosec_devices" "inventory" {}
data "algosec_risk_profiles" "inventory" {}

# Counts avoid printing inventory names; full data still exists in plan/state.
output "device_count" {
  value = length(data.algosec_devices.inventory.devices)
}
output "risk_profile_count" {
  value = length(data.algosec_risk_profiles.inventory.names)
}
