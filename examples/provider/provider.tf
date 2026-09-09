terraform {
  required_version = ">= 1.11.0"
  required_providers {
    algosec = {
      source  = "Scriptception/algosec"
      version = "= 0.2.0"
    }
  }
}

provider "algosec" {
  # Set ALGOSEC_URL and ALGOSEC_SESSION_ID, or ALGOSEC_USERNAME/ALGOSEC_PASSWORD.
  # Published v0.2.0: direct Registry installation verified; no live appliance acceptance.
  # A33.20 EA groups only: experimental_device_groups = true.
  # AlgoSec does not recommend these group APIs for production.
  read_only = true
  insecure  = false
}
