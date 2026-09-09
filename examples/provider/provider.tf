terraform {
  required_version = ">= 1.11.0"
  required_providers {
    algosec = {
      source = "Scriptception/algosec"
    }
  }
}

provider "algosec" {
  # Set ALGOSEC_URL and ALGOSEC_SESSION_ID, or ALGOSEC_USERNAME/ALGOSEC_PASSWORD.
  # This initial provider is not published. See README for local dev overrides.
  # A33.20 EA groups only: experimental_device_groups = true.
  # AlgoSec does not recommend these group APIs for production.
  read_only = true
}
