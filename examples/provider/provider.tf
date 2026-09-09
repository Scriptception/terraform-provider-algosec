terraform {
  required_version = ">= 1.11.0"
  required_providers {
    algosec = {
      source  = "Scriptception/algosec"
      version = "= 0.1.4"
    }
  }
}

provider "algosec" {
  # Set ALGOSEC_URL and ALGOSEC_SESSION_ID, or ALGOSEC_USERNAME/ALGOSEC_PASSWORD.
  # This initial provider is not published. See docs/user-testing.md for ZIP mirror installation.
  # A33.20 EA groups only: experimental_device_groups = true.
  # AlgoSec does not recommend these group APIs for production.
  read_only = true
  insecure  = false
}
