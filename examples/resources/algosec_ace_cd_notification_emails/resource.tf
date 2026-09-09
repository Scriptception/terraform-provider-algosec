# Requires separate ACE bearer configuration and experimental_ace_public_contracts.
resource "algosec_ace_cd_notification_emails" "alerts" {
  cloud_provider = "aws"
  emails         = ["security@example.invalid"]
}
