# Configure the provider with read_only = false to apply.
resource "algosec_url_category" "example" {
  name = "tf-example-services"
  urls = {
    "service.example.invalid" = ["192.0.2.10", "2001:db8::10"]
  }
}
