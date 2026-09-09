// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"fmt"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/Scriptception/terraform-provider-algosec/internal/testserver"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"os"
	"regexp"
	"testing"
)

// These are Terraform CLI/protocol lifecycle tests against a controlled SYNTHETIC
// HTTPS server. They are NOT live-appliance acceptance tests.
var factories = map[string]func() (tfprotov6.ProviderServer, error){"algosec": providerserver.NewProtocol6WithError(New("test")())}

func config(s *testserver.Server, readonly bool) string {
	return fmt.Sprintf(`provider "algosec" {
 url = %q
 session_id = %q
 insecure = true
 read_only = %t
}
`, s.URL, testserver.Session, readonly)
}
func categoryConfig(s *testserver.Server, name, ip string) string {
	return config(s, false) + fmt.Sprintf(`resource "algosec_url_category" "test" {
 name = %q
 urls = { "service.example.invalid" = [%q] }
}
`, name, ip)
}
func requireTerraform(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		t.Skip("set TF_ACC_TERRAFORM_PATH to the local Terraform executable to run synthetic CLI lifecycle tests")
	}
}
func TestProtocolCategoryLifecycle(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		s.Mu.Lock()
		defer s.Mu.Unlock()
		if len(s.Categories) != 0 {
			return fmt.Errorf("synthetic category leaked")
		}
		return nil
	}, Steps: []resource.TestStep{
		{Config: categoryConfig(s, "tf-test a/b?%", "192.0.2.1"), Check: resource.ComposeTestCheckFunc(resource.TestCheckResourceAttr("algosec_url_category.test", "id", "tf-test a/b?%"), resource.TestCheckResourceAttr("algosec_url_category.test", "urls.%", "1"))},
		{ResourceName: "algosec_url_category.test", ImportState: true, ImportStateVerify: true},
		{Config: categoryConfig(s, "tf-test renamed/雪", "192.0.2.1"), Check: resource.TestCheckResourceAttr("algosec_url_category.test", "id", "tf-test renamed/雪")},
		{Config: categoryConfig(s, "tf-test renamed/雪", "198.51.100.2"), Check: resource.TestCheckResourceAttr("algosec_url_category.test", "urls.service.example.invalid.#", "1")},
		{PreConfig: func() { s.Mu.Lock(); delete(s.Categories, "tf-test renamed/雪"); s.Mu.Unlock() }, Config: categoryConfig(s, "tf-test renamed/雪", "198.51.100.2")},
	}})
}
func TestProtocolDataSources(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	s.Devices["ExampleDevice"] = client.Device{Name: "ExampleDevice", DisplayName: "Example Device", NodeType: "FW_FILE"}
	s.Categories["ExampleCategory"] = client.Category{URLs: map[string][]string{"service.example.invalid": {"192.0.2.1"}}}
	cfg := config(s, true) + `
data "algosec_devices" "test" {}
data "algosec_device" "test" { name = "ExampleDevice" }
data "algosec_url_categories" "test" {}
data "algosec_url_category" "test" { name = "ExampleCategory" }
data "algosec_risk_profiles" "test" {}
data "algosec_risk_profile_files" "test" {}
data "algosec_security_zones" "test" { profile_file = "example.xlsx" }
data "algosec_device_zones" "test" { device_name = "ExampleDevice" }
data "algosec_network_objects" "test" {
 device_name = "ExampleDevice"
 query = ""
}
data "algosec_trusted_traffic" "test" { device_name = "ExampleDevice" }
`
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{{Config: cfg, Check: resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttr("data.algosec_devices.test", "devices.#", "1"),
		resource.TestCheckResourceAttr("data.algosec_device.test", "device.name", "ExampleDevice"),
		resource.TestCheckResourceAttr("data.algosec_url_categories.test", "categories.#", "1"),
		resource.TestCheckResourceAttr("data.algosec_url_category.test", "name", "ExampleCategory"),
		resource.TestCheckResourceAttr("data.algosec_risk_profiles.test", "names.#", "1"),
		resource.TestCheckResourceAttr("data.algosec_risk_profile_files.test", "names.#", "1"),
		resource.TestCheckResourceAttr("data.algosec_security_zones.test", "zones.#", "1"),
		resource.TestCheckResourceAttr("data.algosec_device_zones.test", "zones.#", "1"),
		resource.TestCheckResourceAttr("data.algosec_network_objects.test", "objects.0.id", "1"),
		resource.TestCheckResourceAttr("data.algosec_trusted_traffic.test", "entries.0.source", "192.0.2.1"),
	)}}})
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.Writes != 0 {
		t.Fatal("read-only data sources performed mutation")
	}
}
func TestProtocolReadOnly(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	cfg := config(s, true) + `resource "algosec_url_category" "test" {
 name="tf-test"
 urls={}
}
`
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{{Config: cfg, ExpectError: regexp.MustCompile("read_only")}}})
	if s.Writes != 0 {
		t.Fatal("read_only allowed mutation")
	}
}
func TestProtocolInvalidIP(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{{Config: categoryConfig(s, "test", "not-an-ip"), ExpectError: regexp.MustCompile("IP values must")}}})
}
func TestProtocolUnknownPlan(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	cfg := config(s, false) + `
resource "terraform_data" "test" { input = "192.0.2.1" }
resource "algosec_url_category" "test" {
 name = "tf-unknown"
 urls = { "service.example.invalid" = [terraform_data.test.output] }
}
`
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{{Config: cfg}}})
}
func TestProtocolSchema(t *testing.T) {
	p := providerserver.NewProtocol6(New("test")())()
	s, err := p.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range s.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatal(d.Summary, d.Detail)
		}
	}
	for _, name := range []string{"algosec_url_category", "algosec_device_group", "algosec_trusted_rule", "algosec_appviz_role", "algosec_tag", "algosec_url_ip_membership", "algosec_fireflow_role_member", "algosec_fireflow_role_permission"} {
		if _, ok := s.ResourceSchemas[name]; !ok {
			t.Fatalf("missing resource schema %s", name)
		}
	}
	if len(s.ResourceSchemas) != 12 || len(s.DataSourceSchemas) != 12 {
		t.Fatalf("unexpected surface: %d/%d", len(s.ResourceSchemas), len(s.DataSourceSchemas))
	}
}

func TestProtocolNullURLSet(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	cfg := config(s, false) + `resource "algosec_url_category" "test" {
 name = "tf-null"
 urls = { "service.example.invalid" = null }
}
`
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{{Config: cfg, ExpectError: regexp.MustCompile("non-null set")}}})
}

func TestProtocolRefreshErrorPreservesIdentity(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	cfg := categoryConfig(s, "tf-retain", "192.0.2.1")
	resource.UnitTest(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{
		{Config: cfg},
		{PreConfig: func() { s.Mu.Lock(); s.FailReads = true; s.Mu.Unlock() }, Config: cfg, PlanOnly: true, ExpectError: regexp.MustCompile("HTTP 503")},
		{PreConfig: func() { s.Mu.Lock(); s.FailReads = false; s.Mu.Unlock() }, Config: cfg, Check: resource.TestCheckResourceAttr("algosec_url_category.test", "id", "tf-retain")},
	}})
}
