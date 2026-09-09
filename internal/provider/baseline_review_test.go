package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/testserver"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Only synthetic localhost HTTPS; these tests never call TestAcc or an appliance.
func TestBaselineCategoryKnownInvalidWithUnknownReplacement(t *testing.T) {
	requireTerraform(t)
	s := testserver.New()
	defer s.Close()
	good := categoryConfig(s, "owned", "192.0.2.1")
	bad := config(s, false) + `resource "terraform_data" "ip" { input = "198.51.100.1" }
 resource "algosec_url_category" "test" {
 name = "owned"
 urls = { "service.example.invalid" = ["NOT-AN-IP", terraform_data.ip.output] }
 }`
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
		{Config: good},
		{Config: bad, ExpectError: regexp.MustCompile("IP values must")},
		{PreConfig: func() {
			s.Mu.Lock()
			defer s.Mu.Unlock()
			if _, ok := s.Categories["owned"]; !ok {
				t.Error("invalid replacement DELETED previously owned category")
			}
		}, Config: good},
	}})
}

func TestBaselineGroupNullMemberReplacement(t *testing.T) {
	requireTerraform(t)
	s := testserver.NewGroups()
	defer s.Close()
	cfg := func(name, members string) string {
		return fmt.Sprintf(`provider "algosec" {
 url = %q
 session_id = %q
 insecure = true
 read_only = false
 experimental_device_groups = true
 }
 resource "algosec_device_group" "test" {
 display_name = %q
 members = %s
 }`, s.URL, testserver.Session, name, members)
	}
	good := cfg("owned", `["old"]`)
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
		{Config: good},
		{Config: cfg("replacement", `[null]`), ExpectError: regexp.MustCompile("(Value Conversion Error|Invalid members|nonblank|null)")},
		{PreConfig: func() {
			s.Mu.Lock()
			defer s.Mu.Unlock()
			if _, ok := s.Groups["owned"]; !ok {
				t.Error("invalid replacement DELETED previously owned group")
			}
		}, Config: good},
	}})
}
