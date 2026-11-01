// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Synthetic HTTPS assignment fixture preserves every unowned URL/IP.
func TestProtocolURLIPLifecycle(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	cat := client.Category{URLs: map[string][]string{"www.example.com": {"192.0.2.2"}, "other.example": {"198.51.100.1"}}}
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != "GET" {
			writes++
			if r.URL.Path != "/afa/api/v1/plugins/panorama/URLCategory/Example/URL/www.example.com/IP/" {
				t.Error("wrong target")
			}
			var ips []string
			if json.NewDecoder(r.Body).Decode(&ips) != nil || len(ips) != 1 {
				t.Error("not singleton")
			}
			if r.Method == "PUT" {
				cat.URLs["www.example.com"] = append(cat.URLs["www.example.com"], ips[0])
			} else if r.Method == "DELETE" {
				cat.URLs["www.example.com"] = slices.DeleteFunc(cat.URLs["www.example.com"], func(v string) bool { return v == ips[0] })
			} else {
				t.Error("unexpected mutation")
			}
		}
		json.NewEncoder(w).Encode(client.Categories{Categories: map[string]client.Category{"Example": cat}})
	}))
	defer s.Close()
	cfg := func(ip string) string {
		return fmt.Sprintf(`provider "algosec" {
 url=%q
 session_id="synthetic"
 insecure=true
 read_only=false
 experimental_url_ip_memberships=true
}
resource "algosec_url_ip_membership" "test" {
 category="Example"
 url="www.example.com"
 ip=%q
}
`, s.URL, ip)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		mu.Lock()
		defer mu.Unlock()
		if !slices.Equal(cat.URLs["www.example.com"], []string{"192.0.2.2"}) || !slices.Equal(cat.URLs["other.example"], []string{"198.51.100.1"}) {
			return fmt.Errorf("unowned entries changed")
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: cfg("192.0.2.1")}, {ResourceName: "algosec_url_ip_membership.test", ImportState: true, ImportStateVerify: true},
		{Config: cfg("invalid"), ExpectError: regexp.MustCompile("Invalid URL/IP|IP must")},
		{PreConfig: func() {
			mu.Lock()
			defer mu.Unlock()
			if writes != 1 || !slices.Contains(cat.URLs["www.example.com"], "192.0.2.1") {
				t.Error("invalid replacement destroyed assignment")
			}
		}, Config: cfg("192.0.2.3")},
		{ResourceName: "algosec_url_ip_membership.test", ImportState: true, ImportStateVerify: true},
	}})
}
