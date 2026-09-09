// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Synthetic SaaS HTTPS fixture with a trusted local CA, not insecure TLS.
func TestReviewAppVizOversizeReplacementMustRetainOld(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	var role map[string]any
	creates, updates, deletes := 0, 0, 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer synthetic-token" || r.Header.Get("Cookie") != "" {
			t.Error("incorrect or mixed authentication")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing JSON content type")
		}
		if r.URL.Path != "/BusinessFlow/rest/v1/settings/permissions/role" && r.URL.Path != "/BusinessFlow/rest/v1/settings/permissions/role/new" {
			t.Error("unexpected route", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/BusinessFlow/rest/v1/settings/permissions/role/new" {
			if r.URL.Query().Get("name") != "Test Role /雪?" {
				t.Error("incorrect query identity")
			}
		}
		switch r.Method {
		case "GET":
			if role == nil {
				w.WriteHeader(404)
				return
			}
			json.NewEncoder(w).Encode(role)
		case "POST":
			var in map[string]json.RawMessage
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				t.Fatal("bad request body")
			}
			if r.URL.Path == "/BusinessFlow/rest/v1/settings/permissions/role/new" {
				if role != nil {
					t.Error("create adopted existing role")
					w.WriteHeader(400)
					return
				}
				creates++
				var name string
				var enabled bool
				var users, permissions []string
				json.Unmarshal(in["name"], &name)
				json.Unmarshal(in["enabled"], &enabled)
				json.Unmarshal(in["users"], &users)
				json.Unmarshal(in["authorizedViewsAndActions"], &permissions)
				ps := []any{}
				for _, p := range permissions {
					ps = append(ps, map[string]any{"name": p, "allowed": true})
				}
				var ap []struct {
					ID         string `json:"applicationID"`
					Permission string `json:"permission"`
				}
				if e := json.Unmarshal(in["authorizedApplications"], &ap); e != nil {
					t.Error("invalid application payload")
				}
				applications := []any{}
				for _, a := range ap {
					id, e := strconv.ParseInt(a.ID, 10, 64)
					if e != nil {
						t.Error("invalid application ID")
					}
					applications = append(applications, map[string]any{"applicationID": id, "name": "Example application", "permission": a.Permission})
				}
				role = map[string]any{"name": name, "enabled": enabled, "roleUsers": users, "authorizedViewsAndActions": ps, "authorizedApplications": applications}
			} else {
				updates++
				var changes struct{ Add, Remove []string }
				json.Unmarshal(in["users"], &changes)
				users := role["roleUsers"].([]string)
				for _, u := range changes.Remove {
					for i, v := range users {
						if v == u {
							users = append(users[:i], users[i+1:]...)
							break
						}
					}
				}
				users = append(users, changes.Add...)
				role["roleUsers"] = users
				json.Unmarshal(in["authorizedViewsAndActionChanges"], &changes)
				ps := role["authorizedViewsAndActions"].([]any)
				for _, p := range changes.Remove {
					for i, v := range ps {
						if v.(map[string]any)["name"] == p {
							ps = append(ps[:i], ps[i+1:]...)
							break
						}
					}
				}
				for _, p := range changes.Add {
					ps = append(ps, map[string]any{"name": p, "allowed": true})
				}
				role["authorizedViewsAndActions"] = ps
			}
			json.NewEncoder(w).Encode(role)
		case "DELETE":
			deletes++
			role = nil
			fmt.Fprint(w, `{"body":{},"statusCode":"OK","statusCodeValue":200}`)
		default:
			t.Error("unexpected method", r.Method)
		}
	}))
	defer s.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	cfg := func(users, permissions string) string {
		return fmt.Sprintf(`provider "algosec" {
 appviz_saas_url = %q
 appviz_saas_token = "synthetic-token"
 experimental_appviz_roles = true
 appviz_whole_role_ownership = true
 read_only = false
}
resource "algosec_appviz_role" "test" {
 name = "Test Role /雪?"
 users = %s
 permissions = %s
}
`, s.URL, users, permissions)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		mu.Lock()
		defer mu.Unlock()
		if role != nil || creates < 1 || deletes < 1 {
			return fmt.Errorf("incomplete lifecycle: %d %d %d", creates, updates, deletes)
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: cfg(`["alice"]`, `["viewAllApplications"]`)},
		{ResourceName: "algosec_appviz_role.test", ImportState: true, ImportStateVerify: true},
		{Config: strings.Replace(cfg(fmt.Sprintf("[%q]", strings.Repeat("<", 1500000)), `[]`), "users =", "enabled = false\n users =", 1), ExpectError: regexp.MustCompile("API request exceeds 8 MiB limit")},
		{Config: strings.Replace(cfg(fmt.Sprintf("[%q, terraform_data.unknown.output]", strings.Repeat("<", 1500000)), `[]`), "users =", "enabled = false\n users =", 1) + `resource "terraform_data" "unknown" { input = "bob" }`, ExpectError: regexp.MustCompile("API request exceeds 8 MiB limit")},
		{Config: strings.Replace(cfg(`[]`, `["refreshVulnerability"]`), "users =", "enabled = false\n users =", 1), ExpectError: regexp.MustCompile("viewVulnerability")},
		{PreConfig: func() {
			mu.Lock()
			defer mu.Unlock()
			if role == nil || deletes != 0 {
				t.Errorf("KNOWN OVERSIZE REPLACEMENT DESTROYED OWNED ROLE: deletes=%d exists=%v", deletes, role != nil)
			}
		}, Config: cfg(`["alice"]`, `["viewAllApplications"]`)},
	}})
}
