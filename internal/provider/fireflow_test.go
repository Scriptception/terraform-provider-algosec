// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Synthetic TLS fixture models direct and inherited grants independently.
func TestProtocolFireFlowBindings(t *testing.T) {
	requireTerraform(t)
	for _, key := range []string{"ALGOSEC_URL", "ALGOSEC_USERNAME", "ALGOSEC_PASSWORD", "ALGOSEC_SESSION_ID", "ALGOSEC_APPVIZ_SAAS_URL", "ALGOSEC_APPVIZ_SAAS_TOKEN"} {
		t.Setenv(key, "")
	}
	for _, kind := range []string{"User", "Role", "Permission"} {
		t.Run(kind, func(t *testing.T) {
			var mu sync.Mutex
			owned := false
			activeMember := int64(8)
			activePermission := "SeeRole"
			writes := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				cookie, e := r.Cookie("FireFlow_Session")
				if e != nil || cookie.Value != "synthetic-session" || r.Header.Get("Authorization") != "" {
					t.Error("mixed auth")
				}
				if r.Method == "POST" {
					writes++
					if kind == "Permission" {
						var body struct {
							Add []struct {
								Name string `json:"permissionName"`
							} `json:"addPermissions"`
							Remove []struct {
								Name string `json:"permissionName"`
							} `json:"removePermissions"`
						}
						if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Add)+len(body.Remove) != 1 {
							t.Error("not singleton permission")
						}
						target := body.Add
						if len(target) == 0 {
							target = body.Remove
						}
						if target[0].Name != "SeeRole" && target[0].Name != "AdminRole" {
							t.Error("unowned permission changed")
						}
						activePermission = target[0].Name
						owned = len(body.Add) == 1
						fmt.Fprint(w, `{"status":"Success","messages":[],"data":{}}`)
					} else {
						var body struct {
							Add []struct {
								ID   int64  `json:"id"`
								Type string `json:"type"`
							} `json:"addMembers"`
							Remove []struct {
								ID   int64  `json:"id"`
								Type string `json:"type"`
							} `json:"removeMembers"`
						}
						if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Add)+len(body.Remove) != 1 {
							t.Error("not singleton member")
						}
						target := body.Add
						if len(target) == 0 {
							target = body.Remove
						}
						if (target[0].ID != 8 && target[0].ID != 9) || target[0].Type != kind {
							t.Error("unowned member changed")
						}
						activeMember = target[0].ID
						owned = len(body.Add) == 1
						fmt.Fprint(w, `{"status":"Success","messages":[],"data":null}`)
					}
					return
				}
				if r.Method != "GET" {
					t.Error("unexpected method")
				}
				if kind == "Permission" {
					if r.URL.Path != "/FireFlow/api/roles/7/permissions" {
						t.Error("wrong permission route")
					}
					fmt.Fprintf(w, `{"status":"Success","messages":[],"data":{"system":[{"permissionName":%q,"objectType":"System","objectId":0,"direct":%t,"inherited":true},{"permissionName":"Unrelated","objectType":"System","objectId":0,"direct":true,"inherited":false}],"customField":[],"requestTemplate":[]}}`, activePermission, owned)
				} else {
					if r.URL.Path != "/FireFlow/api/roles/7/members" || r.URL.Query().Get("fetchIndirect") != "false" {
						t.Error("wrong direct read")
					}
					rows := []map[string]any{{"id": 17, "name": "Unowned", "type": "User", "isDirectMember": true}, {"id": 18, "name": "Inherited", "type": "User", "isDirectMember": false}}
					if owned {
						rows = append(rows, map[string]any{"id": activeMember, "name": "Example", "type": kind, "isDirectMember": true})
					}
					json.NewEncoder(w).Encode(map[string]any{"status": "Success", "messages": []any{}, "data": rows})
				}
			}))
			defer s.Close()
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); e != nil {
				t.Fatal(e)
			}
			t.Setenv("SSL_CERT_FILE", ca)
			provider := fmt.Sprintf(`provider "algosec" {
 fireflow_url=%q
 fireflow_session="synthetic-session"
 experimental_fireflow_bindings=true
 read_only=false
}
`, s.URL)
			name := "algosec_fireflow_role_member"
			attrs := fmt.Sprintf("role_id=7\nmember_id=8\nmember_type=%q", kind)
			invalid := "role_id=7\nmember_id=7\nmember_type=\"Role\""
			if kind == "Permission" {
				name = "algosec_fireflow_role_permission"
				attrs = "role_id=7\npermission_name=\"SeeRole\"\nobject_type=\"System\"\nobject_id=0"
				invalid = "role_id=7\npermission_name=\"SeeRole\"\nobject_type=\"System\"\nobject_id=1"
			}
			cfg := func(a string) string { return provider + fmt.Sprintf("resource %q \"test\" {\n%s\n}\n", name, a) }
			next := strings.Replace(attrs, "member_id=8", "member_id=9", 1)
			if kind == "Permission" {
				next = strings.Replace(attrs, "SeeRole", "AdminRole", 1)
			}
			steps := []tfresource.TestStep{
				{Config: cfg(attrs)}, {ResourceName: name + ".test", ImportState: true, ImportStateVerify: true},
				{Config: cfg(invalid), ExpectError: regexp.MustCompile("itself|System permission object_id")},
				{PreConfig: func() {
					mu.Lock()
					defer mu.Unlock()
					if !owned || writes != 1 {
						t.Error("known invalid replacement destroyed direct binding")
					}
				}, Config: cfg(attrs)},
				{Config: cfg(next)},
				{ResourceName: name + ".test", ImportState: true, ImportStateVerify: true},
			}
			if kind == "Permission" {
				oversized := tfresource.TestStep{Config: cfg(strings.Replace(attrs, "SeeRole", strings.Repeat("<", 1500000), 1)), ExpectError: regexp.MustCompile("API request exceeds 8 MiB limit")}
				tail := append([]tfresource.TestStep{}, steps[3:]...)
				steps = append(steps[:3], oversized)
				steps = append(steps, tail...)
			}
			tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
				mu.Lock()
				defer mu.Unlock()
				if owned || writes != 4 {
					return fmt.Errorf("wrong final direct ownership writes=%d owned=%v", writes, owned)
				}
				return nil
			}, Steps: steps})
		})
	}
}
