// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
func TestProtocolAppVizRoleLifecycle(t *testing.T) {
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
		if role != nil || creates < 2 || updates < 2 || deletes < 1 {
			return fmt.Errorf("incomplete lifecycle: %d %d %d", creates, updates, deletes)
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: cfg(`["alice"]`, `["viewAllApplications"]`)},
		{ResourceName: "algosec_appviz_role.test", ImportState: true, ImportStateVerify: true},
		{Config: strings.Replace(cfg(`[null]`, `[]`), "users =", "enabled = false\n users =", 1), ExpectError: regexp.MustCompile("Invalid role membership|non-null|nonblank")},
		{PreConfig: func() {
			mu.Lock()
			defer mu.Unlock()
			if role == nil {
				t.Error("invalid replacement destroyed role")
			}
		}, Config: cfg(`["alice"]`, `["viewAllApplications"]`)},
		{Config: strings.Replace(cfg(`["", terraform_data.user.output]`, `[]`), "users =", "enabled = false\n users =", 1) + `resource "terraform_data" "user" { input = "bob" }`, ExpectError: regexp.MustCompile("Invalid role membership|nonblank")},
		{PreConfig: func() {
			mu.Lock()
			defer mu.Unlock()
			if role == nil {
				t.Error("unknown sibling bypassed invalid replacement validation")
			}
		}, Config: cfg(`["alice"]`, `["viewAllApplications"]`)},
		{Config: cfg(`["bob"]`, `[]`)},
		{Config: cfg(`[]`, `["viewAllApplications"]`)},
		{Config: strings.Replace(cfg(`[]`, `["viewAllApplications"]`), "users =", "application_permissions = { \"12\" = \"view\" }\n users =", 1)},
		{ResourceName: "algosec_appviz_role.test", ImportState: true, ImportStateVerify: true},
		{Config: strings.Replace(cfg(`[]`, `["viewAllApplications"]`), "users =", "application_permissions = { \"0\" = \"view\" }\n users =", 1), ExpectError: regexp.MustCompile("Invalid application revision ID")},
		{PreConfig: func() {
			mu.Lock()
			defer mu.Unlock()
			if role == nil {
				t.Error("invalid application replacement destroyed role")
			}
		}, Config: strings.Replace(cfg(`[]`, `["viewAllApplications"]`), "users =", "application_permissions = { \"12\" = \"view\" }\n users =", 1)},
		{PreConfig: func() { mu.Lock(); role = nil; mu.Unlock() }, Config: cfg(`[]`, `["viewAllApplications"]`)},
	}})
}

func TestAppVizRoleFrameworkRecovery(t *testing.T) {
	for _, mode := range []string{"create_unconfirmed", "create_readback_failure", "create_mismatch", "read_error", "update_error", "delete_error"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			body := `{"name":"Test Role","enabled":true,"roleUsers":[],"authorizedViewsAndActions":[],"authorizedApplications":[]}`
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Method == "GET" {
					reads++
					if strings.HasPrefix(mode, "create_") && reads == 1 {
						w.WriteHeader(404)
						return
					}
					if mode == "read_error" || mode == "create_readback_failure" {
						w.WriteHeader(403)
						return
					}
					if mode == "create_mismatch" {
						fmt.Fprint(w, strings.Replace(body, `"enabled":true`, `"enabled":false`, 1))
						return
					}
					fmt.Fprint(w, body)
					return
				}
				if strings.HasPrefix(mode, "create_") {
					if mode == "create_unconfirmed" {
						fmt.Fprint(w, `{}`)
					} else {
						fmt.Fprint(w, body)
					}
					return
				}
				w.WriteHeader(500)
			}))
			defer server.Close()
			ca := filepath.Join(t.TempDir(), "ca.pem")
			os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
			t.Setenv("SSL_CERT_FILE", ca)
			c, e := client.NewAppVizClient(server.URL, "synthetic-token", 30e9, false, true)
			if e != nil {
				t.Fatal(e)
			}
			r := &appVizRoleResource{c: c}
			ctx := context.Background()
			var sr resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &sr)
			m := roleModel(client.AppVizRole{Name: "Test Role", Enabled: true, Users: []string{}, Permissions: []string{}, Applications: map[string]string{}})
			state := tfsdk.State{Schema: sr.Schema}
			if d := state.Set(ctx, m); d.HasError() {
				t.Fatal(d)
			}
			plan := tfsdk.Plan{Schema: sr.Schema}
			plan.Set(ctx, m)
			switch {
			case strings.HasPrefix(mode, "create_"):
				m.ID = types.StringUnknown()
				plan.Set(ctx, m)
				resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema}}
				r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
				if !resp.Diagnostics.HasError() {
					t.Fatal("missing error")
				}
				if mode == "create_unconfirmed" {
					if !resp.State.Raw.IsNull() && resp.State.Raw.IsKnown() {
						t.Fatal("adopted unconfirmed create")
					}
					if reads != 1 {
						t.Fatal("unconfirmed create read back")
					}
				} else {
					var got appVizRoleModel
					if d := resp.State.Get(ctx, &got); d.HasError() || got.ID.ValueString() != "Test Role" {
						t.Fatal("lost acknowledged identity", resp.Diagnostics)
					}
				}
			case mode == "read_error":
				resp := resource.ReadResponse{State: state}
				r.Read(ctx, resource.ReadRequest{State: state}, &resp)
				if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
					t.Fatal("lost read state")
				}
			case mode == "delete_error":
				resp := resource.DeleteResponse{State: state}
				r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
				if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
					t.Fatal("lost delete state")
				}
			case mode == "update_error":
				resp := resource.UpdateResponse{State: state}
				r.Update(ctx, resource.UpdateRequest{State: state, Plan: plan}, &resp)
				if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
					t.Fatal("lost update state")
				}
			}
			if strings.Contains(fmt.Sprint(state.Raw), "synthetic-token") {
				t.Fatal("token stored in state")
			}
		})
	}
}
