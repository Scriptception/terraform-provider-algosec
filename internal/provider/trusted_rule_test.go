// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Synthetic HTTPS fixture; deliberately independent request DTOs verify the wire contract.
func TestProtocolTrustedRuleLifecycle(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	var assignment *client.TrustedRule
	writes := 0
	device, rule := "Device /雪?%+#", "Rule /雪?%+#,"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/afa/api/v1/trusted-rules/rules" {
			t.Error(r.URL.Path)
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case "GET":
			if r.URL.Query().Get("deviceNames") != device {
				t.Error("device query changed")
			}
			rules := []client.TrustedRule{}
			if assignment != nil {
				rules = append(rules, *assignment)
			}
			json.NewEncoder(w).Encode([]any{map[string]any{"deviceName": device, "deviceId": "1", "deviceDisplayName": "D", "trustedRules": rules}})
		case "POST":
			var in struct {
				DeviceName string
				Rules      []struct{ ID, Comment, ExpirationDate string }
			}
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.DeviceName != device || len(in.Rules) != 1 || in.Rules[0].ID != rule {
				t.Error("invalid POST")
				w.WriteHeader(400)
				return
			}
			if assignment != nil {
				t.Error("overwrote assignment")
			}
			assignment = &client.TrustedRule{RuleID: rule, Comment: in.Rules[0].Comment, ExpirationDate: in.Rules[0].ExpirationDate}
			writes++
			json.NewEncoder(w).Encode(map[string]any{"trustedRuleIds": []string{rule}})
		case "DELETE":
			var in struct {
				DeviceName string
				RuleIDs    []string
			}
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.DeviceName != device || len(in.RuleIDs) != 1 || in.RuleIDs[0] != rule {
				t.Error("invalid DELETE")
			}
			assignment = nil
			writes++
			json.NewEncoder(w).Encode(map[string]any{"trustedRuleIds": []string{rule}})
		default:
			t.Error(r.Method)
		}
	}))
	defer s.Close()
	cfg := func(metadata string) string {
		return fmt.Sprintf(`provider "algosec" {
 url = %q
 session_id = "synthetic"
 insecure = true
 read_only = false
 experimental_trusted_rules = true
}
resource "algosec_trusted_rule" "test" {
 device_name = %q
 rule_id = %q
 %s
}
`, s.URL, device, rule, metadata)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		mu.Lock()
		defer mu.Unlock()
		if assignment != nil || writes < 8 {
			return fmt.Errorf("lifecycle incomplete: %d writes", writes)
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: cfg("")},
		{ResourceName: "algosec_trusted_rule.test", ImportState: true, ImportStateVerify: true},
		{Config: cfg(`comment = "Temporary"` + "\n" + `expiration_date = "2099-12-31"`)},
		{Config: cfg("")},
		{PreConfig: func() { mu.Lock(); assignment.Comment = "external"; mu.Unlock() }, Config: cfg("")},
		{PreConfig: func() { mu.Lock(); assignment = nil; mu.Unlock() }, Config: cfg("")},
	}})
}

func TestTrustedRuleImportIdentity(t *testing.T) {
	for _, pair := range [][2]string{{"Device /雪?%+#", "r/,?%+#"}, {" spaced ", " rule "}} {
		id := trustedID(pair[0], pair[1])
		d, r, e := parseTrustedID(id)
		if e != nil || d != pair[0] || r != pair[1] {
			t.Fatal("lossy identity")
		}
	}
	for _, id := range []string{"", "dev/r", "v2.ZGV2.cg", "v1.ZGV2=.cg", "v1.ZGV2.ch", "v1.ZGV2.cg\n", "v1..cg", "v1.ZGV2._w", "v1.ZGV2.cg.extra"} {
		if _, _, e := parseTrustedID(id); e == nil {
			t.Fatal("malformed import accepted", id)
		}
	}
}
func TestTrustedRuleFrameworkRecovery(t *testing.T) {
	for _, mode := range []string{"create_unconfirmed", "create_readback_failure", "create_mismatch", "read_error", "delete_error", "update_error"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Method == "POST" {
					if mode == "create_unconfirmed" {
						fmt.Fprint(w, `{}`)
					} else {
						fmt.Fprint(w, `{"trustedRuleIds":["r"]}`)
					}
					return
				}
				if q.Method == "DELETE" {
					w.WriteHeader(500)
					return
				}
				reads++
				if mode == "read_error" || mode == "create_readback_failure" && reads > 1 {
					w.WriteHeader(403)
					return
				}
				rules := `[{"ruleId":"r","comment":"","expirationDate":""}]`
				if strings.HasPrefix(mode, "create_") && reads == 1 {
					rules = `[]`
				}
				if mode == "create_mismatch" && reads > 1 {
					rules = `[{"ruleId":"r","comment":"external","expirationDate":""}]`
				}
				fmt.Fprintf(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":%s}]`, rules)
			}))
			defer server.Close()
			c, e := client.New(client.Options{URL: server.URL, SessionID: "synthetic", Insecure: true, ExperimentalTrustedRules: true})
			if e != nil {
				t.Fatal(e)
			}
			r := &trustedRuleResource{c: c}
			ctx := context.Background()
			var sr resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &sr)
			m := trustedRuleModel{ID: types.StringValue(trustedID("dev", "r")), DeviceName: types.StringValue("dev"), RuleID: types.StringValue("r"), Comment: types.StringValue(""), ExpirationDate: types.StringValue("")}
			state := tfsdk.State{Schema: sr.Schema}
			if d := state.Set(ctx, m); d.HasError() {
				t.Fatal(d)
			}
			switch {
			case strings.HasPrefix(mode, "create_"):
				m.ID = types.StringUnknown()
				plan := tfsdk.Plan{Schema: sr.Schema}
				plan.Set(ctx, m)
				resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema}}
				r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
				if !resp.Diagnostics.HasError() {
					t.Fatal("missing create error")
				}
				if mode == "create_unconfirmed" {
					if resp.State.Raw.IsKnown() && !resp.State.Raw.IsNull() {
						t.Fatal("unconfirmed state")
					}
				} else {
					var got trustedRuleModel
					if d := resp.State.Get(ctx, &got); d.HasError() || got.ID.ValueString() != trustedID("dev", "r") {
						t.Fatal("lost confirmed identity")
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
				r.Update(ctx, resource.UpdateRequest{State: state}, &resp)
				if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
					t.Fatal("lost update state")
				}
			}
		})
	}
}

func TestProtocolTrustedRuleSafety(t *testing.T) {
	requireTerraform(t)
	for _, tc := range []struct{ name, settings, device, rule, metadata, pattern string }{
		{"gate_default", "read_only = false", "dev", "r", "", "experimental_trusted_rules"},
		{"gate_null", "read_only = false\nexperimental_trusted_rules = null", "dev", "r", "", "experimental_trusted_rules"},
		{"gate_false", "read_only = false\nexperimental_trusted_rules = false", "dev", "r", "", "experimental_trusted_rules"},
		{"readonly_default", "experimental_trusted_rules = true", "dev", "r", "", "read_only"},
		{"readonly_null", "experimental_trusted_rules = true\nread_only = null", "dev", "r", "", "read_only"},
		{"comma", "experimental_trusted_rules = true\nread_only = false", "dev,other", "r", "", "comma"},
		{"all_firewalls", "experimental_trusted_rules = true\nread_only = false", "ALL_FIREWALLS", "r", "", "ALL_FIREWALLS"},
		{"blank_rule", "experimental_trusted_rules = true\nread_only = false", "dev", " ", "", "nonblank"},
		{"invalid_date", "experimental_trusted_rules = true\nread_only = false", "dev", "r", `expiration_date = "2026-02-30"`, "YYYY-MM-DD"},
		{"expired", "experimental_trusted_rules = true\nread_only = false", "dev", "r", `expiration_date = "2000-01-01"`, "future UTC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("invalid configuration contacted fixture")
				w.WriteHeader(500)
			}))
			defer s.Close()
			cfg := fmt.Sprintf(`provider "algosec" {
 url = %q
 session_id = "synthetic"
 insecure = true
 %s
}
resource "algosec_trusted_rule" "test" {
 device_name = %q
 rule_id = %q
 %s
}
`, s.URL, tc.settings, tc.device, tc.rule, tc.metadata)
			tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{{Config: cfg, ExpectError: regexp.MustCompile(tc.pattern)}}})
		})
	}
}
