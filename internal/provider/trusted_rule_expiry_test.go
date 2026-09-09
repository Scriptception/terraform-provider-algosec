// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestProtocolTrustedRuleInvalidExpiryReplacementRetainsExisting(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	exists := false
	invalidStep := false
	invalidDeletes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			rules := []any{}
			if exists {
				rules = append(rules, map[string]any{"ruleId": "r", "comment": "", "expirationDate": ""})
			}
			json.NewEncoder(w).Encode([]any{map[string]any{"deviceName": "dev", "deviceId": "1", "deviceDisplayName": "D", "trustedRules": rules}})
		case "POST":
			exists = true
			fmt.Fprint(w, `{"trustedRuleIds":["r"]}`)
		case "DELETE":
			if invalidStep {
				invalidDeletes++
			}
			exists = false
			fmt.Fprint(w, `{"trustedRuleIds":["r"]}`)
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
 device_name = "dev"
 rule_id = "r"
 %s
}`, s.URL, metadata)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
		{Config: cfg("")},
		{PreConfig: func() { mu.Lock(); invalidStep = true; mu.Unlock() }, Config: cfg(`expiration_date = "2000-01-01"`), ExpectError: regexp.MustCompile("future UTC")},
		{PreConfig: func() {
			mu.Lock()
			defer mu.Unlock()
			invalidStep = false
			if invalidDeletes != 0 || !exists {
				t.Errorf("invalid replacement deleted existing assignment: invalidDeletes=%d exists=%v", invalidDeletes, exists)
			}
		}, Config: cfg("")},
	}})
}

// Synthetic Framework plans cover values that Terraform may only resolve during apply.
func TestTrustedRuleExpiryPlan(t *testing.T) {
	ctx := context.Background()
	r := NewTrustedRuleResource()
	var schema resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schema)
	base := trustedRuleModel{ID: types.StringValue(trustedID("dev", "r")), DeviceName: types.StringValue("dev"), RuleID: types.StringValue("r"), Comment: types.StringValue(""), ExpirationDate: types.StringValue("2000-01-01")}
	for _, name := range []string{"new", "metadata", "device", "rule", "unchanged", "destroy", "unknown_expiry", "unknown_identity", "future", "empty"} {
		t.Run(name, func(t *testing.T) {
			state := tfsdk.State{Schema: schema.Schema}
			if d := state.Set(ctx, base); d.HasError() {
				t.Fatal(d)
			}
			m := base
			wantError := false
			switch name {
			case "new":
				state.Raw = tftypes.NewValue(state.Raw.Type(), nil)
				wantError = true
			case "metadata":
				m.Comment = types.StringValue("changed")
				wantError = true
			case "device":
				m.DeviceName = types.StringValue("other")
				wantError = true
			case "rule":
				m.RuleID = types.StringValue("other")
				wantError = true
			case "unknown_identity":
				m.RuleID = types.StringUnknown()
				wantError = true
			case "unknown_expiry":
				m.ExpirationDate = types.StringUnknown()
			case "future":
				m.ExpirationDate = types.StringValue("2099-12-31")
			case "empty":
				m.ExpirationDate = types.StringValue("")
			}
			plan := tfsdk.Plan{Schema: schema.Schema}
			if d := plan.Set(ctx, m); d.HasError() {
				t.Fatal(d)
			}
			if name == "destroy" {
				plan.Raw = tftypes.NewValue(plan.Raw.Type(), nil)
			}
			resp := resource.ModifyPlanResponse{Plan: plan}
			modifier, ok := r.(resource.ResourceWithModifyPlan)
			if !ok {
				t.Fatal("missing plan-time expiry validation")
			}
			modifier.ModifyPlan(ctx, resource.ModifyPlanRequest{Plan: plan, State: state}, &resp)
			if resp.Diagnostics.HasError() != wantError {
				t.Fatalf("error=%v want=%v: %v", resp.Diagnostics.HasError(), wantError, resp.Diagnostics)
			}
			if !resp.Plan.Raw.Equal(plan.Raw) {
				t.Fatal("validation changed planned values")
			}
		})
	}
}

// Synthetic HTTPS fixture: expired remote assignments remain importable, stable, and deletable.
func TestProtocolTrustedRuleExpiredAssignment(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	exists := true
	writes := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			rules := []any{}
			if exists {
				rules = append(rules, map[string]any{"ruleId": "r", "comment": "", "expirationDate": "2000-01-01"})
			}
			json.NewEncoder(w).Encode([]any{map[string]any{"deviceName": "dev", "deviceId": "1", "deviceDisplayName": "D", "trustedRules": rules}})
		case "DELETE":
			writes++
			exists = false
			fmt.Fprint(w, `{"trustedRuleIds":["r"]}`)
		default:
			writes++
			t.Error("unexpected write")
			w.WriteHeader(500)
		}
	}))
	defer s.Close()
	cfg := func(device, rule, comment string) string {
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
 comment = %q
 expiration_date = "2000-01-01"
}`, s.URL, device, rule, comment)
	}
	check := func() {
		mu.Lock()
		defer mu.Unlock()
		if writes != 0 || !exists {
			t.Errorf("invalid plan changed assignment: writes=%d exists=%v", writes, exists)
		}
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
		{Config: cfg("dev", "r", ""), PlanOnly: true, ExpectError: regexp.MustCompile("future UTC")},
		{Config: cfg("dev", "r", ""), ResourceName: "algosec_trusted_rule.test", ImportState: true, ImportStateId: trustedID("dev", "r"), ImportStatePersist: true},
		{Config: cfg("dev", "r", ""), PlanOnly: true},
		{Config: cfg("dev", "r", "changed"), ExpectError: regexp.MustCompile("future UTC")},
		{PreConfig: check, Config: cfg("dev", "other", ""), ExpectError: regexp.MustCompile("future UTC")},
		{PreConfig: check, Config: cfg("other", "r", ""), ExpectError: regexp.MustCompile("future UTC")},
		{PreConfig: check, Config: cfg("dev", "r", ""), Destroy: true},
	}})
	mu.Lock()
	defer mu.Unlock()
	if exists || writes != 1 {
		t.Fatalf("expired destroy failed: writes=%d exists=%v", writes, exists)
	}
}
