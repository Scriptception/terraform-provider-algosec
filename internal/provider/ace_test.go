// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

func aceProtocolServer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	t.Setenv("ALGOSEC_ACE_ACCESS_TOKEN", "synthetic-token")
	return s.URL
}
func aceConfig(origin string) string {
	return fmt.Sprintf("provider \"algosec\" {\n ace_url = %q\n experimental_ace_public_contracts = true\n read_only = false\n}\n", origin)
}
func TestProtocolACEEmails(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	emails := []string{}
	writes := 0
	origin := aceProtocolServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/prevasio/api/v1/configurations/integrations/cd-mitigation" || r.URL.Query().Get("provider") != "aws" {
			t.Error("wrong route")
		}
		if r.Method == "PATCH" {
			var b struct {
				Notifications struct {
					Emails []string `json:"emails"`
				} `json:"violationNotifications"`
			}
			json.NewDecoder(r.Body).Decode(&b)
			emails = b.Notifications.Emails
			writes++
			w.Write([]byte(`{"data":{"message":"Your CD mitigation settings were successfully updated."}}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"threatManagement": map[string]any{"enabled": true, "minimumSeverityLevel": 0}, "violationNotifications": map[string]any{"emails": emails}}})
	})
	cfg := func(email string) string {
		return aceConfig(origin) + fmt.Sprintf("resource \"algosec_ace_cd_notification_emails\" \"test\" {\ncloud_provider = \"aws\"\nemails = [%q]\n}\n", email)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		mu.Lock()
		defer mu.Unlock()
		if len(emails) != 0 || writes < 4 {
			return fmt.Errorf("incomplete lifecycle")
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: cfg("first@example.invalid")},
		{ResourceName: "algosec_ace_cd_notification_emails.test", ImportState: true, ImportStateVerify: true},
		{Config: strings.Replace(cfg(""), "cloud_provider = \"aws\"", "cloud_provider = \"azure\"", 1), ExpectError: regexp.MustCompile("Invalid email")},
		{Config: strings.Replace(strings.Replace(cfg("bad"), `emails = ["bad"]`, `emails = ["bad", terraform_data.email.output]`, 1), `cloud_provider = "aws"`, `cloud_provider = "azure"`, 1) + `resource "terraform_data" "email" { input = "valid@example.invalid" }`, ExpectError: regexp.MustCompile("Invalid email")},
		{Config: cfg("second@example.invalid")},
		{PreConfig: func() { mu.Lock(); emails = []string{"drift@example.invalid"}; mu.Unlock() }, Config: cfg("second@example.invalid")},
		{PreConfig: func() { mu.Lock(); emails = []string{}; mu.Unlock() }, Config: cfg("second@example.invalid")},
	}})
}
func TestProtocolACEJira(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	var saved map[string]string
	posts, deletes := 0, 0
	origin := aceProtocolServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/prevasio/api/v1/configurations/integrations/jira" {
			t.Error("route")
		}
		switch r.Method {
		case "GET":
			if saved == nil {
				w.Write([]byte(`{"data":{}}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": saved})
		case "POST":
			posts++
			json.NewDecoder(r.Body).Decode(&saved)
			saved["apiToken"] = "MASKED-SYNTHETIC"
			w.Write([]byte(`{"data":{"message":"Your Jira project settings were successfully tested and saved."}}`))
		case "DELETE":
			deletes++
			saved = nil
			w.Write([]byte(`{"data":{"message":"Jira settings have been deleted."}}`))
		default:
			t.Error("invented method")
		}
	})
	cfg := func(version, token string) string {
		return aceConfig(origin) + fmt.Sprintf(`resource "algosec_ace_jira_integration" "test" {
 server_url = "https://jira.example.invalid"
 user_name = "user@example.invalid"
 project_key = "TEST"
 default_issue_type = "Task"
 default_priority = "High"
 replacement_version = %q
 %s
}
`, version, token)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		mu.Lock()
		defer mu.Unlock()
		if saved != nil || posts < 2 || deletes < 2 {
			return fmt.Errorf("incomplete Jira lifecycle")
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: cfg("1", `api_token_wo = "synthetic-raw"`)},
		{ResourceName: "algosec_ace_jira_integration.test", ImportState: true, ImportStateId: "jira", ImportStateVerify: true, ImportStateVerifyIgnore: []string{"replacement_version"}},
		{Config: cfg("1", ``)},
		{Config: cfg("2", ``), ExpectError: regexp.MustCompile("write-only token")},
		{Config: strings.Replace(strings.Replace(cfg("2", `api_token_wo = "synthetic-raw"`), `default_priority = "High"`, `default_priority = ""`, 1), `project_key = "TEST"`, `project_key = terraform_data.project.output`, 1) + `resource "terraform_data" "project" { input = "TEST" }`, ExpectError: regexp.MustCompile("Invalid Jira replacement")},
		{Config: cfg("2", `api_token_wo = "synthetic-raw"`)},
		{PreConfig: func() { mu.Lock(); saved["projectKey"] = "DRIFT"; mu.Unlock() }, Config: cfg("2", `api_token_wo = "synthetic-raw"`)},
		{PreConfig: func() { mu.Lock(); saved = nil; mu.Unlock() }, Config: cfg("2", `api_token_wo = "synthetic-raw"`)},
		{Config: cfg("2", ``), Check: func(s *terraform.State) error {
			b, _ := json.Marshal(s)
			if strings.Contains(string(b), "synthetic-raw") || strings.Contains(string(b), "MASKED-SYNTHETIC") {
				return fmt.Errorf("secret in state")
			}
			return nil
		}},
	}})
}
func TestProtocolACEThreat(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	var saved map[string]string
	origin := aceProtocolServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			v := []any{}
			if saved != nil {
				v = append(v, saved)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": v, "page": map[string]int{"current": 1, "limit": 1000, "total": 1, "totalItems": len(v)}})
		case "POST":
			json.NewDecoder(r.Body).Decode(&saved)
			w.Write([]byte(`{"data":{"message":"Successfully added example.invalid entry to block-list for threat - domains."}}`))
		case "DELETE":
			if r.URL.Query().Get("destination") != "example.invalid" {
				t.Error("unsafe delete")
			}
			saved = nil
			w.Write([]byte(`{"data":{"message":"Successfully deleted example.invalid from the block-list of threat type domains."}}`))
		}
	})
	cfg := func(desc string) string {
		return aceConfig(origin) + fmt.Sprintf(`resource "algosec_ace_threat_list_entry" "test" {
 threat_type = "domains"
 list_type = "block-list"
 destination = "example.invalid"
 description = %q
 severity = "high"
}
`, desc)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
		{Config: cfg("synthetic")},
		{ResourceName: "algosec_ace_threat_list_entry.test", ImportState: true, ImportStateVerify: true},
		{Config: cfg("replacement")},
		{PreConfig: func() { mu.Lock(); saved["description"] = "drift"; mu.Unlock() }, Config: cfg("replacement")},
		{PreConfig: func() { mu.Lock(); saved = nil; mu.Unlock() }, Config: cfg("replacement")},
	}})
}
func TestProtocolACEAccount(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	var saved map[string]any
	origin := aceProtocolServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case "GET":
			v := []any{}
			if saved != nil {
				v = append(v, saved)
			}
			json.NewEncoder(w).Encode(v)
		case "POST":
			saved = map[string]any{"accountKey": "opaque-registration-key", "accountId": "123456789012", "provider": "aws", "name": "synthetic", "autoOnboarded": false}
			w.WriteHeader(201)
			w.Write([]byte(`{"accountKey":"opaque-registration-key"}`))
		case "PATCH":
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if len(v) != 1 {
				t.Error("unexpected credential patch")
			}
			saved["name"] = v["name"]
			w.WriteHeader(204)
		case "DELETE":
			saved = nil
			w.WriteHeader(204)
		}
	})
	cfg := func(name, version, bootstrap string) string {
		return aceConfig(origin) + fmt.Sprintf(`resource "algosec_ace_cloud_account_registration" "test" {
 cloud_provider = "aws"
 account_id = "123456789012"
 name = %q
 unified_onboarding = true
 replacement_version = %q
 %s
}
`, name, version, bootstrap)
	}
	bootstrap := `role_arn_wo = "arn:aws:iam::123456789012:role/Synthetic"
 external_id_wo = "synthetic-external"
 support_changes_wo = false
 flow_logs_wo = false`
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
		{Config: cfg("synthetic", "1", bootstrap)},
		{ResourceName: "algosec_ace_cloud_account_registration.test", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"replacement_version"}},
		{Config: cfg("renamed", "1", "")},
		{Config: cfg("renamed", "2", ""), ExpectError: regexp.MustCompile("bootstrap")},
		{Config: cfg("synthetic", "2", bootstrap)},
		{Config: cfg("synthetic", "2", "")},
	}})
}
func TestACEAccountMixedUnknownBootstrap(t *testing.T) {
	ctx := context.Background()
	r := &aceAccountResource{}
	var schemaResponse resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	cfg := aceAccountModel{ID: types.StringNull(), Provider: types.StringValue("aws"), AccountID: types.StringValue("123456789012"), Name: types.StringValue("synthetic"), AzureTenant: types.StringValue(""), Organization: types.StringValue(""), Version: types.StringValue("2"), Auto: types.BoolValue(false), Unified: types.BoolValue(true), RoleARN: types.StringValue("invalid-nonempty-arn"), ExternalID: types.StringUnknown(), SupportChanges: types.BoolValue(false), FlowLogs: types.BoolValue(false)}
	// Fresh creation with unknown sibling still must reject a known malformed ARN.
	config := tfsdk.Config{Schema: schemaResponse.Schema}
	if d := tfsdkPlanConfig(ctx, schemaResponse.Schema, cfg, &config); d != nil {
		t.Fatal(d)
	}
	plan := tfsdk.Plan{Schema: schemaResponse.Schema}
	plan.Set(ctx, cfg)
	state := tfsdk.State{Schema: schemaResponse.Schema, Raw: tftypes.NewValue(schemaResponse.Schema.Type().TerraformType(ctx), nil)}
	var resp resource.ModifyPlanResponse
	r.ModifyPlan(ctx, resource.ModifyPlanRequest{Config: config, Plan: plan, State: state}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("known invalid bootstrap bypassed by unknown sibling")
	}
}

type acePlanModifier interface {
	ModifyPlan(context.Context, resource.ModifyPlanRequest, *resource.ModifyPlanResponse)
}

func aceModifyPlan(t *testing.T, r acePlanModifier, s schema.Schema, configValue, planValue any) resource.ModifyPlanResponse {
	t.Helper()
	ctx := context.Background()
	config := tfsdk.Config{Schema: s}
	if err := tfsdkPlanConfig(ctx, s, configValue, &config); err != nil {
		t.Fatal(err)
	}
	plan := tfsdk.Plan{Schema: s}
	if d := plan.Set(ctx, planValue); d.HasError() {
		t.Fatal(d)
	}
	state := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	var resp resource.ModifyPlanResponse
	r.ModifyPlan(ctx, resource.ModifyPlanRequest{Config: config, Plan: plan, State: state}, &resp)
	return resp
}

func TestACEPlanRejectsSerializedPayloadAndUnresolvedBootstrap(t *testing.T) {
	ctx := context.Background()

	t.Run("jira payload uses exact serialized size", func(t *testing.T) {
		r := &aceJiraResource{}
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		m := aceJiraModel{ServerURL: types.StringValue("https://jira.example.invalid"), UserName: types.StringValue("user@example.invalid"), ProjectKey: types.StringValue("TEST"), IssueType: types.StringValue("Task"), Priority: types.StringValue("High"), Token: types.StringNull(), Version: types.StringValue("1")}
		cfg := m
		cfg.Token = types.StringValue(strings.Repeat("x", 6*1024*1024))
		resp := aceModifyPlan(t, r, sr.Schema, cfg, m)
		if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "8 MiB") {
			t.Fatalf("expected serialized-size diagnostic, got %v", resp.Diagnostics)
		}
	})

	t.Run("jira unknown token is rejected for fresh creation", func(t *testing.T) {
		r := &aceJiraResource{}
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		m := aceJiraModel{ServerURL: types.StringValue("https://jira.example.invalid"), UserName: types.StringValue("user@example.invalid"), ProjectKey: types.StringValue("TEST"), IssueType: types.StringValue("Task"), Priority: types.StringValue("High"), Token: types.StringUnknown(), Version: types.StringValue("1")}
		resp := aceModifyPlan(t, r, sr.Schema, m, m)
		if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "Unavailable write-only token") {
			t.Fatalf("expected unresolved-token diagnostic, got %v", resp.Diagnostics)
		}
	})

	t.Run("account payload uses exact serialized size", func(t *testing.T) {
		r := &aceAccountResource{}
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		m := aceAccountModel{Provider: types.StringValue("aws"), AccountID: types.StringValue("123456789012"), Name: types.StringValue("synthetic"), Version: types.StringValue("1"), Auto: types.BoolValue(false), Unified: types.BoolValue(true), SupportChanges: types.BoolValue(false), FlowLogs: types.BoolValue(false)}
		cfg := m
		cfg.RoleARN = types.StringValue("arn:aws:iam::123456789012:role/Synthetic")
		cfg.ExternalID = types.StringValue(strings.Repeat("x", 8*1024*1024))
		resp := aceModifyPlan(t, r, sr.Schema, cfg, m)
		if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "8 MiB") {
			t.Fatalf("expected serialized-size diagnostic, got %v", resp.Diagnostics)
		}
	})

	t.Run("account unknown bootstrap is rejected for fresh creation", func(t *testing.T) {
		r := &aceAccountResource{}
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		m := aceAccountModel{Provider: types.StringValue("aws"), AccountID: types.StringValue("123456789012"), Name: types.StringValue("synthetic"), Version: types.StringValue("1"), Auto: types.BoolValue(false), Unified: types.BoolValue(true), SupportChanges: types.BoolValue(false), FlowLogs: types.BoolValue(false), RoleARN: types.StringUnknown(), ExternalID: types.StringValue("synthetic-external")}
		resp := aceModifyPlan(t, r, sr.Schema, m, m)
		if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "Unresolved bootstrap configuration") {
			t.Fatalf("expected unresolved-bootstrap diagnostic, got %v", resp.Diagnostics)
		}
	})

	t.Run("threat payload uses exact serialized size", func(t *testing.T) {
		r := &aceThreatResource{}
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		m := aceThreatModel{Threat: types.StringValue("domains"), List: types.StringValue("block-list"), Destination: types.StringValue("example.invalid"), Description: types.StringValue(strings.Repeat("<", 2*1024*1024)), Severity: types.StringValue("high")}
		resp := aceModifyPlan(t, r, sr.Schema, m, m)
		if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "8 MiB") {
			t.Fatalf("expected serialized-size diagnostic, got %v", resp.Diagnostics)
		}
	})

	t.Run("email payload uses exact serialized size", func(t *testing.T) {
		r := &aceEmailsResource{}
		var sr resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &sr)
		emails := types.SetValueMust(types.StringType, []attr.Value{types.StringValue(strings.Repeat("<", 2*1024*1024))})
		m := aceEmailsModel{Provider: types.StringValue("aws"), Emails: emails}
		resp := aceModifyPlan(t, r, sr.Schema, m, m)
		if !resp.Diagnostics.HasError() || !strings.Contains(resp.Diagnostics.Errors()[0].Detail(), "8 MiB") {
			t.Fatalf("expected serialized-size diagnostic, got %v", resp.Diagnostics)
		}
	})
}

func tfsdkPlanConfig(ctx context.Context, schema schema.Schema, v any, c *tfsdk.Config) error {
	p := tfsdk.Plan{Schema: schema}
	if d := p.Set(ctx, v); d.HasError() {
		return fmt.Errorf("cannot construct synthetic config: %v", d)
	}
	c.Raw = p.Raw
	return nil
}
func TestProtocolACEAzureGCP(t *testing.T) {
	requireTerraform(t)
	for _, cloud := range []string{"azure", "gcp"} {
		t.Run(cloud, func(t *testing.T) {
			var mu sync.Mutex
			var saved map[string]any
			id := "11111111-2222-3333-4444-555555555555"
			extra := `azure_tenant = "11111111-2222-3333-4444-555555555555"`
			bootstrap := `application_id_wo = "11111111-2222-3333-4444-555555555555"
 application_secret_wo = "synthetic-secret"
 support_changes_wo = false`
			if cloud == "gcp" {
				id = "synthetic-project"
				extra = `organization_id = "123456"`
				key, e := rsa.GenerateKey(rand.Reader, 2048)
				if e != nil {
					t.Fatal(e)
				}
				der, e := x509.MarshalPKCS8PrivateKey(key)
				if e != nil {
					t.Fatal(e)
				}
				keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
				bootstrap = fmt.Sprintf(`credential_type_wo = "service_account"
 private_key_id_wo = "synthetic-key-id"
 private_key_wo = %q
 client_email_wo = "synthetic@example.invalid"
 client_id_wo = "123456"
 auth_uri_wo = "https://accounts.google.com/o/oauth2/auth"
 token_uri_wo = "https://oauth2.googleapis.com/token"
 auth_provider_x509_cert_url_wo = "https://www.googleapis.com/oauth2/v1/certs"
 client_x509_cert_url_wo = "https://www.googleapis.com/robot/v1/metadata/x509/synthetic"
`, keyPEM)
			}
			origin := aceProtocolServer(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.Method {
				case "GET":
					v := []any{}
					if saved != nil {
						v = append(v, saved)
					}
					json.NewEncoder(w).Encode(v)
				case "POST":
					var b map[string]any
					json.NewDecoder(r.Body).Decode(&b)
					if cloud == "azure" {
						if b["tenantId"] != id || b["subscriptionId"] != id || b["applicationSecret"] != "synthetic-secret" {
							t.Error("Azure DTO")
						}
					} else {
						if b["project_id"] != id || b["organization_id"] != "123456" || b["type"] != "service_account" || b["private_key"] == nil {
							t.Error("GCP DTO")
						}
					}
					saved = map[string]any{"accountKey": "opaque-key", "accountId": id, "provider": cloud, "name": b["name"], "autoOnboarded": false}
					if cloud == "azure" {
						saved["azureTenant"] = id
					} else {
						saved["organizationId"] = "123456"
					}
					w.WriteHeader(201)
					w.Write([]byte(`{"accountKey":"opaque-key"}`))
				case "PATCH":
					var b map[string]string
					json.NewDecoder(r.Body).Decode(&b)
					if len(b) != 1 {
						t.Error("non-name PATCH")
					}
					saved["name"] = b["name"]
					w.WriteHeader(204)
				case "DELETE":
					saved = nil
					w.WriteHeader(204)
				}
			})
			cfg := func(name, version, boot string) string {
				return aceConfig(origin) + fmt.Sprintf("resource \"algosec_ace_cloud_account_registration\" \"test\" {\n cloud_provider = %q\n account_id = %q\n name = %q\n unified_onboarding = true\n replacement_version = %q\n%s\n%s\n}\n", cloud, id, name, version, extra, boot)
			}
			tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
				{Config: cfg("synthetic", "1", bootstrap)},
				{ResourceName: "algosec_ace_cloud_account_registration.test", ImportState: true, ImportStateVerify: true, ImportStateVerifyIgnore: []string{"replacement_version"}},
				{Config: cfg("renamed", "1", "")},
				{Config: cfg("renamed", "2", bootstrap)},
				{PreConfig: func() { mu.Lock(); saved["name"] = "drift"; mu.Unlock() }, Config: cfg("renamed", "2", "")},
				{PreConfig: func() { mu.Lock(); saved = nil; mu.Unlock() }, Config: cfg("renamed", "2", bootstrap)},
				{Config: cfg("renamed", "2", "")},
			}})
		})
	}
}
