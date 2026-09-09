package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	tfprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestIndependentURLIPAmbiguousStateSafety(t *testing.T) {
	for _, mode := range []string{"create", "read"} {
		t.Run(mode, func(t *testing.T) {
			reads, writes := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Method == "GET" {
					reads++
				} else {
					writes++
				}
				if mode == "read" {
					fmt.Fprint(w, `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1"],"www.example.com":[]}}}}`)
					return
				}
				if writes == 0 {
					fmt.Fprint(w, `{"categories":{"Example":{"urls":{"www.example.com":[]}}}}`)
					return
				}
				if q.Method == "PUT" {
					fmt.Fprint(w, `{"categories":{},"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1"]}}}}`)
					return
				}
				fmt.Fprint(w, `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1"]}}}}`)
			}))
			defer server.Close()
			c, e := client.New(client.Options{URL: server.URL, SessionID: "synthetic", Insecure: true, ExperimentalURLIPs: true})
			if e != nil {
				t.Fatal(e)
			}
			r := &urlIPResource{c: c.URLIPs}
			ctx := context.Background()
			var sr resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &sr)
			m, e := parseURLIPID(urlIPID("Example", "www.example.com", "192.0.2.1"))
			if e != nil {
				t.Fatal(e)
			}
			state := tfsdk.State{Schema: sr.Schema}
			if d := state.Set(ctx, m); d.HasError() {
				t.Fatal(d)
			}
			if mode == "read" {
				resp := resource.ReadResponse{State: state}
				r.Read(ctx, resource.ReadRequest{State: state}, &resp)
				if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
					t.Errorf("ambiguous inventory discarded owned state: diagnostics=%v null=%v reads=%d", resp.Diagnostics, resp.State.Raw.IsNull(), reads)
				}
			} else {
				plan := tfsdk.Plan{Schema: sr.Schema}
				if d := plan.Set(ctx, m); d.HasError() {
					t.Fatal(d)
				}
				resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema}}
				r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
				if !resp.Diagnostics.HasError() || (!resp.State.Raw.IsNull() && resp.State.Raw.IsKnown()) || reads != 2 {
					t.Errorf("ambiguous acknowledgement acquired ownership: diagnostics=%v null=%v reads=%d writes=%d", resp.Diagnostics, resp.State.Raw.IsNull(), reads, writes)
				}
			}
		})
	}
}

func TestIndependentOptionalSaaSConfigMatrix(t *testing.T) {
	for _, mode := range []string{"ambient_url", "ambient_token", "ambient_bad_both", "enabled_partial", "explicit_partial", "mixed", "saas_only"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("ALGOSEC_APPVIZ_SAAS_URL", "")
			t.Setenv("ALGOSEC_APPVIZ_SAAS_TOKEN", "")
			p := New("independent")()
			ctx := context.Background()
			var sr tfprovider.SchemaResponse
			p.Schema(ctx, tfprovider.SchemaRequest{}, &sr)
			m := providerModel{URL: types.StringValue("https://afa.example.invalid"), SessionID: types.StringValue("synthetic"), Username: types.StringNull(), Password: types.StringNull(), AppVizURL: types.StringNull(), AppVizToken: types.StringNull(), ExperimentalAppVizRoles: types.BoolValue(false), ReadOnly: types.BoolNull(), Timeout: types.Int64Null()}
			wantError := false
			switch mode {
			case "ambient_url":
				t.Setenv("ALGOSEC_APPVIZ_SAAS_URL", "https://saas.example.invalid")
			case "ambient_token":
				t.Setenv("ALGOSEC_APPVIZ_SAAS_TOKEN", "synthetic")
			case "ambient_bad_both":
				t.Setenv("ALGOSEC_APPVIZ_SAAS_URL", "not url")
				t.Setenv("ALGOSEC_APPVIZ_SAAS_TOKEN", "bad token")
			case "enabled_partial":
				m.ExperimentalAppVizRoles = types.BoolValue(true)
				t.Setenv("ALGOSEC_APPVIZ_SAAS_URL", "https://saas.example.invalid")
				wantError = true
			case "explicit_partial":
				m.AppVizURL = types.StringValue("https://saas.example.invalid")
				wantError = true
			case "mixed", "saas_only":
				m.ExperimentalAppVizRoles = types.BoolValue(true)
				m.AppVizURL = types.StringValue("https://saas.example.invalid")
				m.AppVizToken = types.StringValue("synthetic")
				if mode == "saas_only" {
					m.URL = types.StringValue("")
					m.SessionID = types.StringValue("")
				}
			}
			value, d := types.ObjectValueFrom(ctx, sr.Schema.Type().(types.ObjectType).AttrTypes, m)
			if d.HasError() {
				t.Fatal(d)
			}
			raw, e := value.ToTerraformValue(ctx)
			if e != nil {
				t.Fatal(e)
			}
			var resp tfprovider.ConfigureResponse
			p.Configure(ctx, tfprovider.ConfigureRequest{Config: tfsdk.Config{Schema: sr.Schema, Raw: raw}}, &resp)
			if resp.Diagnostics.HasError() != wantError {
				t.Fatalf("unexpected configuration result: %v", resp.Diagnostics)
			}
		})
	}
}
