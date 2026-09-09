// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/Scriptception/terraform-provider-algosec/internal/testserver"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"strings"
	"testing"
)

func TestProviderConfigMissingNullUnknown(t *testing.T) {
	for _, n := range []string{"ALGOSEC_URL", "ALGOSEC_SESSION_ID", "ALGOSEC_USERNAME", "ALGOSEC_PASSWORD"} {
		t.Setenv(n, "")
	}
	for _, tc := range []struct {
		name      string
		values    map[string]any
		wantError bool
	}{
		{"missing", nil, true},
		{"unknown_url", map[string]any{"url": tftypes.UnknownValue}, true},
		{"unknown_secret", map[string]any{"url": "https://example.invalid", "session_id": tftypes.UnknownValue}, true},
		{"unknown_groups", map[string]any{"url": "https://example.invalid", "session_id": "secret123", "experimental_device_groups": tftypes.UnknownValue}, true},
		{"unknown_safety", map[string]any{"url": "https://example.invalid", "session_id": "secret123", "read_only": tftypes.UnknownValue}, true},
		{"explicit_empty", map[string]any{"url": "", "session_id": "secret123"}, true},
		{"valid_null_defaults", map[string]any{"url": "https://example.invalid", "session_id": "secret123"}, false},
		{"timeout_zero", map[string]any{"url": "https://example.invalid", "session_id": "secret123", "timeout_seconds": 0}, true},
		{"conflicting_auth", map[string]any{"url": "https://example.invalid", "session_id": "secret123", "password": "secret456"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := providerserver.NewProtocol6(New("test")())()
			schema, err := p.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
			if err != nil {
				t.Fatal(err)
			}
			typ := schema.Provider.ValueType().(tftypes.Object)
			values := map[string]tftypes.Value{}
			for k, v := range typ.AttributeTypes {
				values[k] = tftypes.NewValue(v, tc.values[k])
			}
			dv, err := tfprotov6.NewDynamicValue(typ, tftypes.NewValue(typ, values))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := p.ConfigureProvider(context.Background(), &tfprotov6.ConfigureProviderRequest{Config: &dv})
			if err != nil {
				t.Fatal(err)
			}
			hasError := false
			for _, d := range resp.Diagnostics {
				if d.Severity == tfprotov6.DiagnosticSeverityError {
					hasError = true
				}
				if strings.Contains(d.Detail, "secret123") || strings.Contains(d.Detail, "secret456") {
					t.Fatal("credential leaked")
				}
			}
			if hasError != tc.wantError {
				t.Fatalf("error=%v want %v", hasError, tc.wantError)
			}
		})
	}
}
func categoryState(t *testing.T, r *urlCategoryResource) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	var sr resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sr)
	state := tfsdk.State{Schema: sr.Schema}
	urls, _ := types.MapValueFrom(ctx, types.SetType{ElemType: types.StringType}, map[string]types.Set{})
	m := categoryModel{ID: types.StringValue("test"), Name: types.StringValue("test"), URLs: urls}
	if d := state.Set(ctx, &m); d.HasError() {
		t.Fatal(d)
	}
	return state
}
func TestRefreshRetainsStateOnFailure(t *testing.T) {
	ctx := context.Background()
	s := testserver.New()
	defer s.Close()
	c, _ := client.New(client.Options{URL: s.URL, SessionID: testserver.Session, Insecure: true})
	r := &urlCategoryResource{c}
	state := categoryState(t, r)
	s.FailReads = true
	resp := resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatal("read failure discarded state")
	}
	s.Mu.Lock()
	s.FailReads = false
	s.Mu.Unlock()
	resp = resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Fatal("definitive absence not removed")
	}
}
func TestDeleteRequiresReadBack(t *testing.T) {
	ctx := context.Background()
	s := testserver.New()
	defer s.Close()
	s.Categories["test"] = client.Category{URLs: map[string][]string{}}
	s.NoopDelete = true
	c, _ := client.New(client.Options{URL: s.URL, SessionID: testserver.Session, Insecure: true})
	r := &urlCategoryResource{c}
	state := categoryState(t, r)
	resp := resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("unconfirmed deletion accepted")
	}
}
