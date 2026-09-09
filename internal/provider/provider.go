// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"os"
	"time"
)

type AlgoSecProvider struct{ version string }
type providerModel struct {
	ExperimentalDeviceGroups types.Bool   `tfsdk:"experimental_device_groups"`
	URL                      types.String `tfsdk:"url"`
	Username                 types.String `tfsdk:"username"`
	Password                 types.String `tfsdk:"password"`
	SessionID                types.String `tfsdk:"session_id"`
	Insecure                 types.Bool   `tfsdk:"insecure"`
	ReadOnly                 types.Bool   `tfsdk:"read_only"`
	Timeout                  types.Int64  `tfsdk:"timeout_seconds"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &AlgoSecProvider{version} }
}
func (p *AlgoSecProvider) Metadata(_ context.Context, _ provider.MetadataRequest, r *provider.MetadataResponse) {
	r.TypeName = "algosec"
	r.Version = p.version
}
func (p *AlgoSecProvider) Schema(_ context.Context, _ provider.SchemaRequest, r *provider.SchemaResponse) {
	r.Schema = schema.Schema{Description: "Unofficial AlgoSec Firewall Analyzer / ASMS A32.60 provider with separately gated experimental A33.20 device groups. Uses protocol 6 and HTTPS. Prefer environment credentials; read_only defaults to true.", Attributes: map[string]schema.Attribute{
		"experimental_device_groups": schema.BoolAttribute{Optional: true, Description: "EXPERIMENTAL ASMS A33.20 Early Availability device groups. Defaults to false. AlgoSec does not recommend these APIs for production. Requires complete administrator inventory visibility."},
		"url":                        schema.StringAttribute{Optional: true, Description: "HTTPS appliance origin, without a path. Environment: ALGOSEC_URL.", Validators: []validator.String{originValidator{}}},
		"username":                   schema.StringAttribute{Optional: true, Description: "ASMS login username. Environment: ALGOSEC_USERNAME. Mutually exclusive with session_id."},
		"password":                   schema.StringAttribute{Optional: true, Sensitive: true, Description: "ASMS login password. Prefer ALGOSEC_PASSWORD to avoid configuration/plan persistence."},
		"session_id":                 schema.StringAttribute{Optional: true, Sensitive: true, Description: "Existing PHPSESSID session. Prefer ALGOSEC_SESSION_ID. Mutually exclusive with username/password. Sessions are not refreshed or logged out by this provider."},
		"insecure":                   schema.BoolAttribute{Optional: true, Description: "Disable TLS verification explicitly. Defaults to false. Install the appliance CA in the system trust store instead when possible."},
		"read_only":                  schema.BoolAttribute{Optional: true, Description: "Refuse all administration writes. Defaults to true; set false to manage resources. Authentication may establish an API session."},
		"timeout_seconds":            schema.Int64Attribute{Optional: true, Description: "Per-request timeout, 1–300 seconds. Defaults to 30. No requests are automatically retried.", Validators: []validator.Int64{int64validator.Between(1, 300)}},
	}}
}
func (p *AlgoSecProvider) Configure(ctx context.Context, req provider.ConfigureRequest, r *provider.ConfigureResponse) {
	var m providerModel
	r.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if r.Diagnostics.HasError() {
		return
	}
	for n, v := range map[string]types.String{"url": m.URL, "username": m.Username, "password": m.Password, "session_id": m.SessionID} {
		if v.IsUnknown() {
			r.Diagnostics.AddAttributeError(path.Root(n), "Unknown provider configuration", "Provider settings must be known before configuring the client.")
		}
	}
	if m.ExperimentalDeviceGroups.IsUnknown() || m.Insecure.IsUnknown() || m.ReadOnly.IsUnknown() || m.Timeout.IsUnknown() {
		r.Diagnostics.AddError("Unknown provider configuration", "Safety and timeout settings must be known before configuring the client.")
	}
	if r.Diagnostics.HasError() {
		return
	}
	str := func(v types.String, env string) string {
		if v.IsNull() {
			return os.Getenv(env)
		}
		return v.ValueString()
	}
	timeout := int64(30)
	if !m.Timeout.IsNull() {
		timeout = m.Timeout.ValueInt64()
	}
	if timeout < 1 || timeout > 300 {
		r.Diagnostics.AddError("Invalid timeout", "timeout_seconds must be between 1 and 300.")
		return
	}
	readOnly := true
	if !m.ReadOnly.IsNull() {
		readOnly = m.ReadOnly.ValueBool()
	}
	c, err := client.New(client.Options{URL: str(m.URL, "ALGOSEC_URL"), Username: str(m.Username, "ALGOSEC_USERNAME"), Password: str(m.Password, "ALGOSEC_PASSWORD"), SessionID: str(m.SessionID, "ALGOSEC_SESSION_ID"), Timeout: time.Duration(timeout) * time.Second, Insecure: m.Insecure.ValueBool(), ReadOnly: readOnly, ExperimentalDeviceGroups: m.ExperimentalDeviceGroups.ValueBool()})
	if err != nil {
		r.Diagnostics.AddError("Invalid AlgoSec configuration", err.Error())
		return
	}
	r.ResourceData = c
	r.DataSourceData = c
}
func (p *AlgoSecProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewURLCategoryResource, NewDeviceGroupResource}
}
func (p *AlgoSecProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewURLCategoriesDataSource, NewURLCategoryDataSource, NewDevicesDataSource, NewDeviceDataSource, NewRiskProfilesDataSource, NewRiskProfileFilesDataSource, NewSecurityZonesDataSource, NewDeviceZonesDataSource, NewNetworkObjectsDataSource, NewTrustedTrafficDataSource, NewDeviceGroupDataSource, NewDeviceGroupsDataSource,
	}
}
