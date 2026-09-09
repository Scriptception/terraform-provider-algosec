// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type deviceDataSource struct{ c *client.Client }
type deviceLookupModel struct {
	ID     types.String `tfsdk:"id"`
	Name   types.String `tfsdk:"name"`
	Device *devicesItem `tfsdk:"device"`
}

func NewDeviceDataSource() datasource.DataSource { return &deviceDataSource{} }
func (r *deviceDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_device"
}
func (r *deviceDataSource) Schema(ctx context.Context, q datasource.SchemaRequest, s *datasource.SchemaResponse) {
	var base datasource.SchemaResponse
	(&devicesDataSource{}).Schema(ctx, q, &base)
	attrs := base.Schema.Attributes["devices"].(schema.ListNestedAttribute).NestedObject.Attributes
	s.Schema = schema.Schema{Description: "Look up one device by exact unique tree name using the administrator-visible inventory. Display names are not unique. Passwords are discarded.", Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true, Description: "Device tree name."}, "name": schema.StringAttribute{Required: true, Description: "Unique device tree name.", Validators: []validator.String{identifierValidator{}}}, "device": schema.SingleNestedAttribute{Computed: true, Description: "Allowlisted device information.", Attributes: attrs}}}
}
func (r *deviceDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *deviceDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m deviceLookupModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	v, err := r.c.Device(ctx, m.Name.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot read device", err.Error())
		return
	}
	m.ID = types.StringValue(v.Name)
	m.Device = &devicesItem{Name: types.StringValue(v.Name), DisplayName: types.StringValue(v.DisplayName), OriginalName: types.StringValue(v.OriginalName), Brand: types.StringValue(v.Brand), BrandName: types.StringValue(v.BrandName), HostName: types.StringValue(v.HostName), NodeType: types.StringValue(v.NodeType), Collector: types.StringValue(v.Collector), BaselineProfile: types.StringValue(v.BaselineProfile)}
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
