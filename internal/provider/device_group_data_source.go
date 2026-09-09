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

type deviceGroupDataSource struct{ c *client.Client }
type deviceGroupDataModel struct {
	ID          types.String     `tfsdk:"id"`
	DisplayName types.String     `tfsdk:"display_name"`
	Group       *deviceGroupItem `tfsdk:"group"`
}

func NewDeviceGroupDataSource() datasource.DataSource { return &deviceGroupDataSource{} }
func (r *deviceGroupDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_device_group"
}
func (r *deviceGroupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	s.Schema = schema.Schema{Description: groupExperimental + "Looks up an exact display name in the complete inventory. Missing or ambiguous groups are errors.", Attributes: map[string]schema.Attribute{
		"id":           schema.StringAttribute{Computed: true, Description: "Exact group display name."},
		"display_name": schema.StringAttribute{Required: true, Description: "Case-sensitive group display name, not internal name.", Validators: []validator.String{groupNameValidator{}}},
		"group":        schema.SingleNestedAttribute{Computed: true, Description: "Validated group and typed firewall members.", Attributes: groupDataAttributes()},
	}}
}
func (r *deviceGroupDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *deviceGroupDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m deviceGroupDataModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if m.DisplayName.IsUnknown() || m.DisplayName.IsNull() {
		s.Diagnostics.AddError("Unknown or null display name", "display_name must be known and non-null before reading.")
		return
	}
	g, err := r.c.DeviceGroup(ctx, m.DisplayName.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot read experimental device group", err.Error())
		return
	}
	m.ID = m.DisplayName
	v := flattenDeviceGroup(*g)
	m.Group = &v
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
