// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"sort"
)

type devicesDataSource struct{ c *client.Client }
type devicesItem struct {
	Name            types.String `tfsdk:"name"`
	DisplayName     types.String `tfsdk:"display_name"`
	OriginalName    types.String `tfsdk:"original_name"`
	Brand           types.String `tfsdk:"brand"`
	BrandName       types.String `tfsdk:"brand_name"`
	HostName        types.String `tfsdk:"host_name"`
	NodeType        types.String `tfsdk:"node_type"`
	Collector       types.String `tfsdk:"collector"`
	BaselineProfile types.String `tfsdk:"baseline_profile"`
}
type devicesModel struct {
	ID      types.String  `tfsdk:"id"`
	Devices []devicesItem `tfsdk:"devices"`
}

func NewDevicesDataSource() datasource.DataSource { return &devicesDataSource{} }
func (r *devicesDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_devices"
}
func (r *devicesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Administrator-visible device inventory. Only allowlisted non-secret fields are retained; device credentials are discarded.", Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true, Description: "Lookup identity."},
		"devices": schema.ListNestedAttribute{Computed: true, Description: "Complete returned inventory, deterministically ordered.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"name":             schema.StringAttribute{Computed: true, Description: "Name."},
			"display_name":     schema.StringAttribute{Computed: true, Description: "Display name."},
			"original_name":    schema.StringAttribute{Computed: true, Description: "Original name."},
			"brand":            schema.StringAttribute{Computed: true, Description: "Brand."},
			"brand_name":       schema.StringAttribute{Computed: true, Description: "Brand name."},
			"host_name":        schema.StringAttribute{Computed: true, Description: "Host name."},
			"node_type":        schema.StringAttribute{Computed: true, Description: "Node type."},
			"collector":        schema.StringAttribute{Computed: true, Description: "Collector."},
			"baseline_profile": schema.StringAttribute{Computed: true, Description: "Baseline profile."},
		}}}}}
}
func (r *devicesDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *devicesDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m devicesModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	items, err := r.c.Devices(ctx)
	if err != nil {
		s.Diagnostics.AddError("Cannot read devices", err.Error())
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	m.Devices = make([]devicesItem, 0, len(items))
	for _, v := range items {
		x := devicesItem{}
		x.Name = types.StringValue(v.Name)
		x.DisplayName = types.StringValue(v.DisplayName)
		x.OriginalName = types.StringValue(v.OriginalName)
		x.Brand = types.StringValue(v.Brand)
		x.BrandName = types.StringValue(v.BrandName)
		x.HostName = types.StringValue(v.HostName)
		x.NodeType = types.StringValue(v.NodeType)
		x.Collector = types.StringValue(v.Collector)
		x.BaselineProfile = types.StringValue(v.BaselineProfile)
		m.Devices = append(m.Devices, x)
	}
	m.ID = types.StringValue("devices")
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
