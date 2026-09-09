// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"sort"
)

type deviceZonesDataSource struct{ c *client.Client }
type deviceZonesItem struct {
	Name       types.String `tfsdk:"name"`
	DeviceName types.String `tfsdk:"device_name"`
	Interfaces types.Set    `tfsdk:"interfaces"`
	IPAddress  types.String `tfsdk:"ip_address"`
}
type deviceZonesModel struct {
	ID         types.String      `tfsdk:"id"`
	DeviceName types.String      `tfsdk:"device_name"`
	Zones      []deviceZonesItem `tfsdk:"zones"`
}

func NewDeviceZonesDataSource() datasource.DataSource { return &deviceZonesDataSource{} }
func (r *deviceZonesDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_device_zones"
}
func (r *deviceZonesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Topology zones from analyzed device data. Partial results reported by additionalInformation fail rather than silently returning an incomplete inventory.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true, Description: "Lookup identity."},
		"device_name": schema.StringAttribute{Required: true, Description: "Device name.", Validators: []validator.String{identifierValidator{}}},
		"zones": schema.ListNestedAttribute{Computed: true, Description: "Complete returned inventory, deterministically ordered.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"name":        schema.StringAttribute{Computed: true, Description: "Name."},
			"device_name": schema.StringAttribute{Computed: true, Description: "Device name."},
			"interfaces":  schema.SetAttribute{Computed: true, Description: "Interfaces.", ElementType: types.StringType},
			"ip_address":  schema.StringAttribute{Computed: true, Description: "Ip address."},
		}}}}}
}
func (r *deviceZonesDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *deviceZonesDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m deviceZonesModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	items, err := r.c.DeviceZones(ctx, m.DeviceName.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot read device_zones", err.Error())
		return
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].DeviceName != items[j].DeviceName {
			return items[i].DeviceName < items[j].DeviceName
		}
		return items[i].Name < items[j].Name
	})
	m.Zones = make([]deviceZonesItem, 0, len(items))
	for _, v := range items {
		x := deviceZonesItem{}
		x.Name = types.StringValue(v.Name)
		x.DeviceName = types.StringValue(v.DeviceName)
		val, d := types.SetValueFrom(ctx, types.StringType, v.Interfaces)
		s.Diagnostics.Append(d...)
		x.Interfaces = val
		x.IPAddress = types.StringValue(v.IPAddress)
		m.Zones = append(m.Zones, x)
	}
	m.ID = types.StringValue("device_zones")
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
