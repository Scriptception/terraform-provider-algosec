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

type securityZonesDataSource struct{ c *client.Client }
type securityZonesItem struct {
	Name      types.String `tfsdk:"name"`
	Addresses types.Set    `tfsdk:"addresses"`
}
type securityZonesModel struct {
	ID          types.String        `tfsdk:"id"`
	ProfileFile types.String        `tfsdk:"profile_file"`
	Zones       []securityZonesItem `tfsdk:"zones"`
}

func NewSecurityZonesDataSource() datasource.DataSource { return &securityZonesDataSource{} }
func (r *securityZonesDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_security_zones"
}
func (r *securityZonesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Security-zone definitions from a risk-profile spreadsheet. Accepts the documented array and status/data response forms.", Attributes: map[string]schema.Attribute{
		"id":           schema.StringAttribute{Computed: true, Description: "Lookup identity."},
		"profile_file": schema.StringAttribute{Required: true, Description: "Profile file.", Validators: []validator.String{identifierValidator{}}},
		"zones": schema.ListNestedAttribute{Computed: true, Description: "Complete returned inventory, deterministically ordered.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"name":      schema.StringAttribute{Computed: true, Description: "Name."},
			"addresses": schema.SetAttribute{Computed: true, Description: "Addresses.", ElementType: types.StringType},
		}}}}}
}
func (r *securityZonesDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *securityZonesDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m securityZonesModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	items, err := r.c.SecurityZones(ctx, m.ProfileFile.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot read security_zones", err.Error())
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	m.Zones = make([]securityZonesItem, 0, len(items))
	for _, v := range items {
		x := securityZonesItem{}
		x.Name = types.StringValue(v.Name)
		val, d := types.SetValueFrom(ctx, types.StringType, v.Addresses)
		s.Diagnostics.Append(d...)
		x.Addresses = val
		m.Zones = append(m.Zones, x)
	}
	m.ID = types.StringValue("security_zones")
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
