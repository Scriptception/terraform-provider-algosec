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

type deviceGroupsDataSource struct{ c *client.Client }
type groupFirewallItem struct {
	EntityType   types.String `tfsdk:"entity_type"`
	InternalName types.String `tfsdk:"internal_name"`
	DisplayName  types.String `tfsdk:"display_name"`
}
type deviceGroupItem struct {
	EntityType   types.String        `tfsdk:"entity_type"`
	InternalName types.String        `tfsdk:"internal_name"`
	DisplayName  types.String        `tfsdk:"display_name"`
	Firewalls    []groupFirewallItem `tfsdk:"firewalls"`
}
type deviceGroupsModel struct {
	ID     types.String      `tfsdk:"id"`
	Groups []deviceGroupItem `tfsdk:"groups"`
}

func groupDataAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"entity_type":   schema.StringAttribute{Computed: true, Description: "Group entity type."},
		"internal_name": schema.StringAttribute{Computed: true, Description: "Internal group name."},
		"display_name":  schema.StringAttribute{Computed: true, Description: "Exact case-sensitive group display name."},
		"firewalls": schema.ListNestedAttribute{Computed: true, Description: "Member firewalls ordered by exact display name.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"entity_type":   schema.StringAttribute{Computed: true, Description: "Firewall entity type."},
			"internal_name": schema.StringAttribute{Computed: true, Description: "Internal firewall name."},
			"display_name":  schema.StringAttribute{Computed: true, Description: "Exact firewall display name used for membership writes."},
		}}},
	}
}
func flattenDeviceGroup(g client.DeviceGroup) deviceGroupItem {
	m := deviceGroupItem{EntityType: types.StringValue(g.EntityType), InternalName: types.StringValue(g.Name), DisplayName: types.StringValue(g.DisplayName), Firewalls: []groupFirewallItem{}}
	sort.Slice(g.Firewalls, func(i, j int) bool { return g.Firewalls[i].DisplayName < g.Firewalls[j].DisplayName })
	for _, f := range g.Firewalls {
		m.Firewalls = append(m.Firewalls, groupFirewallItem{types.StringValue(f.EntityType), types.StringValue(f.Name), types.StringValue(f.DisplayName)})
	}
	return m
}
func NewDeviceGroupsDataSource() datasource.DataSource { return &deviceGroupsDataSource{} }
func (r *deviceGroupsDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_device_groups"
}
func (r *deviceGroupsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	s.Schema = schema.Schema{Description: groupExperimental + "Reads the complete group inventory.", Attributes: map[string]schema.Attribute{
		"id":     schema.StringAttribute{Computed: true, Description: "Lookup identity."},
		"groups": schema.ListNestedAttribute{Computed: true, Description: "Complete validated inventory ordered by display name.", NestedObject: schema.NestedAttributeObject{Attributes: groupDataAttributes()}},
	}}
}
func (r *deviceGroupsDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *deviceGroupsDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m deviceGroupsModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	groups, err := r.c.DeviceGroups(ctx)
	if err != nil {
		s.Diagnostics.AddError("Cannot read experimental device groups", err.Error())
		return
	}
	m.ID = types.StringValue("device_groups")
	m.Groups = []deviceGroupItem{}
	for _, g := range groups {
		m.Groups = append(m.Groups, flattenDeviceGroup(g))
	}
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
