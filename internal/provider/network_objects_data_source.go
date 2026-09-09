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

type networkObjectsDataSource struct{ c *client.Client }
type networkObjectsItem struct {
	ID            types.Int64  `tfsdk:"id"`
	CanonizedName types.String `tfsdk:"canonized_name"`
	OriginalName  types.String `tfsdk:"original_name"`
	IPAddress     types.String `tfsdk:"ip_address"`
	IPType        types.String `tfsdk:"ip_type"`
	Members       types.String `tfsdk:"members"`
	Zone          types.String `tfsdk:"zone"`
}
type networkObjectsModel struct {
	ID         types.String         `tfsdk:"id"`
	DeviceName types.String         `tfsdk:"device_name"`
	Query      types.String         `tfsdk:"query"`
	Objects    []networkObjectsItem `tfsdk:"objects"`
}

func NewNetworkObjectsDataSource() datasource.DataSource { return &networkObjectsDataSource{} }
func (r *networkObjectsDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_network_objects"
}
func (r *networkObjectsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Matching network objects from the documented paginated search. Reads all pages, bounded at 1000 pages of 100. Fails on duplicate IDs, inconsistent metadata or incomplete results. Query may be empty.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true, Description: "Lookup identity."},
		"device_name": schema.StringAttribute{Required: true, Description: "Device name.", Validators: []validator.String{identifierValidator{}}},
		"query":       schema.StringAttribute{Required: true, Description: "Search text; an empty string matches all objects."},
		"objects": schema.ListNestedAttribute{Computed: true, Description: "Complete returned inventory, deterministically ordered.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"id":             schema.Int64Attribute{Computed: true, Description: "Id."},
			"canonized_name": schema.StringAttribute{Computed: true, Description: "Canonized name."},
			"original_name":  schema.StringAttribute{Computed: true, Description: "Original name."},
			"ip_address":     schema.StringAttribute{Computed: true, Description: "Ip address."},
			"ip_type":        schema.StringAttribute{Computed: true, Description: "Ip type."},
			"members":        schema.StringAttribute{Computed: true, Description: "Members."},
			"zone":           schema.StringAttribute{Computed: true, Description: "Zone."},
		}}}}}
}
func (r *networkObjectsDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *networkObjectsDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m networkObjectsModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	items, err := r.c.NetworkObjects(ctx, m.DeviceName.ValueString(), m.Query.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot read network_objects", err.Error())
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	m.Objects = make([]networkObjectsItem, 0, len(items))
	for _, v := range items {
		x := networkObjectsItem{}
		x.ID = types.Int64Value(v.ID)
		x.CanonizedName = types.StringValue(v.CanonizedName)
		x.OriginalName = types.StringValue(v.OriginalName)
		x.IPAddress = types.StringValue(v.IPAddress)
		x.IPType = types.StringValue(v.IPType)
		x.Members = types.StringValue(v.Members)
		x.Zone = types.StringValue(v.Zone)
		m.Objects = append(m.Objects, x)
	}
	m.ID = types.StringValue("network_objects")
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
