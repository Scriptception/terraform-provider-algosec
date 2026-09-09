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

type trustedTrafficDataSource struct{ c *client.Client }
type trustedTrafficItem struct {
	ID                  types.Int64  `tfsdk:"id"`
	Source              types.String `tfsdk:"source"`
	Destination         types.String `tfsdk:"destination"`
	Service             types.String `tfsdk:"service"`
	Comment             types.String `tfsdk:"comment"`
	ExpirationDate      types.Int64  `tfsdk:"expiration_date"`
	DisplayTrafficLevel types.String `tfsdk:"display_traffic_level"`
	TrustFutureChanges  types.Bool   `tfsdk:"trust_future_host_group_changes"`
}
type trustedTrafficModel struct {
	ID         types.String         `tfsdk:"id"`
	DeviceName types.String         `tfsdk:"device_name"`
	Entries    []trustedTrafficItem `tfsdk:"entries"`
}

func NewTrustedTrafficDataSource() datasource.DataSource { return &trustedTrafficDataSource{} }
func (r *trustedTrafficDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_trusted_traffic"
}
func (r *trustedTrafficDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Read-only trusted-traffic inventory for a device tree name or ALL_FIREWALLS. Reads all advertised pages; the upstream API can omit zero-hit rows, so this data source is not an authoritative drift source for mutations.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true, Description: "Lookup identity."},
		"device_name": schema.StringAttribute{Required: true, Description: "Device name.", Validators: []validator.String{identifierValidator{}}},
		"entries": schema.ListNestedAttribute{Computed: true, Description: "Complete returned inventory, deterministically ordered.", NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"id":                              schema.Int64Attribute{Computed: true, Description: "Id."},
			"source":                          schema.StringAttribute{Computed: true, Description: "Source."},
			"destination":                     schema.StringAttribute{Computed: true, Description: "Destination."},
			"service":                         schema.StringAttribute{Computed: true, Description: "Service."},
			"comment":                         schema.StringAttribute{Computed: true, Description: "Comment."},
			"expiration_date":                 schema.Int64Attribute{Computed: true, Description: "Expiration date. Unix milliseconds; null if absent."},
			"display_traffic_level":           schema.StringAttribute{Computed: true, Description: "Display traffic level."},
			"trust_future_host_group_changes": schema.BoolAttribute{Computed: true, Description: "Trust future host group changes."},
		}}}}}
}
func (r *trustedTrafficDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *trustedTrafficDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m trustedTrafficModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	items, err := r.c.TrustedTraffic(ctx, m.DeviceName.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot read trusted_traffic", err.Error())
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	m.Entries = make([]trustedTrafficItem, 0, len(items))
	for _, v := range items {
		x := trustedTrafficItem{}
		x.ID = types.Int64Value(v.ID)
		x.Source = types.StringValue(v.Source)
		x.Destination = types.StringValue(v.Destination)
		x.Service = types.StringValue(v.Service)
		x.Comment = types.StringValue(v.Comment)
		x.ExpirationDate = types.Int64PointerValue(v.ExpirationDate)
		x.DisplayTrafficLevel = types.StringValue(v.DisplayTrafficLevel)
		x.TrustFutureChanges = types.BoolPointerValue(v.TrustFutureChanges)
		m.Entries = append(m.Entries, x)
	}
	m.ID = types.StringValue("trusted_traffic")
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
