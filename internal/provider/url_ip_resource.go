// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type urlIPResource struct{ c *client.URLIPClient }
type urlIPModel struct {
	ID       types.String `tfsdk:"id"`
	Category types.String `tfsdk:"category"`
	URL      types.String `tfsdk:"url"`
	IP       types.String `tfsdk:"ip"`
}

func urlIPID(category, url, ip string) string {
	return "v1." + base64.RawURLEncoding.EncodeToString([]byte(category)) + "." + base64.RawURLEncoding.EncodeToString([]byte(url)) + "." + base64.RawURLEncoding.EncodeToString([]byte(ip))
}
func parseURLIPID(id string) (urlIPModel, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return urlIPModel{}, errors.New("expected v1.<base64url category>.<base64url URL>.<base64url IP>, unpadded")
	}
	values := []string{}
	for _, part := range parts[1:] {
		v, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			return urlIPModel{}, errors.New("invalid base64url import token")
		}
		values = append(values, string(v))
	}
	if urlIPID(values[0], values[1], values[2]) != id {
		return urlIPModel{}, errors.New("noncanonical import identity")
	}
	if err := client.ValidateURLIP(values[0], values[1], values[2]); err != nil {
		return urlIPModel{}, err
	}
	return urlIPModel{ID: types.StringValue(id), Category: types.StringValue(values[0]), URL: types.StringValue(values[1]), IP: types.StringValue(values[2])}, nil
}

type urlIPValidator struct{ ip bool }

func (v urlIPValidator) Description(context.Context) string {
	return "Exact nonempty identifier or individual unscoped IP address."
}
func (v urlIPValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v urlIPValidator) ValidateString(_ context.Context, q validator.StringRequest, s *validator.StringResponse) {
	if q.ConfigValue.IsNull() || q.ConfigValue.IsUnknown() {
		return
	}
	var err error
	if v.ip {
		err = client.ValidateURLIP("category", "url", q.ConfigValue.ValueString())
	} else {
		_, err = client.Segment(q.ConfigValue.ValueString())
	}
	if err != nil {
		s.Diagnostics.AddAttributeError(q.Path, "Invalid URL/IP input", err.Error())
	}
}
func NewURLIPResource() resource.Resource { return &urlIPResource{} }
func (r *urlIPResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_url_ip_membership"
}
func (r *urlIPResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	s.Schema = schema.Schema{Description: "Owns one IP assignment to an existing Panorama URL in an existing category, using the A33.20 public contract. Requires experimental_url_ip_memberships=true; not available in A32.60. Other IPs and URLs are preserved. Never overlap algosec_url_category whole-category ownership, duplicate tuple ownership or concurrent writers. All changes replace with a temporary assignment gap. Administrator visibility and appliance override-file prerequisites apply. Synthetic-contract tested only; no live acceptance or automatic newer-version compatibility claim.", Attributes: map[string]schema.Attribute{
		"id":       schema.StringAttribute{Computed: true, Description: "v1.<unpadded base64url UTF-8 category>.<unpadded base64url UTF-8 URL>.<unpadded base64url UTF-8 IP>; exact supplied values are preserved."},
		"category": schema.StringAttribute{Required: true, Description: "Exact existing category name. Changes replace.", Validators: []validator.String{urlIPValidator{}}, PlanModifiers: replace},
		"url":      schema.StringAttribute{Required: true, Description: "Exact existing URL key. Changes replace.", Validators: []validator.String{urlIPValidator{}}, PlanModifiers: replace},
		"ip":       schema.StringAttribute{Required: true, Description: "One unscoped IPv4 or IPv6 address, without CIDR prefix. Spelling is preserved; changes replace.", Validators: []validator.String{urlIPValidator{ip: true}}, PlanModifiers: replace},
	}}
}
func (r *urlIPResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	c, ok := q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected provider data", "Expected AlgoSec client.")
		return
	}
	r.c = c.URLIPs
}
func (m urlIPModel) validate() error {
	return client.ValidateURLIP(m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString())
}
func (r *urlIPResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m urlIPModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if err := m.validate(); err != nil {
		s.Diagnostics.AddError("Invalid URL/IP input", err.Error())
		return
	}
	if err := r.c.RequireParent(ctx, m.Category.ValueString(), m.URL.ValueString()); err != nil {
		s.Diagnostics.AddError("Cannot read URL parent", err.Error())
		return
	}
	present, err := r.c.Present(ctx, m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot check IP ownership", err.Error())
		return
	}
	if present {
		s.Diagnostics.AddError("IP assignment already exists", "Import the exact tuple; do not overlap whole-category ownership.")
		return
	}
	if err = r.c.Change(ctx, m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString(), true); err != nil {
		s.Diagnostics.AddError("Cannot assign IP", err.Error()+" Unconfirmed writes never adopt from later reads; inspect ownership before import or retry.")
		return
	}
	m.ID = types.StringValue(urlIPID(m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString()))
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
	present, err = r.c.Present(ctx, m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh acknowledged IP assignment", err.Error())
		return
	}
	if !present {
		s.Diagnostics.AddError("IP assignment readback mismatch", "Acknowledged tuple retained for recovery.")
	}
}
func (r *urlIPResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	var m urlIPModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	parsed, err := parseURLIPID(m.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid IP identity", err.Error())
		return
	}
	present, err := r.c.Present(ctx, parsed.Category.ValueString(), parsed.URL.ValueString(), parsed.IP.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot read IP assignment", err.Error())
		return
	}
	if !present {
		s.State.RemoveResource(ctx)
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, parsed)...)
}
func (r *urlIPResource) Update(_ context.Context, _ resource.UpdateRequest, s *resource.UpdateResponse) {
	s.Diagnostics.AddError("Replacement required", "All IP assignment changes require replacement.")
}
func (r *urlIPResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	var m urlIPModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	m, err := parseURLIPID(m.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid IP identity", err.Error())
		return
	}
	present, err := r.c.Present(ctx, m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot check IP assignment", err.Error())
		return
	}
	if !present {
		return
	}
	if err = r.c.Change(ctx, m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString(), false); err != nil {
		s.Diagnostics.AddError("Cannot remove IP assignment", err.Error())
		return
	}
	present, err = r.c.Present(ctx, m.Category.ValueString(), m.URL.ValueString(), m.IP.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh removed IP assignment", err.Error())
		return
	}
	if present {
		s.Diagnostics.AddError("IP assignment remains", "State retained; inspect before retry.")
	}
}
func (r *urlIPResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	m, err := parseURLIPID(q.ID)
	if err != nil {
		s.Diagnostics.AddError("Invalid IP import", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
