// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"strings"
	"unicode/utf8"
)

type aceThreatResource struct{ c *client.ACEClient }
type aceThreatModel struct {
	ID          types.String `tfsdk:"id"`
	Threat      types.String `tfsdk:"threat_type"`
	List        types.String `tfsdk:"list_type"`
	Destination types.String `tfsdk:"destination"`
	Description types.String `tfsdk:"description"`
	Severity    types.String `tfsdk:"severity"`
}

func NewACEThreatResource() resource.Resource { return &aceThreatResource{} }
func (r *aceThreatResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_ace_threat_list_entry"
}
func (r *aceThreatResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Owns one exact destination in an ACE custom threat list. Experimental: normalization and concurrent insertion semantics are unverified; use exact server spelling and one writer. Requires complete paginated visibility. All changes replace, temporarily removing the entry; do not use create_before_destroy. DELETE always includes the exact nonempty destination, never the whole list. No live acceptance.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true, Description: "Import ID: v1.<base64url(threat_type)>.<base64url(list_type)>.<base64url(destination)>, unpadded."},
		"threat_type": schema.StringAttribute{Required: true, Description: "Threat type. Changes replace.", Validators: []validator.String{stringvalidator.OneOf("ip-addresses", "domains", "open-ports", "countries", "cve", "malware-names")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"list_type":   schema.StringAttribute{Required: true, Description: "Custom block-list or allow-list. Changes replace.", Validators: []validator.String{stringvalidator.OneOf("block-list", "allow-list")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"destination": schema.StringAttribute{Required: true, Description: "Exact nonempty destination; no normalization. Changes replace.", Validators: []validator.String{appVizNameValidator{}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"description": schema.StringAttribute{Required: true, Description: "Entry description, including explicit empty string. Changes replace.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"severity":    schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Required low, medium, high or critical for block-list. Omit for allow-list. Changes replace.", Validators: []validator.String{stringvalidator.OneOf("", "low", "medium", "high", "critical")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
	}}
}
func (r *aceThreatResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	c, ok := q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected provider data", "Expected AlgoSec client.")
		return
	}
	r.c = c.ACE
}
func (m aceThreatModel) value() client.ACEThreatEntry {
	return client.ACEThreatEntry{ThreatType: m.Threat.ValueString(), ListType: m.List.ValueString(), Destination: m.Destination.ValueString(), Description: m.Description.ValueString(), Severity: m.Severity.ValueString()}
}
func aceThreatID(v client.ACEThreatEntry) string {
	parts := []string{"v1"}
	for _, s := range []string{v.ThreatType, v.ListType, v.Destination} {
		parts = append(parts, base64.RawURLEncoding.EncodeToString([]byte(s)))
	}
	return strings.Join(parts, ".")
}
func parseACEThreatID(id string) (client.ACEThreatEntry, error) {
	v := client.ACEThreatEntry{}
	p := strings.Split(id, ".")
	if len(p) != 4 || p[0] != "v1" {
		return v, errors.New("invalid threat entry import ID")
	}
	out := []string{}
	for _, s := range p[1:] {
		b, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil || !utf8.Valid(b) || base64.RawURLEncoding.EncodeToString(b) != s {
			return v, errors.New("invalid canonical base64url import ID")
		}
		out = append(out, string(b))
	}
	v.ThreatType = out[0]
	v.ListType = out[1]
	v.Destination = out[2]
	return v, nil
}
func aceThreatState(v client.ACEThreatEntry) aceThreatModel {
	return aceThreatModel{types.StringValue(aceThreatID(v)), types.StringValue(v.ThreatType), types.StringValue(v.ListType), types.StringValue(v.Destination), types.StringValue(v.Description), types.StringValue(v.Severity)}
}
func (r *aceThreatResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var m aceThreatModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := aceThreatPayloadSize(m); e != nil {
		s.Diagnostics.AddError("Invalid threat replacement payload", e.Error())
	}
	if !m.List.IsUnknown() && !m.Severity.IsUnknown() {
		v := m.value()
		v.ThreatType = "domains"
		v.Destination = "synthetic"
		if e := client.ValidateACEThreat(v); e != nil {
			s.Diagnostics.AddError("Invalid threat severity", e.Error())
		}
	}
}
func (r *aceThreatResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m aceThreatModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	v := m.value()
	if e := r.c.CreateThreatEntry(ctx, v); e != nil {
		s.Diagnostics.AddError("ACE threat creation failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceThreatState(v))...)
	got, e := r.c.ThreatEntry(ctx, v.ThreatType, v.ListType, v.Destination)
	if e != nil {
		s.Diagnostics.AddError("ACE threat readback failed", e.Error()+"; acknowledged identity retained.")
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceThreatState(*got))...)
	if *got != v {
		s.Diagnostics.AddError("ACE threat readback differs", "Acknowledged entry retained; refresh before retrying.")
	}
}
func (r *aceThreatResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	s.State = q.State
	var m aceThreatModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	v := m.value()
	got, e := r.c.ThreatEntry(ctx, v.ThreatType, v.ListType, v.Destination)
	if errors.Is(e, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if e != nil {
		s.Diagnostics.AddError("ACE threat read failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceThreatState(*got))...)
}
func (r *aceThreatResource) Update(_ context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	s.State = q.State
	s.Diagnostics.AddError("ACE threat requires replacement", "No public update operation exists.")
}
func (r *aceThreatResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	s.State = q.State
	var m aceThreatModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := r.c.DeleteThreatEntry(ctx, m.value()); e != nil {
		s.Diagnostics.AddError("ACE threat deletion failed", e.Error())
	}
}
func (r *aceThreatResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	v, e := parseACEThreatID(q.ID)
	if e == nil {
		var got *client.ACEThreatEntry
		got, e = r.c.ThreatEntry(ctx, v.ThreatType, v.ListType, v.Destination)
		if e == nil {
			s.Diagnostics.Append(s.State.Set(ctx, aceThreatState(*got))...)
			return
		}
	}
	s.Diagnostics.AddError("ACE threat import failed", e.Error())
}
