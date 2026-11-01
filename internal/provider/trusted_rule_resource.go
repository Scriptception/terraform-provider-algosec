// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type trustedRuleResource struct{ c *client.Client }
type trustedRuleModel struct {
	ID             types.String `tfsdk:"id"`
	DeviceName     types.String `tfsdk:"device_name"`
	RuleID         types.String `tfsdk:"rule_id"`
	Comment        types.String `tfsdk:"comment"`
	ExpirationDate types.String `tfsdk:"expiration_date"`
}

func trustedID(device, rule string) string {
	return "v1." + base64.RawURLEncoding.EncodeToString([]byte(device)) + "." + base64.RawURLEncoding.EncodeToString([]byte(rule))
}
func parseTrustedID(id string) (string, string, error) {
	p := strings.Split(id, ".")
	if len(p) != 3 || p[0] != "v1" {
		return "", "", errors.New("expected v1.<base64url-device>.<base64url-rule> without padding")
	}
	d, e := base64.RawURLEncoding.Strict().DecodeString(p[1])
	if e != nil {
		return "", "", errors.New("invalid device token")
	}
	r, e := base64.RawURLEncoding.Strict().DecodeString(p[2])
	if e != nil {
		return "", "", errors.New("invalid rule token")
	}
	if trustedID(string(d), string(r)) != id {
		return "", "", errors.New("noncanonical import identity")
	}
	return string(d), string(r), client.ValidateTrustedIdentity(string(d), string(r))
}

type trustedValidator struct{ field string }

func (v trustedValidator) Description(context.Context) string {
	return "Exact nonblank identifier or valid YYYY-MM-DD expiration date."
}
func (v trustedValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v trustedValidator) ValidateString(_ context.Context, q validator.StringRequest, s *validator.StringResponse) {
	if q.ConfigValue.IsNull() || q.ConfigValue.IsUnknown() {
		return
	}
	value := q.ConfigValue.ValueString()
	var e error
	switch v.field {
	case "date":
		e = client.ValidateTrustedDate(value, false)
	case "device":
		e = client.ValidateTrustedIdentity(value, "rule")
	default:
		e = client.ValidateTrustedIdentity("device", value)
	}
	if e != nil {
		s.Diagnostics.AddAttributeError(q.Path, "Invalid trusted rule input", e.Error())
	}
}
func NewTrustedRuleResource() resource.Resource { return &trustedRuleResource{} }
func (r *trustedRuleResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_trusted_rule"
}
func (r *trustedRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	s.Schema = schema.Schema{Description: "Manages one A33.20 AFA trusted-rule assignment, not the firewall rule. Requires experimental_trusted_rules=true and complete administrator visibility. Public-contract tested only; no live acceptance. All changes replace (delete then create), temporarily removing trust. Do not use create_before_destroy or share assignment ownership.", Attributes: map[string]schema.Attribute{
		"id":              schema.StringAttribute{Computed: true, Description: "Import identity: v1.<unpadded base64url UTF-8 device_name>.<unpadded base64url UTF-8 rule_id>."},
		"device_name":     schema.StringAttribute{Required: true, Description: "Exact actual device tree name from device inventory. Groups, ALL_FIREWALLS and comma-containing names are unsupported. Changes replace.", Validators: []validator.String{trustedValidator{"device"}}, PlanModifiers: replace},
		"rule_id":         schema.StringAttribute{Required: true, Description: "Exact existing firewall rule ID. Changes replace.", Validators: []validator.String{trustedValidator{"rule"}}, PlanModifiers: replace},
		"comment":         schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Trust comment. Defaults to empty (omitted from create). Changes replace.", PlanModifiers: replace},
		"expiration_date": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "YYYY-MM-DD, strictly after the current UTC date when planning creation or replacement and rechecked when creating. Empty default omits expiry. Refresh preserves returned dates; it never guesses absence from the clock. If the server removes an expired assignment, extend or remove this date before recreating. Changes replace.", Validators: []validator.String{trustedValidator{"date"}}, PlanModifiers: replace},
	}}
}

var _ resource.ResourceWithModifyPlan = (*trustedRuleResource)(nil)

// Validate replacement inputs before Terraform can delete the existing assignment.
// Compare only managed inputs: the computed ID may be unknown on a changed plan.
func (r *trustedRuleResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return // Destroy must remain possible for an expired assignment.
	}
	var planned trustedRuleModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &planned)...)
	if s.Diagnostics.HasError() {
		return
	}
	if !q.State.Raw.IsNull() {
		var prior trustedRuleModel
		s.Diagnostics.Append(q.State.Get(ctx, &prior)...)
		if s.Diagnostics.HasError() {
			return
		}
		if planned.DeviceName.Equal(prior.DeviceName) && planned.RuleID.Equal(prior.RuleID) &&
			planned.Comment.Equal(prior.Comment) && planned.ExpirationDate.Equal(prior.ExpirationDate) {
			return // Refresh/import of unchanged expired metadata is valid.
		}
	}
	// Unknown expiry is preserved and checked when resolved; Create also rechecks
	// the UTC date in case it expires between planning and applying.
	if planned.ExpirationDate.IsUnknown() || planned.ExpirationDate.IsNull() {
		return
	}
	if err := client.ValidateTrustedDate(planned.ExpirationDate.ValueString(), true); err != nil {
		s.Diagnostics.AddAttributeError(path.Root("expiration_date"), "Invalid trusted rule expiration", err.Error())
	}
}
func (r *trustedRuleResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected AlgoSec client.")
	}
}
func (m trustedRuleModel) rule() client.TrustedRule {
	return client.TrustedRule{RuleID: m.RuleID.ValueString(), Comment: m.Comment.ValueString(), ExpirationDate: m.ExpirationDate.ValueString()}
}
func (r *trustedRuleResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m trustedRuleModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	for _, v := range []types.String{m.DeviceName, m.RuleID, m.Comment, m.ExpirationDate} {
		if v.IsNull() || v.IsUnknown() {
			s.Diagnostics.AddError("Unknown or null input", "All planned values must be known before create.")
			return
		}
	}
	got, e := r.c.CreateTrustedRule(ctx, m.DeviceName.ValueString(), m.rule(), func() {
		m.ID = types.StringValue(trustedID(m.DeviceName.ValueString(), m.RuleID.ValueString()))
		s.Diagnostics.Append(s.State.Set(ctx, &m)...)
	})
	if got != nil {
		m.Comment = types.StringValue(got.Comment)
		m.ExpirationDate = types.StringValue(got.ExpirationDate)
		s.Diagnostics.Append(s.State.Set(ctx, &m)...)
	}
	if e != nil {
		s.Diagnostics.AddError("Cannot create trusted rule", e.Error())
	}
}
func (r *trustedRuleResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	var m trustedRuleModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	got, e := r.c.TrustedRule(ctx, m.DeviceName.ValueString(), m.RuleID.ValueString())
	if errors.Is(e, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if e != nil {
		s.Diagnostics.AddError("Cannot read trusted rule", e.Error())
		return
	}
	m.ID = types.StringValue(trustedID(m.DeviceName.ValueString(), m.RuleID.ValueString()))
	m.Comment = types.StringValue(got.Comment)
	m.ExpirationDate = types.StringValue(got.ExpirationDate)
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
func (r *trustedRuleResource) Update(_ context.Context, _ resource.UpdateRequest, s *resource.UpdateResponse) {
	s.Diagnostics.AddError("Replacement required", "Trust metadata cannot be updated in place; create a replacement plan.")
}
func (r *trustedRuleResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	var m trustedRuleModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := r.c.DeleteTrustedRule(ctx, m.DeviceName.ValueString(), m.rule()); e != nil {
		s.Diagnostics.AddError("Cannot delete trusted rule", e.Error())
		return
	}
	s.State.RemoveResource(ctx)
}
func (r *trustedRuleResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	if e := r.c.TrustedRulesEnabled(); e != nil {
		s.Diagnostics.AddError("Trusted rules disabled", e.Error())
		return
	}
	d, id, e := parseTrustedID(q.ID)
	if e != nil {
		s.Diagnostics.AddError("Invalid import identity", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("id"), q.ID)...)
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("device_name"), d)...)
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("rule_id"), id)...)
}
