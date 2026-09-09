// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type aceEmailsResource struct{ c *client.ACEClient }
type aceEmailsModel struct {
	ID       types.String `tfsdk:"id"`
	Provider types.String `tfsdk:"cloud_provider"`
	Emails   types.Set    `tfsdk:"emails"`
}

func NewACEEmailsResource() resource.Resource { return &aceEmailsResource{} }
func (r *aceEmailsResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_ace_cd_notification_emails"
}
func (r *aceEmailsResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Owns the complete nonempty ACE CD notification email set for one cloud provider. Requires experimental_ace_public_contracts. Selective PATCH preserves protection and threat management; destroy explicitly clears only emails. Import existing sets. Exclusive ownership and complete visibility required; no atomic concurrency guarantee or live acceptance.", Attributes: map[string]schema.Attribute{
		"id":             schema.StringAttribute{Computed: true, Description: "Cloud provider; import uses aws, azure or gcp."},
		"cloud_provider": schema.StringAttribute{Required: true, Description: "aws, azure or gcp. Changes replace.", Validators: []validator.String{stringvalidator.OneOf("aws", "azure", "gcp")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"emails":         schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "Complete nonempty set of notification addresses. Spelling is preserved. Destroy sends an explicit empty list.", Validators: []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(aceEmailValidator{})}},
	}}
}

type aceEmailValidator struct{}

func (aceEmailValidator) Description(context.Context) string             { return "Plain nonempty email address." }
func (v aceEmailValidator) MarkdownDescription(c context.Context) string { return v.Description(c) }
func (aceEmailValidator) ValidateString(_ context.Context, q validator.StringRequest, s *validator.StringResponse) {
	if q.ConfigValue.IsUnknown() {
		return
	}
	if q.ConfigValue.IsNull() || client.ValidateACEEmail(q.ConfigValue.ValueString()) != nil {
		s.Diagnostics.AddAttributeError(q.Path, "Invalid email", "Use a nonempty plain email address.")
	}
}
func (r *aceEmailsResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var m aceEmailsModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() || m.Emails.IsNull() || m.Emails.IsUnknown() {
		return
	}
	values := []any{}
	for _, value := range m.Emails.Elements() {
		if stringValue, ok := value.(types.String); ok && !stringValue.IsUnknown() && !stringValue.IsNull() {
			values = append(values, stringValue.ValueString())
		}
	}
	payload := map[string]any{"violationNotifications": map[string]any{"emails": values}}
	if e := client.ValidateACESerializedPayload(payload); e != nil {
		s.Diagnostics.AddError("Invalid email replacement payload", e.Error())
	}
}
func (r *aceEmailsResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
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
func aceEmailsState(p string, e []string) aceEmailsModel {
	v := []attr.Value{}
	for _, s := range e {
		v = append(v, types.StringValue(s))
	}
	return aceEmailsModel{types.StringValue(p), types.StringValue(p), types.SetValueMust(types.StringType, v)}
}
func (r *aceEmailsResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m aceEmailsModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	var v []string
	s.Diagnostics.Append(m.Emails.ElementsAs(ctx, &v, false)...)
	if s.Diagnostics.HasError() {
		return
	}
	p := m.Provider.ValueString()
	if e := r.c.CreateCDEmails(ctx, p, v); e != nil {
		s.Diagnostics.AddError("ACE email creation failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceEmailsState(p, v))...)
	got, e := r.c.CDEmails(ctx, p)
	if e != nil {
		s.Diagnostics.AddError("ACE email readback failed", e.Error()+"; acknowledged identity retained.")
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceEmailsState(p, got))...)
	if !client.SameACEEmails(v, got) {
		s.Diagnostics.AddError("ACE email readback differs", "Acknowledged identity retained; refresh before retrying.")
	}
}
func (r *aceEmailsResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	s.State = q.State
	var m aceEmailsModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	v, e := r.c.CDEmails(ctx, m.ID.ValueString())
	if e != nil {
		s.Diagnostics.AddError("ACE email read failed", e.Error())
		return
	}
	if len(v) == 0 {
		s.State.RemoveResource(ctx)
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceEmailsState(m.ID.ValueString(), v))...)
}
func (r *aceEmailsResource) Update(ctx context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	s.State = q.State
	var a, b aceEmailsModel
	s.Diagnostics.Append(q.State.Get(ctx, &a)...)
	s.Diagnostics.Append(q.Plan.Get(ctx, &b)...)
	var old, next []string
	s.Diagnostics.Append(a.Emails.ElementsAs(ctx, &old, false)...)
	s.Diagnostics.Append(b.Emails.ElementsAs(ctx, &next, false)...)
	if s.Diagnostics.HasError() {
		return
	}
	if len(next) == 0 {
		s.Diagnostics.AddError("Invalid emails", "Managed emails must be nonempty.")
		return
	}
	if e := r.c.ChangeCDEmails(ctx, a.ID.ValueString(), old, next); e != nil {
		s.Diagnostics.AddError("ACE email update failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceEmailsState(a.ID.ValueString(), next))...)
	got, e := r.c.CDEmails(ctx, a.ID.ValueString())
	if e != nil {
		s.Diagnostics.AddError("ACE email readback failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceEmailsState(a.ID.ValueString(), got))...)
	if !client.SameACEEmails(next, got) {
		s.Diagnostics.AddError("ACE email readback differs", "Owned set retained; refresh before retrying.")
	}
}
func (r *aceEmailsResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	s.State = q.State
	var m aceEmailsModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	var old []string
	s.Diagnostics.Append(m.Emails.ElementsAs(ctx, &old, false)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := r.c.ChangeCDEmails(ctx, m.ID.ValueString(), old, []string{}); e != nil {
		s.Diagnostics.AddError("ACE email deletion failed", e.Error())
		return
	}
	got, e := r.c.CDEmails(ctx, m.ID.ValueString())
	if e != nil {
		s.Diagnostics.AddError("ACE email deletion readback failed", e.Error())
		return
	}
	if len(got) != 0 {
		s.Diagnostics.AddError("ACE email deletion unconfirmed", "Email set is still nonempty; state retained.")
	}
}
func (r *aceEmailsResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	v, e := r.c.CDEmails(ctx, q.ID)
	if e != nil {
		s.Diagnostics.AddError("ACE email import failed", e.Error())
		return
	}
	if len(v) == 0 {
		s.Diagnostics.AddError("ACE email import failed", "Cannot import an empty email set.")
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, aceEmailsState(q.ID, v))...)
}
