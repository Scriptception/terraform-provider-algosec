// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"errors"
	"strconv"

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

type tagResource struct{ c *client.TagClient }
type tagModel struct {
	ID    types.String `tfsdk:"id"`
	Name  types.String `tfsdk:"name"`
	Scope types.String `tfsdk:"scope"`
	Type  types.String `tfsdk:"type"`
}
type tagValidator struct{ scope bool }

func (v tagValidator) Description(context.Context) string {
	return "Canonical tag name/scope without surrounding whitespace or control characters."
}
func (v tagValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v tagValidator) ValidateString(_ context.Context, q validator.StringRequest, s *validator.StringResponse) {
	if q.ConfigValue.IsNull() || q.ConfigValue.IsUnknown() {
		return
	}
	name, scope := q.ConfigValue.ValueString(), ""
	if v.scope {
		name, scope = "tag", name
	}
	if err := client.ValidateTagInput(name, scope); err != nil {
		s.Diagnostics.AddAttributeError(q.Path, "Invalid tag input", err.Error())
	}
}
func NewTagResource() resource.Resource { return &tagResource{} }
func (r *tagResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_tag"
}
func (r *tagResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Manages an A33.30 vendor Early Availability ALGOSEC tag. Requires experimental_tags=true. Numeric ID is immutable; names refresh by unfiltered paginated inventory, using short-page termination. Scope changes replace. Delete refuses loaded hostgroup associations. Full administrator visibility and exclusive writers required; association checks are not atomic and risk-profile reference behavior is unverified. Synthetic public-contract tests only; no live acceptance.", Attributes: map[string]schema.Attribute{
		"id":    schema.StringAttribute{Computed: true, Description: "Positive decimal int64 tag ID; canonical numeric import identifier.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"name":  schema.StringAttribute{Required: true, Description: "Exact canonical tag name. Rename updates the same numeric ID.", Validators: []validator.String{tagValidator{}}},
		"scope": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Canonical scope, default empty. Changes replace.", Validators: []validator.String{tagValidator{scope: true}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"type":  schema.StringAttribute{Computed: true, Description: "Always ALGOSEC; DEVICE tags cannot be imported.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
	}}
}
func (r *tagResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	c, ok := q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected provider data", "Expected AlgoSec client.")
		return
	}
	r.c = c.Tags
}
func parseTagID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != s {
		return 0, errors.New("tag import ID must be a canonical positive decimal int64")
	}
	return id, nil
}
func tagState(v client.Tag) tagModel {
	return tagModel{ID: types.StringValue(strconv.FormatInt(v.ID, 10)), Name: types.StringValue(v.Name), Scope: types.StringValue(v.Scope), Type: types.StringValue(v.Type)}
}
func (r *tagResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m tagModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if err := client.ValidateTagInput(m.Name.ValueString(), m.Scope.ValueString()); err != nil {
		s.Diagnostics.AddError("Invalid tag input", err.Error())
		return
	}
	all, err := r.c.List(ctx)
	if err != nil {
		s.Diagnostics.AddError("Cannot check tag ownership", err.Error())
		return
	}
	for _, v := range all {
		if v.Name == m.Name.ValueString() && v.Scope == m.Scope.ValueString() && v.Type == "ALGOSEC" {
			s.Diagnostics.AddError("Tag already exists", "Import its numeric ID before managing it.")
			return
		}
	}
	got, err := r.c.Create(ctx, m.Name.ValueString(), m.Scope.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot create tag", err.Error()+" An unconfirmed create is never adopted; inspect and verify ownership before import or retry.")
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, tagState(got))...)
	fresh, err := r.c.Get(ctx, got.ID)
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh acknowledged tag", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, tagState(fresh))...)
	if fresh.Name != got.Name || fresh.Scope != got.Scope {
		s.Diagnostics.AddError("Tag readback mismatch", "Acknowledged numeric identity retained; refresh and inspect concurrent changes.")
	}
}
func (r *tagResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	var m tagModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	id, err := parseTagID(m.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid tag identity", err.Error())
		return
	}
	got, err := r.c.Get(ctx, id)
	if errors.Is(err, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot read tag", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, tagState(got))...)
}
func (r *tagResource) Update(ctx context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	var old, next tagModel
	s.Diagnostics.Append(q.State.Get(ctx, &old)...)
	s.Diagnostics.Append(q.Plan.Get(ctx, &next)...)
	if s.Diagnostics.HasError() {
		return
	}
	id, err := parseTagID(old.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid tag identity", err.Error())
		return
	}
	if err = client.ValidateTagInput(next.Name.ValueString(), next.Scope.ValueString()); err != nil {
		s.Diagnostics.AddError("Invalid tag input", err.Error())
		return
	}
	if !old.Scope.Equal(next.Scope) {
		s.Diagnostics.AddError("Tag scope requires replacement", "Scope cannot be renamed.")
		return
	}
	current, err := r.c.Get(ctx, id)
	if err != nil {
		s.Diagnostics.AddError("Cannot check tag before rename", err.Error())
		return
	}
	if current.Name != old.Name.ValueString() || current.Scope != old.Scope.ValueString() {
		s.Diagnostics.AddError("Tag changed since refresh", "Refresh the plan before renaming.")
		return
	}
	if err = r.c.Rename(ctx, id, next.Name.ValueString()); err != nil {
		s.Diagnostics.AddError("Cannot rename tag", err.Error())
		return
	}
	current.Name = next.Name.ValueString()
	s.Diagnostics.Append(s.State.Set(ctx, tagState(current))...)
	got, err := r.c.Get(ctx, id)
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh renamed tag", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, tagState(got))...)
	if got.Name != next.Name.ValueString() || got.Scope != old.Scope.ValueString() {
		s.Diagnostics.AddError("Tag readback mismatch", "Numeric identity retained; inspect concurrent changes.")
	}
}
func (r *tagResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	var m tagModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	id, err := parseTagID(m.ID.ValueString())
	if err == nil {
		err = r.c.Delete(ctx, id)
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot delete tag", err.Error())
	}
}
func (r *tagResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	if _, err := parseTagID(q.ID); err != nil {
		s.Diagnostics.AddError("Invalid tag import", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("id"), q.ID)...)
}
