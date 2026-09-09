// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"errors"
	"strconv"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type appVizRoleResource struct{ c *client.AppVizClient }
type appVizRoleModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	Users        types.Set    `tfsdk:"users"`
	Permissions  types.Set    `tfsdk:"permissions"`
	Applications types.Map    `tfsdk:"application_permissions"`
}

func NewAppVizRoleResource() resource.Resource { return &appVizRoleResource{} }
func (r *appVizRoleResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_appviz_role"
}

type appVizNameValidator struct{}

func (appVizNameValidator) Description(context.Context) string {
	return "Nonblank UTF-8 name without control characters."
}
func (v appVizNameValidator) MarkdownDescription(c context.Context) string { return v.Description(c) }
func (appVizNameValidator) ValidateString(_ context.Context, q validator.StringRequest, s *validator.StringResponse) {
	if q.ConfigValue.IsNull() || q.ConfigValue.IsUnknown() {
		return
	}
	if e := client.ValidateAppVizName(q.ConfigValue.ValueString()); e != nil {
		s.Diagnostics.AddAttributeError(q.Path, "Invalid AppViz name", e.Error())
	}
}

type appVizApplicationsValidator struct{}

func (appVizApplicationsValidator) Description(context.Context) string {
	return "Canonical positive application revision IDs mapped to view or edit."
}
func (v appVizApplicationsValidator) MarkdownDescription(c context.Context) string {
	return v.Description(c)
}
func (appVizApplicationsValidator) ValidateMap(_ context.Context, q validator.MapRequest, s *validator.MapResponse) {
	if q.ConfigValue.IsNull() || q.ConfigValue.IsUnknown() {
		return
	}
	for id, v := range q.ConfigValue.Elements() {
		n, e := strconv.ParseInt(id, 10, 64)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
			s.Diagnostics.AddAttributeError(q.Path, "Invalid application revision ID", "Use canonical positive integer application revision IDs.")
		}
		if v.IsUnknown() {
			continue
		}
		p := v.(types.String)
		if p.IsNull() || (p.ValueString() != "view" && p.ValueString() != "edit") {
			s.Diagnostics.AddAttributeError(q.Path, "Invalid application permission", "Permission must be view or edit.")
		}
	}
}
func (r *appVizRoleResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Manages an AppViz SaaS Early Availability role, including complete user membership and allowed global/application permission sets. Requires experimental_appviz_roles=true and separate SaaS bearer authentication. Public-schema tested only; no live acceptance. Import existing roles explicitly. Name, enabled and application permission changes replace, temporarily removing the role; do not use create_before_destroy for same-name replacement. Description and LDAP linkage are not managed because the public GET omits them. Use dedicated roles with no external writers.", Attributes: map[string]schema.Attribute{
		"id":                      schema.StringAttribute{Computed: true, Description: "Exact case-sensitive role name; also the import identifier."},
		"name":                    schema.StringAttribute{Required: true, Description: "Case-sensitive role name. Changes replace.", Validators: []validator.String{appVizNameValidator{}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"enabled":                 schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), Description: "Whether the role is enabled. Defaults true. Changes replace because the documented update does not set enabled.", PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()}},
		"users":                   schema.SetAttribute{Optional: true, Computed: true, ElementType: types.StringType, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), Description: "Complete set of existing user names assigned to this role; defaults empty."},
		"permissions":             schema.SetAttribute{Optional: true, Computed: true, ElementType: types.StringType, Default: setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})), Description: "Complete set of allowed global permission names. Defaults empty. The server validates permission availability."},
		"application_permissions": schema.MapAttribute{Optional: true, Computed: true, ElementType: types.StringType, Default: mapdefault.StaticValue(types.MapValueMust(types.StringType, map[string]attr.Value{})), Description: "Application revision IDs mapped to view or edit. Defaults empty. Changes replace to avoid guessing the order of same-application permission removal and addition.", Validators: []validator.Map{appVizApplicationsValidator{}}, PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()}},
	}}
}
func (r *appVizRoleResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	c, ok := q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected provider data", "Expected AlgoSec client.")
		return
	}
	r.c = c.AppViz
}
func (m appVizRoleModel) role(ctx context.Context) (client.AppVizRole, error) {
	v := client.AppVizRole{Name: m.Name.ValueString(), Enabled: m.Enabled.ValueBool(), Users: []string{}, Permissions: []string{}, Applications: map[string]string{}}
	if d := m.Users.ElementsAs(ctx, &v.Users, false); d.HasError() {
		return v, errors.New("user names must be known and non-null")
	}
	if d := m.Permissions.ElementsAs(ctx, &v.Permissions, false); d.HasError() {
		return v, errors.New("permission names must be known and non-null")
	}
	if d := m.Applications.ElementsAs(ctx, &v.Applications, false); d.HasError() {
		return v, errors.New("application permissions must be known and non-null")
	}
	return v, client.ValidateAppVizRole(v)
}
func roleModel(v client.AppVizRole) appVizRoleModel {
	u := []attr.Value{}
	for _, s := range v.Users {
		u = append(u, types.StringValue(s))
	}
	p := []attr.Value{}
	for _, s := range v.Permissions {
		p = append(p, types.StringValue(s))
	}
	a := map[string]attr.Value{}
	for k, s := range v.Applications {
		a[k] = types.StringValue(s)
	}
	return appVizRoleModel{ID: types.StringValue(v.Name), Name: types.StringValue(v.Name), Enabled: types.BoolValue(v.Enabled), Users: types.SetValueMust(types.StringType, u), Permissions: types.SetValueMust(types.StringType, p), Applications: types.MapValueMust(types.StringType, a)}
}

// Check known inputs before replacement can destroy an existing role, including
// individual known elements when other set/map elements remain unknown.
func (r *appVizRoleResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var m appVizRoleModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	for _, set := range []types.Set{m.Users, m.Permissions} {
		if set.IsNull() || set.IsUnknown() {
			continue
		}
		for _, v := range set.Elements() {
			if v.IsUnknown() {
				continue
			}
			if v.IsNull() || client.ValidateAppVizName(v.(types.String).ValueString()) != nil {
				s.Diagnostics.AddError("Invalid role membership or permission", "Known user and permission names must be nonblank UTF-8 without control characters.")
			}
		}
	}
}
func (r *appVizRoleResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m appVizRoleModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	plan, e := m.role(ctx)
	if e != nil {
		s.Diagnostics.AddError("Invalid AppViz role", e.Error())
		return
	}
	ack, e := r.c.CreateRole(ctx, plan)
	if e != nil {
		s.Diagnostics.AddError("AppViz role creation failed", e.Error())
		return
	}
	// The create response, never a subsequent same-name lookup, establishes state.
	s.Diagnostics.Append(s.State.Set(ctx, roleModel(*ack))...)
	current, e := r.c.Role(ctx, ack.Name)
	if e != nil {
		s.Diagnostics.AddError("AppViz role readback failed", e.Error()+"; acknowledged role identity retained.")
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, roleModel(*current))...)
	if !client.SameAppVizRole(plan, *current) {
		s.Diagnostics.AddError("AppViz role readback differs", "Acknowledged role retained. Refresh and inspect permissions before retrying.")
	}
}
func (r *appVizRoleResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	s.State = q.State
	var m appVizRoleModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	current, e := r.c.Role(ctx, m.ID.ValueString())
	if errors.Is(e, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if e != nil {
		s.Diagnostics.AddError("AppViz role read failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, roleModel(*current))...)
}
func (r *appVizRoleResource) Update(ctx context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	s.State = q.State
	var old, next appVizRoleModel
	s.Diagnostics.Append(q.State.Get(ctx, &old)...)
	s.Diagnostics.Append(q.Plan.Get(ctx, &next)...)
	if s.Diagnostics.HasError() {
		return
	}
	a, e := old.role(ctx)
	if e != nil {
		s.Diagnostics.AddError("Invalid prior AppViz role", e.Error())
		return
	}
	b, e := next.role(ctx)
	if e != nil {
		s.Diagnostics.AddError("Invalid AppViz role", e.Error())
		return
	}
	ack, e := r.c.UpdateRole(ctx, a, b)
	if e != nil {
		s.Diagnostics.AddError("AppViz role update failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, roleModel(*ack))...)
	current, e := r.c.Role(ctx, ack.Name)
	if e != nil {
		s.Diagnostics.AddError("AppViz role readback failed", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, roleModel(*current))...)
	if !client.SameAppVizRole(b, *current) {
		s.Diagnostics.AddError("AppViz role readback differs", "Updated role retained; inspect permissions and refresh before retrying.")
	}
}
func (r *appVizRoleResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	s.State = q.State
	var m appVizRoleModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	v, e := m.role(ctx)
	if e == nil {
		e = r.c.DeleteRole(ctx, v)
	}
	if e != nil {
		s.Diagnostics.AddError("AppViz role deletion failed", e.Error())
	}
}
func (r *appVizRoleResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	if e := client.ValidateAppVizName(q.ID); e != nil {
		s.Diagnostics.AddError("Invalid AppViz role import", e.Error())
		return
	}
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("id"), q.ID)...)
}
