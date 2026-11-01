// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type fireFlowPermissionResource struct{ c *client.FireFlowClient }
type fireFlowPermissionModel struct {
	ID         types.String `tfsdk:"id"`
	RoleID     types.Int64  `tfsdk:"role_id"`
	Name       types.String `tfsdk:"permission_name"`
	ObjectType types.String `tfsdk:"object_type"`
	ObjectID   types.Int64  `tfsdk:"object_id"`
	Inherited  types.Bool   `tfsdk:"inherited"`
}

func (m fireFlowPermissionModel) ref() client.FireFlowPermissionRef {
	return client.FireFlowPermissionRef{Name: m.Name.ValueString(), ObjectType: m.ObjectType.ValueString(), ObjectID: m.ObjectID.ValueInt64()}
}
func fireFlowPermissionID(role int64, p client.FireFlowPermissionRef) string {
	return fmt.Sprintf("v1.%d.%s.%d.%s", role, p.ObjectType, p.ObjectID, base64.RawURLEncoding.EncodeToString([]byte(p.Name)))
}
func parseFireFlowPermissionID(id string) (fireFlowPermissionModel, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 5 || parts[0] != "v1" {
		return fireFlowPermissionModel{}, errors.New("expected v1.<role_id>.<object_type>.<object_id>.<unpadded base64url permission_name>")
	}
	role, e := strconv.ParseInt(parts[1], 10, 32)
	if e != nil {
		return fireFlowPermissionModel{}, errors.New("invalid role ID")
	}
	object, e := strconv.ParseInt(parts[3], 10, 32)
	if e != nil {
		return fireFlowPermissionModel{}, errors.New("invalid object ID")
	}
	name, e := base64.RawURLEncoding.Strict().DecodeString(parts[4])
	if e != nil {
		return fireFlowPermissionModel{}, errors.New("invalid permission token")
	}
	ref := client.FireFlowPermissionRef{Name: string(name), ObjectType: parts[2], ObjectID: object}
	if e = client.ValidateFireFlowPermission(role, ref); e != nil {
		return fireFlowPermissionModel{}, e
	}
	if fireFlowPermissionID(role, ref) != id {
		return fireFlowPermissionModel{}, errors.New("noncanonical permission identity")
	}
	return fireFlowPermissionModel{ID: types.StringValue(id), RoleID: types.Int64Value(role), Name: types.StringValue(ref.Name), ObjectType: types.StringValue(ref.ObjectType), ObjectID: types.Int64Value(object), Inherited: types.BoolUnknown()}, nil
}
func NewFireFlowPermissionResource() resource.Resource { return &fireFlowPermissionResource{} }
func (r *fireFlowPermissionResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_fireflow_role_permission"
}

type fireFlowNameValidator struct{}

func (fireFlowNameValidator) Description(context.Context) string {
	return "Exact nonblank UTF-8 permission name without control characters."
}
func (v fireFlowNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (fireFlowNameValidator) ValidateString(_ context.Context, q validator.StringRequest, s *validator.StringResponse) {
	if q.ConfigValue.IsNull() || q.ConfigValue.IsUnknown() {
		return
	}
	if e := client.ValidateAppVizName(q.ConfigValue.ValueString()); e != nil {
		s.Diagnostics.AddAttributeError(q.Path, "Invalid FireFlow permission name", e.Error())
	}
}
func (r *fireFlowPermissionResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	ints := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	stringsReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	s.Schema = schema.Schema{Description: "Owns one direct A33.30 FireFlow role permission tuple, preserving inherited and unrelated grants. Requires experimental_fireflow_bindings=true and separate verified-TLS FireFlow_Session authentication. System, CustomField and RequestTemplate permissions are persistent authorization, not execution of the named workflow action. All changes replace with a temporary direct-grant gap. Complete privileged visibility and exclusive tuple ownership required; no role/object ownership or live acceptance.", Attributes: map[string]schema.Attribute{
		"id":              schema.StringAttribute{Computed: true, Description: "Canonical import v1.<role_id>.<object_type>.<object_id>.<unpadded base64url UTF-8 permission_name>."},
		"role_id":         schema.Int64Attribute{Required: true, Description: "Existing role positive int32 ID. Changes replace.", Validators: []validator.Int64{int64validator.Between(1, math.MaxInt32)}, PlanModifiers: ints},
		"permission_name": schema.StringAttribute{Required: true, Description: "Exact permission name; availability is validated by FireFlow. Changes replace.", Validators: []validator.String{fireFlowNameValidator{}}, PlanModifiers: stringsReplace},
		"object_type":     schema.StringAttribute{Required: true, Description: "System, CustomField or RequestTemplate. Changes replace.", Validators: []validator.String{stringvalidator.OneOf("System", "CustomField", "RequestTemplate")}, PlanModifiers: stringsReplace},
		"object_id":       schema.Int64Attribute{Required: true, Description: "Exactly 0 for System; positive int32 referenced ID for CustomField/RequestTemplate. Changes replace.", Validators: []validator.Int64{int64validator.Between(0, math.MaxInt32)}, PlanModifiers: ints},
		"inherited":       schema.BoolAttribute{Computed: true, Description: "Whether this permission also has inherited access. Removing this resource removes only the direct grant; inherited access can remain."},
	}}
}
func (r *fireFlowPermissionResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	c, ok := q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected provider data", "Expected AlgoSec client.")
		return
	}
	r.c = c.FireFlow
}
func (r *fireFlowPermissionResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var m fireFlowPermissionModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if !m.Name.IsUnknown() {
		known := m.ref()
		if m.ObjectType.IsUnknown() {
			known.ObjectType = "System"
		}
		if m.ObjectID.IsUnknown() {
			known.ObjectID = 0
		}
		if e := client.ValidateFireFlowPermissionSize(known); e != nil {
			s.Diagnostics.AddError("Invalid FireFlow permission payload", e.Error())
		}
	}
	if !m.ObjectType.IsUnknown() && !m.ObjectID.IsUnknown() {
		role := m.RoleID.ValueInt64()
		if m.RoleID.IsUnknown() {
			role = 1
		}
		ref := m.ref()
		if m.Name.IsUnknown() {
			ref.Name = "permission"
		}
		if e := client.ValidateFireFlowPermission(role, ref); e != nil {
			s.Diagnostics.AddError("Invalid FireFlow permission", e.Error())
		}
	}
}
func (r *fireFlowPermissionResource) observe(ctx context.Context, m fireFlowPermissionModel) (bool, bool, error) {
	rows, err := r.c.Permissions(ctx, m.RoleID.ValueInt64())
	if err != nil {
		return false, false, err
	}
	for _, v := range rows {
		if v.FireFlowPermissionRef == m.ref() {
			return v.Direct, v.Inherited, nil
		}
	}
	return false, false, nil
}
func (r *fireFlowPermissionResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m fireFlowPermissionModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if err := client.ValidateFireFlowPermission(m.RoleID.ValueInt64(), m.ref()); err != nil {
		s.Diagnostics.AddError("Invalid FireFlow permission", err.Error())
		return
	}
	if err := client.ValidateFireFlowPermissionSize(m.ref()); err != nil {
		s.Diagnostics.AddError("Invalid FireFlow permission payload", err.Error())
		return
	}
	present, inherited, err := r.observe(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot check direct permission", err.Error())
		return
	}
	if present {
		s.Diagnostics.AddError("Direct permission already exists", "Import the exact tuple before managing it.")
		return
	}
	if err = r.c.ChangePermission(ctx, m.RoleID.ValueInt64(), m.ref(), true); err != nil {
		s.Diagnostics.AddError("Cannot add direct permission", err.Error()+" Unconfirmed/partial success never acquires ownership; inspect before import or retry.")
		return
	}
	m.ID = types.StringValue(fireFlowPermissionID(m.RoleID.ValueInt64(), m.ref()))
	m.Inherited = types.BoolValue(inherited)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
	present, inherited, err = r.observe(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh acknowledged permission", err.Error())
		return
	}
	m.Inherited = types.BoolValue(inherited)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
	if !present {
		s.Diagnostics.AddError("Permission readback mismatch", "Acknowledged direct tuple retained for recovery.")
	}
}
func (r *fireFlowPermissionResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	var m fireFlowPermissionModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	m, err := parseFireFlowPermissionID(m.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid permission identity", err.Error())
		return
	}
	present, inherited, err := r.observe(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot read direct permission", err.Error())
		return
	}
	if !present {
		s.State.RemoveResource(ctx)
		return
	}
	m.Inherited = types.BoolValue(inherited)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
func (r *fireFlowPermissionResource) Update(_ context.Context, _ resource.UpdateRequest, s *resource.UpdateResponse) {
	s.Diagnostics.AddError("Replacement required", "All permission changes require replacement.")
}
func (r *fireFlowPermissionResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	var m fireFlowPermissionModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	m, err := parseFireFlowPermissionID(m.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid permission identity", err.Error())
		return
	}
	present, _, err := r.observe(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot check direct permission", err.Error())
		return
	}
	if !present {
		return
	}
	if err = r.c.ChangePermission(ctx, m.RoleID.ValueInt64(), m.ref(), false); err != nil {
		s.Diagnostics.AddError("Cannot remove direct permission", err.Error())
		return
	}
	present, _, err = r.observe(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh removed permission", err.Error())
		return
	}
	if present {
		s.Diagnostics.AddError("Direct permission remains", "State retained; inspect before retry.")
	}
}
func (r *fireFlowPermissionResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	m, err := parseFireFlowPermissionID(q.ID)
	if err != nil {
		s.Diagnostics.AddError("Invalid permission import", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
