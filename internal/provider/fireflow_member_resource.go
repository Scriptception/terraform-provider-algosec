// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
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

type fireFlowMemberResource struct{ c *client.FireFlowClient }
type fireFlowMemberModel struct {
	ID         types.String `tfsdk:"id"`
	RoleID     types.Int64  `tfsdk:"role_id"`
	MemberID   types.Int64  `tfsdk:"member_id"`
	MemberType types.String `tfsdk:"member_type"`
}

func (m fireFlowMemberModel) ref() client.FireFlowMemberRef {
	return client.FireFlowMemberRef{ID: m.MemberID.ValueInt64(), Type: m.MemberType.ValueString()}
}
func fireFlowMemberID(role int64, m client.FireFlowMemberRef) string {
	return fmt.Sprintf("v1.%d.%s.%d", role, m.Type, m.ID)
}
func parseFireFlowMemberID(id string) (fireFlowMemberModel, error) {
	parts := strings.Split(id, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return fireFlowMemberModel{}, errors.New("expected v1.<role_id>.<User|Role>.<member_id>")
	}
	role, e := strconv.ParseInt(parts[1], 10, 32)
	if e != nil {
		return fireFlowMemberModel{}, errors.New("invalid role ID")
	}
	member, e := strconv.ParseInt(parts[3], 10, 32)
	if e != nil {
		return fireFlowMemberModel{}, errors.New("invalid member ID")
	}
	ref := client.FireFlowMemberRef{ID: member, Type: parts[2]}
	if e = client.ValidateFireFlowMember(role, ref); e != nil {
		return fireFlowMemberModel{}, e
	}
	if fireFlowMemberID(role, ref) != id {
		return fireFlowMemberModel{}, errors.New("noncanonical membership identity")
	}
	return fireFlowMemberModel{ID: types.StringValue(id), RoleID: types.Int64Value(role), MemberID: types.Int64Value(member), MemberType: types.StringValue(ref.Type)}, nil
}
func NewFireFlowMemberResource() resource.Resource { return &fireFlowMemberResource{} }
func (r *fireFlowMemberResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_fireflow_role_member"
}
func (r *fireFlowMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	ints := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	s.Schema = schema.Schema{Description: "Owns one direct User or Role membership of an existing A33.30 FireFlow role. Requires experimental_fireflow_bindings=true and a separate FireFlow_Session client with verified TLS. Preserves inherited/unrelated memberships and role metadata. Role members are the inverse of parent-role links; never own the same edge twice. All changes replace, temporarily removing direct membership. Complete administrator/SeeRole visibility and exclusive tuple ownership required; no live acceptance.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true, Description: "Canonical import identity v1.<role_id>.<User|Role>.<member_id>."},
		"role_id":     schema.Int64Attribute{Required: true, Description: "Existing parent role's positive int32 ID. Changes replace.", Validators: []validator.Int64{int64validator.Between(1, math.MaxInt32)}, PlanModifiers: ints},
		"member_id":   schema.Int64Attribute{Required: true, Description: "Existing User or Role positive int32 ID; disabled/missing principals are errors. Changes replace.", Validators: []validator.Int64{int64validator.Between(1, math.MaxInt32)}, PlanModifiers: ints},
		"member_type": schema.StringAttribute{Required: true, Description: "Exact principal type User or Role. A role cannot contain itself; server cycle/dependency errors remain errors. Changes replace.", Validators: []validator.String{stringvalidator.OneOf("User", "Role")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
	}}
}
func (r *fireFlowMemberResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
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
func (r *fireFlowMemberResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var m fireFlowMemberModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() || m.RoleID.IsUnknown() || m.MemberID.IsUnknown() || m.MemberType.IsUnknown() {
		return
	}
	if err := client.ValidateFireFlowMember(m.RoleID.ValueInt64(), m.ref()); err != nil {
		s.Diagnostics.AddError("Invalid FireFlow membership", err.Error())
	}
}
func (r *fireFlowMemberResource) present(ctx context.Context, m fireFlowMemberModel) (bool, error) {
	rows, err := r.c.Members(ctx, m.RoleID.ValueInt64())
	if err != nil {
		return false, err
	}
	for _, v := range rows {
		if v.FireFlowMemberRef == m.ref() {
			return v.Direct, nil
		}
	}
	return false, nil
}
func (r *fireFlowMemberResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m fireFlowMemberModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if err := client.ValidateFireFlowMember(m.RoleID.ValueInt64(), m.ref()); err != nil {
		s.Diagnostics.AddError("Invalid FireFlow membership", err.Error())
		return
	}
	present, err := r.present(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot check direct membership", err.Error())
		return
	}
	if present {
		s.Diagnostics.AddError("Direct membership already exists", "Import the exact tuple before managing it.")
		return
	}
	if err = r.c.ChangeMember(ctx, m.RoleID.ValueInt64(), m.ref(), true); err != nil {
		s.Diagnostics.AddError("Cannot add direct member", err.Error()+" Unconfirmed/partial success never acquires ownership; inspect before import or retry.")
		return
	}
	m.ID = types.StringValue(fireFlowMemberID(m.RoleID.ValueInt64(), m.ref()))
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
	present, err = r.present(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh acknowledged membership", err.Error())
		return
	}
	if !present {
		s.Diagnostics.AddError("Membership readback mismatch", "Acknowledged direct tuple retained for recovery.")
	}
}
func (r *fireFlowMemberResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	var m fireFlowMemberModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	m, err := parseFireFlowMemberID(m.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid membership identity", err.Error())
		return
	}
	present, err := r.present(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot read direct membership", err.Error())
		return
	}
	if !present {
		s.State.RemoveResource(ctx)
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
func (r *fireFlowMemberResource) Update(_ context.Context, _ resource.UpdateRequest, s *resource.UpdateResponse) {
	s.Diagnostics.AddError("Replacement required", "All membership changes require replacement.")
}
func (r *fireFlowMemberResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	var m fireFlowMemberModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	m, err := parseFireFlowMemberID(m.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Invalid membership identity", err.Error())
		return
	}
	present, err := r.present(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot check direct membership", err.Error())
		return
	}
	if !present {
		return
	}
	if err = r.c.ChangeMember(ctx, m.RoleID.ValueInt64(), m.ref(), false); err != nil {
		s.Diagnostics.AddError("Cannot remove direct member", err.Error())
		return
	}
	present, err = r.present(ctx, m)
	if err != nil {
		s.Diagnostics.AddError("Cannot refresh removed membership", err.Error())
		return
	}
	if present {
		s.Diagnostics.AddError("Direct membership remains", "State retained; inspect before retry.")
	}
}
func (r *fireFlowMemberResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	m, err := parseFireFlowMemberID(q.ID)
	if err != nil {
		s.Diagnostics.AddError("Invalid membership import", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
