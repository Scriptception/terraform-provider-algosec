// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"errors"
	"strings"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const groupExperimental = "EXPERIMENTAL ASMS A33.20 Early Availability API. Requires experimental_device_groups=true and complete administrator inventory visibility. AlgoSec does not recommend these APIs for production use. "

type deviceGroupResource struct{ c *client.Client }
type deviceGroupModel struct {
	ID           types.String `tfsdk:"id"`
	DisplayName  types.String `tfsdk:"display_name"`
	InternalName types.String `tfsdk:"internal_name"`
	Members      types.Set    `tfsdk:"members"`
}
type groupNameValidator struct{ member bool }

func (v groupNameValidator) Description(context.Context) string {
	return "Nonblank exact display name; case and whitespace are preserved."
}
func (v groupNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v groupNameValidator) ValidateString(_ context.Context, q validator.StringRequest, s *validator.StringResponse) {
	if q.ConfigValue.IsUnknown() {
		return
	}
	if q.ConfigValue.IsNull() {
		if v.member {
			s.Diagnostics.AddAttributeError(q.Path, "Invalid members", "Device display names must not be null.")
		}
		return
	}
	var err error
	if v.member {
		if strings.TrimSpace(q.ConfigValue.ValueString()) == "" {
			err = errors.New("device display names must be nonblank")
		}
	} else {
		err = client.ValidateGroupName(q.ConfigValue.ValueString())
	}
	if err != nil {
		s.Diagnostics.AddAttributeError(q.Path, "Invalid display name", err.Error())
	}
}
func NewDeviceGroupResource() resource.Resource { return &deviceGroupResource{} }
func (r *deviceGroupResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_device_group"
}
func (r *deviceGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	s.Schema = schema.Schema{Description: groupExperimental + "Authoritatively manages a non-empty set of existing device display names. Adds new members before removing old members. Destroy removes only the group and associations, leaving physical devices intact.", Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true, Description: "Exact group display name; import identity.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		"display_name":  schema.StringAttribute{Required: true, Description: "Case-sensitive group display name. Rename requires replacement.", Validators: []validator.String{groupNameValidator{}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"internal_name": schema.StringAttribute{Computed: true, Description: "Internal group name returned by inventory; distinct from import identity."},
		"members":       schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "Authoritative non-empty set of exact device DISPLAY names, not internal names. Do not share membership ownership with other tools.", Validators: []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.ValueStringsAre(groupNameValidator{member: true})}},
	}}
}
func (r *deviceGroupResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func groupInput(ctx context.Context, m deviceGroupModel) ([]string, diag.Diagnostics) {
	var d diag.Diagnostics
	if m.DisplayName.IsUnknown() || m.DisplayName.IsNull() || m.Members.IsNull() || m.Members.IsUnknown() {
		d.AddError("Unknown or null group input", "Group display_name and members must be known and non-null before applying.")
		return nil, d
	}
	if err := client.ValidateGroupName(m.DisplayName.ValueString()); err != nil {
		d.AddError("Invalid display name", err.Error())
	}
	names := []string{}
	d.Append(m.Members.ElementsAs(ctx, &names, false)...)
	if !d.HasError() {
		if err := client.ValidateGroupMembers(names); err != nil {
			d.AddError("Invalid members", err.Error())
		}
	}
	return names, d
}
func groupPrior(ctx context.Context, m deviceGroupModel) (client.DeviceGroup, diag.Diagnostics) {
	names, d := groupInput(ctx, m)
	if m.InternalName.IsUnknown() || m.InternalName.IsNull() || m.InternalName.ValueString() == "" {
		d.AddError("Unknown group identity", "Refresh the group before changing it.")
	}
	g := client.DeviceGroup{Name: m.InternalName.ValueString(), DisplayName: m.DisplayName.ValueString()}
	for _, n := range names {
		g.Firewalls = append(g.Firewalls, client.GroupFirewall{DisplayName: n})
	}
	return g, d
}
func setGroupState(ctx context.Context, state *tfsdk.State, g *client.DeviceGroup) diag.Diagnostics {
	members, d := types.SetValueFrom(ctx, types.StringType, g.Members())
	if d.HasError() {
		return d
	}
	m := deviceGroupModel{ID: types.StringValue(g.DisplayName), DisplayName: types.StringValue(g.DisplayName), InternalName: types.StringValue(g.Name), Members: members}
	d.Append(state.Set(ctx, &m)...)
	return d
}
func (r *deviceGroupResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m deviceGroupModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	names, d := groupInput(ctx, m)
	s.Diagnostics.Append(d...)
	if s.Diagnostics.HasError() {
		return
	}
	g, err := r.c.CreateDeviceGroup(ctx, m.DisplayName.ValueString(), names, func() {
		m.ID = m.DisplayName
		m.InternalName = types.StringNull()
		s.Diagnostics.Append(s.State.Set(ctx, &m)...)
	})
	if g != nil {
		s.Diagnostics.Append(setGroupState(ctx, &s.State, g)...)
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot create experimental device group", err.Error())
	}
}
func (r *deviceGroupResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	var m deviceGroupModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if m.DisplayName.IsNull() || m.DisplayName.IsUnknown() {
		s.Diagnostics.AddError("Missing group identity", "display_name must be known.")
		return
	}
	g, err := r.c.DeviceGroup(ctx, m.DisplayName.ValueString())
	if errors.Is(err, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot read experimental device group", err.Error())
		return
	}
	s.Diagnostics.Append(setGroupState(ctx, &s.State, g)...)
}
func (r *deviceGroupResource) Update(ctx context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	var prior, plan deviceGroupModel
	s.Diagnostics.Append(q.State.Get(ctx, &prior)...)
	s.Diagnostics.Append(q.Plan.Get(ctx, &plan)...)
	if s.Diagnostics.HasError() {
		return
	}
	names, d := groupInput(ctx, plan)
	s.Diagnostics.Append(d...)
	g, d := groupPrior(ctx, prior)
	s.Diagnostics.Append(d...)
	if s.Diagnostics.HasError() {
		return
	}
	if prior.DisplayName.ValueString() != plan.DisplayName.ValueString() {
		s.Diagnostics.AddError("Rename requires replacement", "Group display_name cannot be changed in place.")
		return
	}
	observed, err := r.c.UpdateDeviceGroup(ctx, g, names)
	if observed != nil {
		s.Diagnostics.Append(setGroupState(ctx, &s.State, observed)...)
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot update experimental device group", err.Error())
	}
}
func (r *deviceGroupResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	var m deviceGroupModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	g, d := groupPrior(ctx, m)
	s.Diagnostics.Append(d...)
	if s.Diagnostics.HasError() {
		return
	}
	observed, err := r.c.DeleteDeviceGroup(ctx, g)
	if err != nil {
		if observed != nil {
			s.Diagnostics.Append(setGroupState(ctx, &s.State, observed)...)
		}
		s.Diagnostics.AddError("Cannot delete experimental device group", err.Error())
		return
	}
	s.State.RemoveResource(ctx)
}
func (r *deviceGroupResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	if err := r.c.DeviceGroupsEnabled(); err != nil {
		s.Diagnostics.AddError("Experimental device groups disabled", err.Error())
		return
	}
	if err := client.ValidateGroupName(q.ID); err != nil {
		s.Diagnostics.AddError("Invalid import identity", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("id"), q.ID)...)
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("display_name"), q.ID)...)
}

func (r *deviceGroupResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var m deviceGroupModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() || m.Members.IsNull() || m.Members.IsUnknown() {
		return
	}
	for _, v := range m.Members.Elements() {
		if v.IsUnknown() {
			continue
		}
		if v.IsNull() || strings.TrimSpace(v.(types.String).ValueString()) == "" {
			s.Diagnostics.AddError("Invalid members", "Device display names must be nonblank and non-null.")
		}
	}
}
