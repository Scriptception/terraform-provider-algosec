// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"errors"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"reflect"
	"sort"
)

type urlCategoryResource struct{ c *client.Client }
type categoryModel struct {
	ID   types.String `tfsdk:"id"`
	Name types.String `tfsdk:"name"`
	URLs types.Map    `tfsdk:"urls"`
}

func NewURLCategoryResource() resource.Resource { return &urlCategoryResource{} }
func (r *urlCategoryResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_url_category"
}
func (r *urlCategoryResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	s.Schema = schema.Schema{Description: "Manage one Panorama URL-category override, including its complete URL/IP map. Requires the override file prepared by an administrator (see API coverage). Name changes rename in place; URL/IP changes replace the category. Do not share ownership with another resource or administrator. Destroy deletes the category.", Attributes: map[string]schema.Attribute{
		"id":   schema.StringAttribute{Computed: true, Description: "Category name, also the import identifier."},
		"name": schema.StringAttribute{Required: true, Description: "Category name. Renamed in place when changed.", Validators: []validator.String{identifierValidator{}}},
		"urls": schema.MapAttribute{Required: true, ElementType: types.SetType{ElemType: types.StringType}, Description: "Complete map from URL strings to sets of individual IPv4/IPv6 addresses. Changes require replacement because granular removal/merge semantics are inconsistent in the public docs.", PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()}},
	}}
}
func (r *urlCategoryResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func categoryFrom(ctx context.Context, m categoryModel, d *diag.Diagnostics) (client.Category, bool) {
	var sets map[string]types.Set
	d.Append(m.URLs.ElementsAs(ctx, &sets, false)...)
	out := client.Category{URLs: map[string][]string{}}
	for name, set := range sets {
		if set.IsNull() || set.IsUnknown() {
			d.AddError("Invalid URL IP set", "Every URL must have a known, non-null set of IP addresses.")
			continue
		}
		var ips []string
		d.Append(set.ElementsAs(ctx, &ips, false)...)
		if ips == nil {
			ips = []string{}
		}
		out.URLs[name] = ips
	}
	if err := client.ValidateURLs(out.URLs); err != nil {
		d.AddError("Invalid URL map", err.Error())
	}
	return out, !d.HasError()
}
func categoryTo(ctx context.Context, m *categoryModel, v client.Category, d *diag.Diagnostics) {
	sets := map[string]types.Set{}
	for k, ips := range v.URLs {
		val, diags := types.SetValueFrom(ctx, types.StringType, ips)
		d.Append(diags...)
		sets[k] = val
	}
	value, diags := types.MapValueFrom(ctx, types.SetType{ElemType: types.StringType}, sets)
	d.Append(diags...)
	m.URLs = value
	m.ID = m.Name
}
func sameURLs(a, b client.Category) bool {
	if len(a.URLs) != len(b.URLs) {
		return false
	}
	for k, x := range a.URLs {
		y, ok := b.URLs[k]
		if !ok {
			return false
		}
		x = append([]string{}, x...)
		y = append([]string{}, y...)
		sort.Strings(x)
		sort.Strings(y)
		if !reflect.DeepEqual(x, y) {
			return false
		}
	}
	return true
}
func (r *urlCategoryResource) ValidateConfig(ctx context.Context, q resource.ValidateConfigRequest, s *resource.ValidateConfigResponse) {
	var m categoryModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() || m.URLs.IsUnknown() || m.URLs.IsNull() {
		return
	}
	// Nested unknown values are valid during planning; validate known values only.
	for _, v := range m.URLs.Elements() {
		if v.IsUnknown() {
			return
		}
		set := v.(types.Set)
		for _, ip := range set.Elements() {
			if ip.IsUnknown() {
				return
			}
		}
	}
	categoryFrom(ctx, m, &s.Diagnostics)
}
func (r *urlCategoryResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m categoryModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	v, ok := categoryFrom(ctx, m, &s.Diagnostics)
	if !ok {
		return
	}
	_, err := r.c.Category(ctx, m.Name.ValueString())
	if err == nil {
		s.Diagnostics.AddError("Category already exists", "Import the existing category before managing it.")
		return
	}
	if !errors.Is(err, client.ErrNotFound) {
		s.Diagnostics.AddError("Cannot check category", err.Error())
		return
	}
	if err = r.c.CreateCategory(ctx, m.Name.ValueString(), v); err != nil {
		s.Diagnostics.AddError("Category create not confirmed", err.Error()+" Inspect the remote category and verify ownership before importing or retrying; no ownership was recorded.")
		return
	}
	// Persist recoverable identity before read-back, even if read-back subsequently fails.
	m.ID = m.Name
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
	live, err := r.c.Category(ctx, m.Name.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Category read-back failed", err.Error())
		return
	}
	categoryTo(ctx, &m, live, &s.Diagnostics)
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
	if !sameURLs(v, live) {
		s.Diagnostics.AddError("Category read-back mismatch", "Appliance URL/IP values differ from the requested values; state contains the observed object.")
	}
}
func (r *urlCategoryResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	var m categoryModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	live, err := r.c.Category(ctx, m.ID.ValueString())
	if errors.Is(err, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot read category", err.Error())
		return
	}
	m.Name = m.ID
	categoryTo(ctx, &m, live, &s.Diagnostics)
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
func (r *urlCategoryResource) Update(ctx context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	var old, m categoryModel
	s.Diagnostics.Append(q.State.Get(ctx, &old)...)
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	desired, ok := categoryFrom(ctx, m, &s.Diagnostics)
	if !ok {
		return
	}
	previous, ok := categoryFrom(ctx, old, &s.Diagnostics)
	if !ok {
		return
	}
	if !sameURLs(previous, desired) {
		s.Diagnostics.AddError("Replacement required", "URL/IP changes require category replacement.")
		return
	}
	current, err := r.c.Category(ctx, old.ID.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Cannot check category", err.Error())
		return
	}
	if !sameURLs(current, previous) {
		s.Diagnostics.AddError("Concurrent category change", "Refresh and plan again before renaming this category.")
		return
	}
	if old.ID.ValueString() != m.Name.ValueString() {
		_, err = r.c.Category(ctx, m.Name.ValueString())
		if err == nil {
			s.Diagnostics.AddError("Category already exists", "The rename target already exists.")
			return
		}
		if !errors.Is(err, client.ErrNotFound) {
			s.Diagnostics.AddError("Cannot check rename target", err.Error())
			return
		}
		if err = r.c.RenameCategory(ctx, old.ID.ValueString(), m.Name.ValueString(), previous); err != nil {
			s.Diagnostics.AddError("Cannot rename category", err.Error())
			return
		}
	}
	m.ID = m.Name
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
	live, err := r.c.Category(ctx, m.Name.ValueString())
	if err != nil {
		s.Diagnostics.AddError("Category read-back failed", err.Error())
		return
	}
	categoryTo(ctx, &m, live, &s.Diagnostics)
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
	if !sameURLs(desired, live) {
		s.Diagnostics.AddError("Category read-back mismatch", "Appliance URL/IP values differ from the requested values.")
	}
	if old.ID.ValueString() != m.ID.ValueString() {
		if _, err = r.c.Category(ctx, old.ID.ValueString()); !errors.Is(err, client.ErrNotFound) {
			s.Diagnostics.AddError("Rename not confirmed", "The old category is still present or its absence could not be verified.")
		}
	}
}
func (r *urlCategoryResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	var m categoryModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	_, err := r.c.Category(ctx, m.ID.ValueString())
	if errors.Is(err, client.ErrNotFound) {
		return
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot check category", err.Error())
		return
	}
	if err = r.c.DeleteCategory(ctx, m.ID.ValueString()); err != nil {
		s.Diagnostics.AddError("Cannot delete category", err.Error())
		return
	}
	if _, err = r.c.Category(ctx, m.ID.ValueString()); !errors.Is(err, client.ErrNotFound) {
		s.Diagnostics.AddError("Deletion not confirmed", "Category remains present or its absence could not be verified; state is retained.")
	}
}
func (r *urlCategoryResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	if _, err := client.Segment(q.ID); err != nil {
		s.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("id"), q.ID)...)
	s.Diagnostics.Append(s.State.SetAttribute(ctx, path.Root("name"), q.ID)...)
}

var _ resource.ResourceWithValidateConfig = (*urlCategoryResource)(nil)
