// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"sort"
)

type catalogDataSource struct {
	c     *client.Client
	files bool
}
type catalogModel struct {
	ID    types.String `tfsdk:"id"`
	Names types.Set    `tfsdk:"names"`
}

func NewRiskProfilesDataSource() datasource.DataSource     { return &catalogDataSource{} }
func NewRiskProfileFilesDataSource() datasource.DataSource { return &catalogDataSource{files: true} }
func (r *catalogDataSource) suffix() string {
	if r.files {
		return "risk_profile_files"
	}
	return "risk_profiles"
}
func (r *catalogDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_" + r.suffix()
}
func (r *catalogDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	desc := "Names of customer-defined risk profiles."
	if r.files {
		desc = "Risk-profile spreadsheet filenames available to the session user; use with algosec_security_zones."
	}
	s.Schema = schema.Schema{Description: desc, Attributes: map[string]schema.Attribute{"id": schema.StringAttribute{Computed: true, Description: "Catalog identity."}, "names": schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "Names returned by the API."}}}
}
func (r *catalogDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *catalogDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	var m catalogModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	var names []string
	var err error
	if r.files {
		names, err = r.c.RiskProfileFiles(ctx)
	} else {
		names, err = r.c.RiskProfiles(ctx)
	}
	if err != nil {
		s.Diagnostics.AddError("Cannot read risk profile catalog", err.Error())
		return
	}
	m.ID = types.StringValue(r.suffix())
	v, d := types.SetValueFrom(ctx, types.StringType, names)
	s.Diagnostics.Append(d...)
	m.Names = v
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}

type urlCategoriesDataSource struct {
	c      *client.Client
	single bool
}
type categoriesModel struct {
	ID         types.String    `tfsdk:"id"`
	Categories []categoryModel `tfsdk:"categories"`
}

func NewURLCategoriesDataSource() datasource.DataSource { return &urlCategoriesDataSource{} }
func NewURLCategoryDataSource() datasource.DataSource   { return &urlCategoriesDataSource{single: true} }
func (r *urlCategoriesDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, s *datasource.MetadataResponse) {
	s.TypeName = "algosec_url_categories"
	if r.single {
		s.TypeName = "algosec_url_category"
	}
}
func (r *urlCategoriesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, s *datasource.SchemaResponse) {
	attrs := map[string]schema.Attribute{"id": schema.StringAttribute{Computed: true, Description: "Category name."}, "name": schema.StringAttribute{Computed: true, Description: "Category name."}, "urls": schema.MapAttribute{Computed: true, ElementType: types.SetType{ElemType: types.StringType}, Description: "URL strings mapped to sets of individual IP addresses."}}
	if r.single {
		attrs["name"] = schema.StringAttribute{Required: true, Description: "Exact category name.", Validators: []validator.String{identifierValidator{}}}
		s.Schema = schema.Schema{Description: "Look up one Panorama URL-category override by exact name.", Attributes: attrs}
		return
	}
	s.Schema = schema.Schema{Description: "Read Panorama URL-category overrides. Requires the administrator-prepared URL categories override file.", Attributes: map[string]schema.Attribute{"id": schema.StringAttribute{Computed: true, Description: "Inventory identity."}, "categories": schema.ListNestedAttribute{Computed: true, Description: "Categories ordered by name.", NestedObject: schema.NestedAttributeObject{Attributes: attrs}}}}
}
func (r *urlCategoriesDataSource) Configure(_ context.Context, q datasource.ConfigureRequest, s *datasource.ConfigureResponse) {
	if q.ProviderData == nil {
		return
	}
	var ok bool
	r.c, ok = q.ProviderData.(*client.Client)
	if !ok {
		s.Diagnostics.AddError("Unexpected client", "Expected an AlgoSec client.")
	}
}
func (r *urlCategoriesDataSource) Read(ctx context.Context, q datasource.ReadRequest, s *datasource.ReadResponse) {
	if r.single {
		var m categoryModel
		s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
		if s.Diagnostics.HasError() {
			return
		}
		v, err := r.c.Category(ctx, m.Name.ValueString())
		if err != nil {
			s.Diagnostics.AddError("Cannot read URL category", err.Error())
			return
		}
		categoryTo(ctx, &m, v, &s.Diagnostics)
		s.Diagnostics.Append(s.State.Set(ctx, &m)...)
		return
	}
	var m categoriesModel
	s.Diagnostics.Append(q.Config.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	all, err := r.c.Categories(ctx)
	if err != nil {
		s.Diagnostics.AddError("Cannot read URL categories", err.Error())
		return
	}
	names := []string{}
	for k := range all {
		names = append(names, k)
	}
	sort.Strings(names)
	m.Categories = []categoryModel{}
	for _, name := range names {
		v := categoryModel{Name: types.StringValue(name)}
		categoryTo(ctx, &v, all[name], &s.Diagnostics)
		m.Categories = append(m.Categories, v)
	}
	m.ID = types.StringValue("panorama")
	s.Diagnostics.Append(s.State.Set(ctx, &m)...)
}
