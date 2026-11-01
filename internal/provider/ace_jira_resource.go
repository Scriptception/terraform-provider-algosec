// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"errors"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"strings"
)

type aceJiraResource struct{ c *client.ACEClient }
type aceJiraModel struct {
	ID         types.String `tfsdk:"id"`
	ServerURL  types.String `tfsdk:"server_url"`
	UserName   types.String `tfsdk:"user_name"`
	ProjectKey types.String `tfsdk:"project_key"`
	IssueType  types.String `tfsdk:"default_issue_type"`
	Priority   types.String `tfsdk:"default_priority"`
	Token      types.String `tfsdk:"api_token_wo"`
	Version    types.String `tfsdk:"replacement_version"`
}

func NewACEJiraResource() resource.Resource { return &aceJiraResource{} }
func (r *aceJiraResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_ace_jira_integration"
}
func (r *aceJiraResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	a := map[string]schema.Attribute{
		"id":                  schema.StringAttribute{Computed: true, Description: "Tenant singleton ID; import using jira."},
		"api_token_wo":        schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Raw Atlassian API token, converted internally to base64(user_name:token). Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Required for creation/replacement, never stored in plan/state or reconstructed from masked GET. May be omitted for import, no-op, refresh and destroy."},
		"replacement_version": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Nonsecret replacement trigger. Change this when resubmitting a new write-only token. Token drift cannot be read.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
	}
	for k, d := range map[string]string{"server_url": "Jira HTTPS origin, without embedded credentials.", "user_name": "Atlassian account email address used in token conversion.", "project_key": "Dedicated Jira project key.", "default_issue_type": "Explicit nonempty Jira issue type; no ambiguous API default is synthesized.", "default_priority": "Explicit nonempty Jira priority; no ambiguous API default is synthesized."} {
		a[k] = schema.StringAttribute{Required: true, Description: d + " Changes replace.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
	}
	s.Schema = schema.Schema{Description: "Owns the tenant ACE Jira integration. Experimental rolling SaaS contract; complete visibility and exclusive ownership required. Every configuration change replaces using delete then create; cannot use create_before_destroy. Deletion/replacement loses alert-ticket associations, not Jira tickets. A fresh write-only token is required before replacement. Import existing integrations with jira. No live acceptance.", Attributes: a}
}
func (r *aceJiraResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
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
func (m aceJiraModel) value() client.ACEJira {
	return client.ACEJira{ServerURL: m.ServerURL.ValueString(), UserName: m.UserName.ValueString(), ProjectKey: m.ProjectKey.ValueString(), IssueType: m.IssueType.ValueString(), Priority: m.Priority.ValueString()}
}
func (m *aceJiraModel) set(v client.ACEJira) {
	m.ID = types.StringValue("jira")
	m.ServerURL = types.StringValue(v.ServerURL)
	m.UserName = types.StringValue(v.UserName)
	m.ProjectKey = types.StringValue(v.ProjectKey)
	m.IssueType = types.StringValue(v.IssueType)
	m.Priority = types.StringValue(v.Priority)
	m.Token = types.StringNull()
}
func (m aceJiraModel) inputs() []types.String {
	return []types.String{m.ServerURL, m.UserName, m.ProjectKey, m.IssueType, m.Priority, m.Version}
}
func (r *aceJiraResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var next, old aceJiraModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &next)...)
	if !q.State.Raw.IsNull() {
		s.Diagnostics.Append(q.State.Get(ctx, &old)...)
	}
	if s.Diagnostics.HasError() {
		return
	}
	change := q.State.Raw.IsNull()
	for i, v := range next.inputs() {
		if !v.Equal(old.inputs()[i]) {
			change = true
		}
	}
	if !change {
		return
	}
	// Validate each known field independently; an unknown sibling cannot hide an
	// invalid value before Terraform schedules the old singleton's destruction.
	for i, v := range next.inputs() {
		if v.IsUnknown() {
			continue
		}
		if i == 5 {
			continue
		}
		var e error
		switch i {
		case 0:
			e = client.ValidateURL(v.ValueString())
		case 1:
			e = client.ValidateACEEmail(v.ValueString())
			if strings.Contains(v.ValueString(), ":") {
				e = errors.New("email must not contain a colon")
			}
		default:
			e = client.ValidateAppVizName(v.ValueString())
		}
		if v.IsNull() || e != nil {
			s.Diagnostics.AddError("Invalid Jira replacement configuration", "Known Jira fields must be valid and nonempty before replacement.")
		}
	}
	var config aceJiraModel
	s.Diagnostics.Append(q.Config.Get(ctx, &config)...)
	if e := aceJiraPayloadSize(next, config.Token); e != nil {
		s.Diagnostics.AddError("Invalid Jira replacement payload", e.Error())
	}
	if config.Token.IsUnknown() {
		s.Diagnostics.AddError("Unavailable write-only token", "Resolve the write-only token before planning creation or replacement.")
	} else if e := client.ValidateACESecret(config.Token.ValueString()); e != nil {
		s.Diagnostics.AddError("Missing write-only token", e.Error())
	}
}
func (r *aceJiraResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m, cfg aceJiraModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	s.Diagnostics.Append(q.Config.Get(ctx, &cfg)...)
	if s.Diagnostics.HasError() {
		return
	}
	v := m.value()
	if e := r.c.CreateJira(ctx, v, cfg.Token.ValueString()); e != nil {
		s.Diagnostics.AddError("ACE Jira creation failed", e.Error())
		return
	}
	m.set(v)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
	got, e := r.c.Jira(ctx)
	if e != nil {
		s.Diagnostics.AddError("ACE Jira readback failed", e.Error()+"; acknowledged singleton retained.")
		return
	}
	m.set(*got)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
	if *got != v {
		s.Diagnostics.AddError("ACE Jira readback differs", "Acknowledged singleton retained; refresh before retrying.")
	}
}
func (r *aceJiraResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	s.State = q.State
	var m aceJiraModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	v, e := r.c.Jira(ctx)
	if errors.Is(e, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if e != nil {
		s.Diagnostics.AddError("ACE Jira read failed", e.Error())
		return
	}
	m.set(*v)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
func (r *aceJiraResource) Update(_ context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	s.State = q.State
	s.Diagnostics.AddError("ACE Jira requires replacement", "No public update operation exists.")
}
func (r *aceJiraResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	s.State = q.State
	var m aceJiraModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := r.c.DeleteJira(ctx, m.value()); e != nil {
		s.Diagnostics.AddError("ACE Jira deletion failed", e.Error())
	}
}
func (r *aceJiraResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	if q.ID != "jira" {
		s.Diagnostics.AddError("Invalid Jira import", "Use jira as the tenant singleton ID.")
		return
	}
	v, e := r.c.Jira(ctx)
	if e != nil {
		s.Diagnostics.AddError("ACE Jira import failed", e.Error())
		return
	}
	m := aceJiraModel{Version: types.StringValue("")}
	m.set(*v)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
