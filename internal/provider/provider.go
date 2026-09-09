// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"os"
	"time"
)

type AlgoSecProvider struct{ version string }
type providerModel struct {
	ACEURL                       types.String `tfsdk:"ace_url"`
	ACEToken                     types.String `tfsdk:"ace_access_token"`
	ExperimentalACE              types.Bool   `tfsdk:"experimental_ace_public_contracts"`
	FireFlowURL                  types.String `tfsdk:"fireflow_url"`
	FireFlowSession              types.String `tfsdk:"fireflow_session"`
	ExperimentalFireFlowBindings types.Bool   `tfsdk:"experimental_fireflow_bindings"`
	ExperimentalURLIPs           types.Bool   `tfsdk:"experimental_url_ip_memberships"`
	AppVizWholeRoleOwnership     types.Bool   `tfsdk:"appviz_whole_role_ownership"`
	ExperimentalTags             types.Bool   `tfsdk:"experimental_tags"`
	AppVizURL                    types.String `tfsdk:"appviz_saas_url"`
	AppVizToken                  types.String `tfsdk:"appviz_saas_token"`
	ExperimentalAppVizRoles      types.Bool   `tfsdk:"experimental_appviz_roles"`
	ExperimentalTrustedRules     types.Bool   `tfsdk:"experimental_trusted_rules"`
	ExperimentalDeviceGroups     types.Bool   `tfsdk:"experimental_device_groups"`
	URL                          types.String `tfsdk:"url"`
	Username                     types.String `tfsdk:"username"`
	Password                     types.String `tfsdk:"password"`
	SessionID                    types.String `tfsdk:"session_id"`
	Insecure                     types.Bool   `tfsdk:"insecure"`
	ReadOnly                     types.Bool   `tfsdk:"read_only"`
	Timeout                      types.Int64  `tfsdk:"timeout_seconds"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &AlgoSecProvider{version} }
}
func (p *AlgoSecProvider) Metadata(_ context.Context, _ provider.MetadataRequest, r *provider.MetadataResponse) {
	r.TypeName = "algosec"
	r.Version = p.version
}
func (p *AlgoSecProvider) Schema(_ context.Context, _ provider.SchemaRequest, r *provider.SchemaResponse) {
	r.Schema = schema.Schema{Description: "Unofficial AlgoSec provider with A32.60 AFA base APIs, separately gated experimental A33.20 groups/trusted rules/URL-IP assignments, A33.30 EA tags and FireFlow direct bindings, AppViz SaaS EA roles, and experimental ACE SaaS configuration. Uses protocol 6 and HTTPS. Prefer environment credentials; read_only defaults to true.", Attributes: map[string]schema.Attribute{
		"ace_url":                           schema.StringAttribute{Optional: true, Description: "Separate regional ACE HTTPS origin. Environment ALGOSEC_ACE_URL. CAA routes use the documented /prevasio service base. TLS verification is mandatory.", Validators: []validator.String{originValidator{}}},
		"ace_access_token":                  schema.StringAttribute{Optional: true, Sensitive: true, Description: "Externally supplied ACE bearer token. Prefer ALGOSEC_ACE_ACCESS_TOKEN; never stored in resource state."},
		"experimental_ace_public_contracts": schema.BoolAttribute{Optional: true, Description: "Enable the experimental rolling ACE SaaS public contracts. Defaults false and remains separate from AFA, FireFlow and AppViz clients; no live acceptance."},
		"appviz_saas_url":                   schema.StringAttribute{Optional: true, Description: "Separate AppViz SaaS HTTPS origin. Environment: ALGOSEC_APPVIZ_SAAS_URL. Not the legacy on-premises AppViz API. TLS verification is always required.", Validators: []validator.String{originValidator{}}},
		"appviz_saas_token":                 schema.StringAttribute{Optional: true, Sensitive: true, Description: "AppViz SaaS Bearer token. Prefer ALGOSEC_APPVIZ_SAAS_TOKEN to avoid configuration/plan persistence. Never refreshed, logged, or stored in resource state."},
		"fireflow_url":                      schema.StringAttribute{Optional: true, Description: "Separate FireFlow HTTPS origin. Environment ALGOSEC_FIREFLOW_URL. TLS verification is mandatory, independent of AFA insecure.", Validators: []validator.String{originValidator{}}},
		"fireflow_session":                  schema.StringAttribute{Optional: true, Sensitive: true, Description: "Externally supplied FireFlow_Session cookie value. Prefer ALGOSEC_FIREFLOW_SESSION. No login, refresh or logout; never stored in resource state."},
		"experimental_fireflow_bindings":    schema.BoolAttribute{Optional: true, Description: "Enable A33.30 direct FireFlow member/permission bindings. Defaults false; separate from AFA/AppViz clients. Complete privileged visibility and exclusive ownership required; synthetic contracts only."},
		"appviz_whole_role_ownership":       schema.BoolAttribute{Optional: true, Description: "Explicitly acknowledge destructive whole-role ownership, including imported roles: delete/replacement removes unreadable description and LDAP linkage. Defaults false. Required by algosec_appviz_role in addition to its experimental gate; use dedicated exclusively owned roles."},
		"experimental_url_ip_memberships":   schema.BoolAttribute{Optional: true, Description: "Enable A33.20 experimental singleton URL/IP memberships. Defaults false; separate from whole-category ownership and other experimental flags. Never overlap whole-category or concurrent tuple ownership. No live acceptance."},
		"experimental_tags":                 schema.BoolAttribute{Optional: true, Description: "Enable experimental A33.30 vendor Early Availability ALGOSEC tags. Defaults false. Complete administrator visibility, exclusive writers and short-page pagination contract required; no live acceptance."},
		"experimental_appviz_roles":         schema.BoolAttribute{Optional: true, Description: "Enable AppViz SaaS Early Availability roles. Defaults false; vendor EA, synthetic-contract tested only. Separate from AFA and legacy AppViz authentication."},
		"experimental_trusted_rules":        schema.BoolAttribute{Optional: true, Description: "Enable experimental A33.20 trusted-rule assignments. Defaults false. Public-contract tested only; complete administrator device/rule visibility required. This provider gate is separate from vendor Early Availability device groups."},
		"experimental_device_groups":        schema.BoolAttribute{Optional: true, Description: "EXPERIMENTAL ASMS A33.20 Early Availability device groups. Defaults to false. AlgoSec does not recommend these APIs for production. Requires complete administrator inventory visibility."},
		"url":                               schema.StringAttribute{Optional: true, Description: "HTTPS appliance origin, without a path. Environment: ALGOSEC_URL.", Validators: []validator.String{originValidator{}}},
		"username":                          schema.StringAttribute{Optional: true, Description: "ASMS login username. Environment: ALGOSEC_USERNAME. Mutually exclusive with session_id."},
		"password":                          schema.StringAttribute{Optional: true, Sensitive: true, Description: "ASMS login password. Prefer ALGOSEC_PASSWORD to avoid configuration/plan persistence."},
		"session_id":                        schema.StringAttribute{Optional: true, Sensitive: true, Description: "Existing PHPSESSID session. Prefer ALGOSEC_SESSION_ID. Mutually exclusive with username/password. Sessions are not refreshed or logged out by this provider."},
		"insecure":                          schema.BoolAttribute{Optional: true, Description: "Disable TLS verification explicitly. Defaults to false. Install the appliance CA in the system trust store instead when possible."},
		"read_only":                         schema.BoolAttribute{Optional: true, Description: "Refuse all administration writes. Defaults to true; set false to manage resources. Authentication may establish an API session."},
		"timeout_seconds":                   schema.Int64Attribute{Optional: true, Description: "Per-request timeout, 1–300 seconds. Defaults to 30. No requests are automatically retried.", Validators: []validator.Int64{int64validator.Between(1, 300)}},
	}}
}
func (p *AlgoSecProvider) Configure(ctx context.Context, req provider.ConfigureRequest, r *provider.ConfigureResponse) {
	var m providerModel
	r.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if r.Diagnostics.HasError() {
		return
	}
	for n, v := range map[string]types.String{"ace_url": m.ACEURL, "ace_access_token": m.ACEToken, "fireflow_url": m.FireFlowURL, "fireflow_session": m.FireFlowSession, "appviz_saas_url": m.AppVizURL, "appviz_saas_token": m.AppVizToken, "url": m.URL, "username": m.Username, "password": m.Password, "session_id": m.SessionID} {
		if v.IsUnknown() {
			r.Diagnostics.AddAttributeError(path.Root(n), "Unknown provider configuration", "Provider settings must be known before configuring the client.")
		}
	}
	if m.ExperimentalACE.IsUnknown() || m.ExperimentalFireFlowBindings.IsUnknown() || m.ExperimentalURLIPs.IsUnknown() || m.AppVizWholeRoleOwnership.IsUnknown() || m.ExperimentalTags.IsUnknown() || m.ExperimentalAppVizRoles.IsUnknown() || m.ExperimentalTrustedRules.IsUnknown() || m.ExperimentalDeviceGroups.IsUnknown() || m.Insecure.IsUnknown() || m.ReadOnly.IsUnknown() || m.Timeout.IsUnknown() {
		r.Diagnostics.AddError("Unknown provider configuration", "Safety and timeout settings must be known before configuring the client.")
	}
	if r.Diagnostics.HasError() {
		return
	}
	str := func(v types.String, env string) string {
		if v.IsNull() {
			return os.Getenv(env)
		}
		return v.ValueString()
	}
	timeout := int64(30)
	if !m.Timeout.IsNull() {
		timeout = m.Timeout.ValueInt64()
	}
	if timeout < 1 || timeout > 300 {
		r.Diagnostics.AddError("Invalid timeout", "timeout_seconds must be between 1 and 300.")
		return
	}
	readOnly := true
	if !m.ReadOnly.IsNull() {
		readOnly = m.ReadOnly.ValueBool()
	}
	// Ambient credentials for a disabled optional service must not break AFA.
	appvizURL, appvizToken := "", ""
	if m.ExperimentalAppVizRoles.ValueBool() || !m.AppVizURL.IsNull() || !m.AppVizToken.IsNull() {
		appvizURL, appvizToken = str(m.AppVizURL, "ALGOSEC_APPVIZ_SAAS_URL"), str(m.AppVizToken, "ALGOSEC_APPVIZ_SAAS_TOKEN")
	}
	fireflowURL, fireflowSession := "", ""
	if m.ExperimentalFireFlowBindings.ValueBool() || !m.FireFlowURL.IsNull() || !m.FireFlowSession.IsNull() {
		fireflowURL, fireflowSession = str(m.FireFlowURL, "ALGOSEC_FIREFLOW_URL"), str(m.FireFlowSession, "ALGOSEC_FIREFLOW_SESSION")
	}
	aceURL, aceToken := "", ""
	if m.ExperimentalACE.ValueBool() || !m.ACEURL.IsNull() || !m.ACEToken.IsNull() {
		aceURL, aceToken = str(m.ACEURL, "ALGOSEC_ACE_URL"), str(m.ACEToken, "ALGOSEC_ACE_ACCESS_TOKEN")
	}
	c, err := client.New(client.Options{ACEURL: aceURL, ACEToken: aceToken, ExperimentalACE: m.ExperimentalACE.ValueBool(), FireFlowURL: fireflowURL, FireFlowSession: fireflowSession, ExperimentalFireFlowBindings: m.ExperimentalFireFlowBindings.ValueBool(), ExperimentalURLIPs: m.ExperimentalURLIPs.ValueBool(), ExperimentalTags: m.ExperimentalTags.ValueBool(), AppVizURL: appvizURL, AppVizToken: appvizToken, ExperimentalAppVizRoles: m.ExperimentalAppVizRoles.ValueBool(), URL: str(m.URL, "ALGOSEC_URL"), Username: str(m.Username, "ALGOSEC_USERNAME"), Password: str(m.Password, "ALGOSEC_PASSWORD"), SessionID: str(m.SessionID, "ALGOSEC_SESSION_ID"), Timeout: time.Duration(timeout) * time.Second, Insecure: m.Insecure.ValueBool(), ReadOnly: readOnly, ExperimentalTrustedRules: m.ExperimentalTrustedRules.ValueBool(), ExperimentalDeviceGroups: m.ExperimentalDeviceGroups.ValueBool()})
	if err != nil {
		r.Diagnostics.AddError("Invalid AlgoSec configuration", err.Error())
		return
	}
	c.AppVizWholeRoleOwnership = m.AppVizWholeRoleOwnership.ValueBool()
	r.ResourceData = c
	r.DataSourceData = c
}
func (p *AlgoSecProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewURLCategoryResource, NewDeviceGroupResource, NewTrustedRuleResource, NewAppVizRoleResource, NewTagResource, NewURLIPResource, NewFireFlowMemberResource, NewFireFlowPermissionResource, NewACEEmailsResource, NewACEJiraResource, NewACEThreatResource, NewACEAccountResource}
}
func (p *AlgoSecProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewURLCategoriesDataSource, NewURLCategoryDataSource, NewDevicesDataSource, NewDeviceDataSource, NewRiskProfilesDataSource, NewRiskProfileFilesDataSource, NewSecurityZonesDataSource, NewDeviceZonesDataSource, NewNetworkObjectsDataSource, NewTrustedTrafficDataSource, NewDeviceGroupDataSource, NewDeviceGroupsDataSource,
	}
}
