// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"errors"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/boolvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type aceAccountResource struct{ c *client.ACEClient }
type aceAccountModel struct {
	ID                types.String `tfsdk:"id"`
	Provider          types.String `tfsdk:"cloud_provider"`
	AccountID         types.String `tfsdk:"account_id"`
	Name              types.String `tfsdk:"name"`
	AzureTenant       types.String `tfsdk:"azure_tenant"`
	Organization      types.String `tfsdk:"organization_id"`
	Version           types.String `tfsdk:"replacement_version"`
	Auto              types.Bool   `tfsdk:"auto_onboarded"`
	Unified           types.Bool   `tfsdk:"unified_onboarding"`
	SupportChanges    types.Bool   `tfsdk:"support_changes_wo"`
	FlowLogs          types.Bool   `tfsdk:"flow_logs_wo"`
	RoleARN           types.String `tfsdk:"role_arn_wo"`
	ExternalID        types.String `tfsdk:"external_id_wo"`
	ApplicationID     types.String `tfsdk:"application_id_wo"`
	ApplicationSecret types.String `tfsdk:"application_secret_wo"`
	CredentialType    types.String `tfsdk:"credential_type_wo"`
	PrivateKeyID      types.String `tfsdk:"private_key_id_wo"`
	PrivateKey        types.String `tfsdk:"private_key_wo"`
	ClientEmail       types.String `tfsdk:"client_email_wo"`
	ClientID          types.String `tfsdk:"client_id_wo"`
	AuthURI           types.String `tfsdk:"auth_uri_wo"`
	TokenURI          types.String `tfsdk:"token_uri_wo"`
	AuthCertURL       types.String `tfsdk:"auth_provider_x509_cert_url_wo"`
	ClientCertURL     types.String `tfsdk:"client_x509_cert_url_wo"`
}

func NewACEAccountResource() resource.Resource { return &aceAccountResource{} }
func (r *aceAccountResource) Metadata(_ context.Context, _ resource.MetadataRequest, s *resource.MetadataResponse) {
	s.TypeName = "algosec_ace_cloud_account_registration"
}
func (r *aceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, s *resource.SchemaResponse) {
	a := map[string]schema.Attribute{
		"id":                  schema.StringAttribute{Computed: true, Description: "Opaque accountKey returned by POST and matched exactly against GET. Import using the exact accountKey."},
		"cloud_provider":      schema.StringAttribute{Required: true, Description: "aws, azure or gcp. Changes replace.", Validators: []validator.String{stringvalidator.OneOf("aws", "azure", "gcp")}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"account_id":          schema.StringAttribute{Required: true, Description: "Expected cloud account ID, Azure subscription ID or GCP project ID. Verified from the accountKey-matched GET row, never parsed from accountKey. Changes replace.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"name":                schema.StringAttribute{Required: true, Description: "Drift-managed registration display name. Updated using name-only PATCH.", Validators: []validator.String{appVizNameValidator{}}},
		"azure_tenant":        schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Required Azure tenant UUID, read from azureTenant. Omit for other providers. Changes replace.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"organization_id":     schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Required GCP organization/folder identity, read from organizationId. Omit for other providers. Changes replace.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"auto_onboarded":      schema.BoolAttribute{Computed: true, Description: "Readable manual provenance. Only false can be owned or imported; automatic registrations are refused."},
		"unified_onboarding":  schema.BoolAttribute{Required: true, Description: "Explicit assertion that the ACE tenant uses unified onboarding. Must be true. The API cannot detect historical-tenant eligibility before submission.", Validators: []validator.Bool{boolvalidator.Equals(true)}},
		"replacement_version": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(""), Description: "Nonsecret explicit trigger for delete/recreate with newly supplied bootstrap inputs. Bootstrap changes alone are submission-only and cannot be drift-detected.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"support_changes_wo":  schema.BoolAttribute{Optional: true, WriteOnly: true, Description: "Nonsecret submission-only permission option, required explicitly for AWS/Azure creation/replacement. Not managed access drift. Omit for GCP."},
		"flow_logs_wo":        schema.BoolAttribute{Optional: true, WriteOnly: true, Description: "Nonsecret submission-only flow-log option, required explicitly for AWS creation/replacement. Not managed access drift. Omit for Azure/GCP."},
	}
	a["role_arn_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "AWS role ARN matching account_id. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["external_id_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "AWS external ID. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["application_id_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Azure service-principal application UUID; required despite optional schema wording to avoid omitted-credential ambiguity. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["application_secret_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Azure service-principal secret. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["credential_type_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP credential type; explicitly service_account. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["private_key_id_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP private key ID. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["private_key_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP PKCS8 PEM private key. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["client_email_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP service-account email. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["client_id_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP service-account client ID. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["auth_uri_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP OAuth authorization HTTPS URI. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["token_uri_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP OAuth token HTTPS URI. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["auth_provider_x509_cert_url_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP auth provider certificate HTTPS URL. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	a["client_x509_cert_url_wo"] = schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "GCP client certificate HTTPS URL. Write-only bootstrap input; required for the matching provider on creation/replacement. Write-only arguments require Terraform 1.11+; saved-plan ephemeral examples require Terraform 1.16.1+. Never drift-managed, persisted or reconstructed on import."}
	s.Schema = schema.Schema{Description: "Owns a manual ACE cloud registration and its readable name/provider/account identity, only for unified-onboarding tenants. Requires experimental_ace_public_contracts and exclusive ownership. Typed write-only bootstrap inputs are submission-only, not desired access configuration; use replacement_version to deliberately resubmit. Replacement deletes registration before creating it; cannot use create_before_destroy for the same account. Delete removes ACE registration, never external IAM roles, applications, service accounts or keys. Import/refresh/name-only update/destroy work without bootstrap credentials. Complete inventory visibility required. No live acceptance.", Attributes: a}
}
func (r *aceAccountResource) Configure(_ context.Context, q resource.ConfigureRequest, s *resource.ConfigureResponse) {
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
func (m aceAccountModel) value() client.ACEAccount {
	return client.ACEAccount{AccountKey: m.ID.ValueString(), Provider: m.Provider.ValueString(), AccountID: m.AccountID.ValueString(), Name: m.Name.ValueString(), AzureTenant: m.AzureTenant.ValueString(), OrganizationID: m.Organization.ValueString(), AutoOnboarded: m.Auto.ValueBool()}
}
func (m aceAccountModel) aws() client.ACEAWSBootstrap {
	return client.ACEAWSBootstrap{RoleARN: m.RoleARN.ValueString(), ExternalID: m.ExternalID.ValueString(), SupportChanges: m.SupportChanges.ValueBool(), FlowLogs: m.FlowLogs.ValueBool()}
}
func (m aceAccountModel) azure() client.ACEAzureBootstrap {
	return client.ACEAzureBootstrap{ApplicationID: m.ApplicationID.ValueString(), ApplicationSecret: m.ApplicationSecret.ValueString(), SupportChanges: m.SupportChanges.ValueBool()}
}
func (m aceAccountModel) gcp() client.ACEGCPBootstrap {
	return client.ACEGCPBootstrap{Type: m.CredentialType.ValueString(), PrivateKeyID: m.PrivateKeyID.ValueString(), PrivateKey: m.PrivateKey.ValueString(), ClientEmail: m.ClientEmail.ValueString(), ClientID: m.ClientID.ValueString(), AuthURI: m.AuthURI.ValueString(), TokenURI: m.TokenURI.ValueString(), AuthCertURL: m.AuthCertURL.ValueString(), ClientCertURL: m.ClientCertURL.ValueString()}
}
func (m *aceAccountModel) set(v client.ACEAccount) {
	m.ID = types.StringValue(v.AccountKey)
	m.Provider = types.StringValue(v.Provider)
	m.AccountID = types.StringValue(v.AccountID)
	m.Name = types.StringValue(v.Name)
	m.Auto = types.BoolValue(v.AutoOnboarded)
	m.AzureTenant = types.StringValue("")
	m.Organization = types.StringValue("")
	if v.Provider == "azure" {
		m.AzureTenant = types.StringValue(v.AzureTenant)
	}
	if v.Provider == "gcp" {
		m.Organization = types.StringValue(v.OrganizationID)
	}
	m.Unified = types.BoolValue(true)
	m.SupportChanges = types.BoolNull()
	m.FlowLogs = types.BoolNull()
	m.RoleARN = types.StringNull()
	m.ExternalID = types.StringNull()
	m.ApplicationID = types.StringNull()
	m.ApplicationSecret = types.StringNull()
	m.CredentialType = types.StringNull()
	m.PrivateKeyID = types.StringNull()
	m.PrivateKey = types.StringNull()
	m.ClientEmail = types.StringNull()
	m.ClientID = types.StringNull()
	m.AuthURI = types.StringNull()
	m.TokenURI = types.StringNull()
	m.AuthCertURL = types.StringNull()
	m.ClientCertURL = types.StringNull()
}
func (m aceAccountModel) replacementInputs() []types.String {
	return []types.String{m.Provider, m.AccountID, m.AzureTenant, m.Organization, m.Version}
}
func (m aceAccountModel) bootstrapFields() []types.String {
	switch m.Provider.ValueString() {
	case "aws":
		return []types.String{m.RoleARN, m.ExternalID}
	case "azure":
		return []types.String{m.ApplicationID, m.ApplicationSecret}
	case "gcp":
		return []types.String{m.CredentialType, m.PrivateKeyID, m.PrivateKey, m.ClientEmail, m.ClientID, m.AuthURI, m.TokenURI, m.AuthCertURL, m.ClientCertURL}
	}
	return nil
}
func (m aceAccountModel) validateBootstrap() error {
	if !m.Unified.ValueBool() {
		return errors.New("unified_onboarding must be true")
	}
	if m.Provider.ValueString() == "aws" || m.Provider.ValueString() == "azure" {
		if m.SupportChanges.IsNull() || m.SupportChanges.IsUnknown() {
			return errors.New("explicit support_changes_wo bootstrap option required")
		}
	}
	if m.Provider.ValueString() == "aws" && (m.FlowLogs.IsNull() || m.FlowLogs.IsUnknown()) {
		return errors.New("explicit flow_logs_wo bootstrap option required")
	}
	switch m.Provider.ValueString() {
	case "aws":
		return client.ValidateACEAWSBootstrap(m.value(), m.aws())
	case "azure":
		return client.ValidateACEAzureBootstrap(m.azure())
	case "gcp":
		return client.ValidateACEGCPBootstrap(m.gcp())
	}
	return errors.New("invalid bootstrap provider")
}
func (r *aceAccountResource) ModifyPlan(ctx context.Context, q resource.ModifyPlanRequest, s *resource.ModifyPlanResponse) {
	if q.Plan.Raw.IsNull() {
		return
	}
	var next, old, cfg aceAccountModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &next)...)
	s.Diagnostics.Append(q.Config.Get(ctx, &cfg)...)
	if !q.State.Raw.IsNull() {
		s.Diagnostics.Append(q.State.Get(ctx, &old)...)
	}
	if s.Diagnostics.HasError() {
		return
	}
	change := q.State.Raw.IsNull()
	for i, v := range next.replacementInputs() {
		if !v.Equal(old.replacementInputs()[i]) {
			change = true
		}
	}
	// Validate known identity fields separately using valid placeholders for unknown siblings.
	if !next.Provider.IsUnknown() {
		v := next.value()
		v.AutoOnboarded = false
		if next.Name.IsUnknown() {
			v.Name = "placeholder"
		}
		if next.AccountID.IsUnknown() {
			switch v.Provider {
			case "aws":
				v.AccountID = "123456789012"
			case "azure":
				v.AccountID = "11111111-2222-3333-4444-555555555555"
			case "gcp":
				v.AccountID = "placeholder-project"
			}
		}
		if next.AzureTenant.IsUnknown() {
			v.AzureTenant = "11111111-2222-3333-4444-555555555555"
		}
		if next.Organization.IsUnknown() {
			v.OrganizationID = "123456"
		}
		if e := client.ValidateACEAccount(v); e != nil {
			s.Diagnostics.AddError("Invalid account configuration", e.Error())
		}
		if !next.AzureTenant.IsUnknown() && v.Provider != "azure" && v.AzureTenant != "" {
			s.Diagnostics.AddError("Invalid account configuration", "azure_tenant is Azure-only.")
		}
		if !next.Organization.IsUnknown() && v.Provider != "gcp" && v.OrganizationID != "" {
			s.Diagnostics.AddError("Invalid account configuration", "organization_id is GCP-only.")
		}
	}

	supplied := map[string]types.String{"role_arn_wo": cfg.RoleARN, "external_id_wo": cfg.ExternalID, "application_id_wo": cfg.ApplicationID, "application_secret_wo": cfg.ApplicationSecret, "credential_type_wo": cfg.CredentialType, "private_key_id_wo": cfg.PrivateKeyID, "private_key_wo": cfg.PrivateKey, "client_email_wo": cfg.ClientEmail, "client_id_wo": cfg.ClientID, "auth_uri_wo": cfg.AuthURI, "token_uri_wo": cfg.TokenURI, "auth_provider_x509_cert_url_wo": cfg.AuthCertURL, "client_x509_cert_url_wo": cfg.ClientCertURL}
	for field, v := range supplied {
		if v.IsNull() {
			continue
		}
		requiredProvider := "gcp"
		if field == "role_arn_wo" || field == "external_id_wo" {
			requiredProvider = "aws"
		}
		if field == "application_id_wo" || field == "application_secret_wo" {
			requiredProvider = "azure"
		}
		if !cfg.Provider.IsUnknown() && cfg.Provider.ValueString() != requiredProvider {
			s.Diagnostics.AddError("Unexpected bootstrap input", "Only supply bootstrap fields for the selected cloud provider.")
		}
		if !v.IsUnknown() {
			id := ""
			if !cfg.AccountID.IsUnknown() {
				id = cfg.AccountID.ValueString()
			}
			if e := client.ValidateACEBootstrapField(field, v.ValueString(), id); e != nil {
				s.Diagnostics.AddError("Invalid bootstrap input", e.Error())
			}
		}
	}
	if !cfg.Provider.IsUnknown() {
		if cfg.Provider.ValueString() != "aws" && !cfg.FlowLogs.IsNull() {
			s.Diagnostics.AddError("Unexpected bootstrap input", "flow_logs_wo is AWS-only.")
		}
		if cfg.Provider.ValueString() == "gcp" && !cfg.SupportChanges.IsNull() {
			s.Diagnostics.AddError("Unexpected bootstrap input", "support_changes_wo is AWS/Azure-only.")
		}
	}
	if !change {
		return
	}
	if e := aceAccountPayloadSize(next, cfg); e != nil {
		s.Diagnostics.AddError("Invalid account replacement payload", e.Error())
	}
	// Require resolved bootstrap before any replacement. For a fresh create, known
	// malformed siblings still fail; unknowns can be resolved at apply.
	unknown := cfg.Provider.IsUnknown() || cfg.AccountID.IsUnknown() || cfg.AzureTenant.IsUnknown() || cfg.Organization.IsUnknown()
	if !cfg.Provider.IsUnknown() {
		if (cfg.Provider.ValueString() == "aws" || cfg.Provider.ValueString() == "azure") && cfg.SupportChanges.IsNull() {
			s.Diagnostics.AddError("Missing bootstrap option", "Explicit support_changes_wo is required before creation/replacement.")
		}
		if cfg.Provider.ValueString() == "aws" && cfg.FlowLogs.IsNull() {
			s.Diagnostics.AddError("Missing bootstrap option", "Explicit flow_logs_wo is required before creation/replacement.")
		}
	}
	for _, v := range cfg.bootstrapFields() {
		if v.IsUnknown() {
			unknown = true
		} else if v.IsNull() || v.ValueString() == "" {
			s.Diagnostics.AddError("Missing bootstrap input", "All matching typed write-only bootstrap fields must be supplied for creation/replacement.")
		}
	}
	if unknown {
		s.Diagnostics.AddError("Unresolved bootstrap configuration", "Resolve identity and all bootstrap inputs before creation or replacement.")
		return
	}
	if e := cfg.validateBootstrap(); e != nil {
		s.Diagnostics.AddError("Invalid bootstrap configuration", e.Error())
	}
}
func (r *aceAccountResource) Create(ctx context.Context, q resource.CreateRequest, s *resource.CreateResponse) {
	var m, cfg aceAccountModel
	s.Diagnostics.Append(q.Plan.Get(ctx, &m)...)
	s.Diagnostics.Append(q.Config.Get(ctx, &cfg)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := cfg.validateBootstrap(); e != nil {
		s.Diagnostics.AddError("Invalid bootstrap configuration", e.Error())
		return
	}
	v := m.value()
	v.AutoOnboarded = false
	var key string
	var e error
	switch v.Provider {
	case "aws":
		key, e = r.c.CreateAWSAccount(ctx, v, cfg.aws())
	case "azure":
		key, e = r.c.CreateAzureAccount(ctx, v, cfg.azure())
	case "gcp":
		key, e = r.c.CreateGCPAccount(ctx, v, cfg.gcp())
	default:
		e = errors.New("invalid cloud provider")
	}
	if e != nil {
		s.Diagnostics.AddError("ACE account creation failed", e.Error())
		return
	}
	v.AccountKey = key
	m.set(v)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
	got, e := r.c.Account(ctx, key)
	if e != nil {
		s.Diagnostics.AddError("ACE account readback failed", e.Error()+"; acknowledged accountKey retained.")
		return
	}
	if !client.SameACEAccount(v, *got) {
		s.Diagnostics.AddError("ACE account readback differs", "Acknowledged accountKey retained; provider/account identity, name or manual provenance did not match. Inspect before retrying.")
		return
	}
	m.set(*got)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
func (r *aceAccountResource) Read(ctx context.Context, q resource.ReadRequest, s *resource.ReadResponse) {
	s.State = q.State
	var m aceAccountModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	got, e := r.c.Account(ctx, m.ID.ValueString())
	if errors.Is(e, client.ErrNotFound) {
		s.State.RemoveResource(ctx)
		return
	}
	if e != nil {
		s.Diagnostics.AddError("ACE account read failed", e.Error())
		return
	}
	if got.AutoOnboarded || got.Provider != m.Provider.ValueString() || got.AccountID != m.AccountID.ValueString() {
		s.Diagnostics.AddError("ACE account provenance changed", "Manual provider/account identity no longer matches; state retained and mutation refused.")
		return
	}
	m.set(*got)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
func (r *aceAccountResource) Update(ctx context.Context, q resource.UpdateRequest, s *resource.UpdateResponse) {
	s.State = q.State
	var old, next aceAccountModel
	s.Diagnostics.Append(q.State.Get(ctx, &old)...)
	s.Diagnostics.Append(q.Plan.Get(ctx, &next)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := r.c.RenameAccount(ctx, old.value(), next.Name.ValueString()); e != nil {
		s.Diagnostics.AddError("ACE account rename failed", e.Error())
		return
	}
	v := old.value()
	v.Name = next.Name.ValueString()
	next.set(v)
	s.Diagnostics.Append(s.State.Set(ctx, next)...)
	got, e := r.c.Account(ctx, v.AccountKey)
	if e != nil {
		s.Diagnostics.AddError("ACE account readback failed", e.Error())
		return
	}
	if !client.SameACEAccount(v, *got) {
		s.Diagnostics.AddError("ACE account readback differs", "Owned registration retained; refresh before retrying.")
		return
	}
	next.set(*got)
	s.Diagnostics.Append(s.State.Set(ctx, next)...)
}
func (r *aceAccountResource) Delete(ctx context.Context, q resource.DeleteRequest, s *resource.DeleteResponse) {
	s.State = q.State
	var m aceAccountModel
	s.Diagnostics.Append(q.State.Get(ctx, &m)...)
	if s.Diagnostics.HasError() {
		return
	}
	if e := r.c.DeleteAccount(ctx, m.value()); e != nil {
		s.Diagnostics.AddError("ACE account deletion failed", e.Error())
	}
}
func (r *aceAccountResource) ImportState(ctx context.Context, q resource.ImportStateRequest, s *resource.ImportStateResponse) {
	got, e := r.c.Account(ctx, q.ID)
	if e != nil {
		s.Diagnostics.AddError("ACE account import failed", e.Error())
		return
	}
	if got.AutoOnboarded {
		s.Diagnostics.AddError("ACE account import refused", "Automatic registrations cannot be owned by this resource.")
		return
	}
	m := aceAccountModel{Version: types.StringValue("")}
	m.set(*got)
	s.Diagnostics.Append(s.State.Set(ctx, m)...)
}
