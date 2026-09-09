// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"encoding/base64"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func addKnownString(dst map[string]any, name string, value types.String) {
	if !value.IsNull() && !value.IsUnknown() {
		dst[name] = value.ValueString()
	}
}

func addKnownBool(dst map[string]any, name string, value types.Bool) {
	if !value.IsNull() && !value.IsUnknown() {
		dst[name] = value.ValueBool()
	}
}

func aceJiraPayloadSize(m aceJiraModel, token types.String) error {
	payload := map[string]any{}
	addKnownString(payload, "serverUrl", m.ServerURL)
	addKnownString(payload, "userName", m.UserName)
	addKnownString(payload, "projectKey", m.ProjectKey)
	addKnownString(payload, "defaultIssueType", m.IssueType)
	addKnownString(payload, "defaultPriority", m.Priority)
	if !token.IsNull() && !token.IsUnknown() {
		user := ""
		if !m.UserName.IsUnknown() && !m.UserName.IsNull() {
			user = m.UserName.ValueString()
		}
		// A known token must contribute to the lower bound even when a
		// sibling username is unresolved. Any eventual username can only
		// increase the serialized user:token value.
		payload["apiToken"] = base64.StdEncoding.EncodeToString([]byte(user + ":" + token.ValueString()))
	}
	return client.ValidateACESerializedPayload(payload)
}

func aceAccountPayloadSize(m, cfg aceAccountModel) error {
	payload := map[string]any{}
	addKnownString(payload, "name", m.Name)
	switch m.Provider.ValueString() {
	case "aws":
		addKnownString(payload, "roleArn", cfg.RoleARN)
		addKnownString(payload, "externalId", cfg.ExternalID)
		addKnownBool(payload, "supportChanges", cfg.SupportChanges)
		addKnownBool(payload, "flowLogs", cfg.FlowLogs)
	case "azure":
		addKnownString(payload, "tenantId", m.AzureTenant)
		addKnownString(payload, "subscriptionId", m.AccountID)
		addKnownString(payload, "applicationId", cfg.ApplicationID)
		addKnownString(payload, "applicationSecret", cfg.ApplicationSecret)
		addKnownBool(payload, "supportChanges", cfg.SupportChanges)
	case "gcp":
		addKnownString(payload, "organization_id", m.Organization)
		addKnownString(payload, "type", cfg.CredentialType)
		addKnownString(payload, "project_id", m.AccountID)
		addKnownString(payload, "private_key_id", cfg.PrivateKeyID)
		addKnownString(payload, "private_key", cfg.PrivateKey)
		addKnownString(payload, "client_email", cfg.ClientEmail)
		addKnownString(payload, "client_id", cfg.ClientID)
		addKnownString(payload, "auth_uri", cfg.AuthURI)
		addKnownString(payload, "token_uri", cfg.TokenURI)
		addKnownString(payload, "auth_provider_x509_cert_url", cfg.AuthCertURL)
		addKnownString(payload, "client_x509_cert_url", cfg.ClientCertURL)
	}
	return client.ValidateACESerializedPayload(payload)
}

func aceThreatPayloadSize(m aceThreatModel) error {
	payload := map[string]any{}
	addKnownString(payload, "destination", m.Destination)
	addKnownString(payload, "description", m.Description)
	if !m.List.IsUnknown() && m.List.ValueString() == "block-list" {
		addKnownString(payload, "severity", m.Severity)
	}
	return client.ValidateACESerializedPayload(payload)
}
