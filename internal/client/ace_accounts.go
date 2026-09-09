// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

const aceAccountPath = "/api/algosaas/accounts/v1/account"

type ACEAccount struct {
	AccountKey, AccountID, Provider, Name, AzureTenant, OrganizationID string
	AutoOnboarded                                                      bool
}
type aceScanStatus struct {
	Message     *string `json:"message"`
	LastSuccess *int64  `json:"lastSuccess"`
	Status      *string `json:"status"`
	Timestamp   *int64  `json:"timestamp"`
}

func (c *ACEClient) Accounts(ctx context.Context) ([]ACEAccount, error) {
	raw, e := c.request(ctx, "GET", aceAccountPath, nil, nil)
	if e != nil {
		return nil, e
	}
	var w []struct {
		ID           *string `json:"accountId"`
		Key          *string `json:"accountKey"`
		Provider     *string `json:"provider"`
		Name         *string `json:"name"`
		Auto         *bool   `json:"autoOnboarded"`
		Onboarded    *int64  `json:"onboarded"`
		AzureTenant  *string `json:"azureTenant"`
		Organization *string `json:"organizationId"`
		Permission   *struct {
			Write    *bool `json:"enableWrite"`
			FlowLogs *bool `json:"enableFlowLogs"`
		} `json:"permission"`
		Scan *struct {
			CNS *aceScanStatus `json:"CloudNetworkSecurity"`
			CAA *aceScanStatus `json:"CloudAppAnalyzer"`
		} `json:"scanStatus"`
	}
	if aceDecode(raw, &w) != nil || w == nil {
		return nil, ErrContract
	}
	out := []ACEAccount{}
	keys := map[string]bool{}
	ids := map[string]bool{}
	for _, v := range w {
		if v.ID == nil || v.Key == nil || v.Provider == nil || v.Name == nil || v.Auto == nil || ValidateACEProvider(*v.Provider) != nil || ValidateAppVizName(*v.ID) != nil || ValidateAppVizName(*v.Key) != nil || ValidateAppVizName(*v.Name) != nil || keys[*v.Key] || ids[*v.Provider+":"+*v.ID] {
			return nil, ErrContract
		}
		a := ACEAccount{AccountID: *v.ID, AccountKey: *v.Key, Provider: *v.Provider, Name: *v.Name, AutoOnboarded: *v.Auto}
		if v.AzureTenant != nil {
			a.AzureTenant = *v.AzureTenant
		}
		if v.Organization != nil {
			a.OrganizationID = *v.Organization
		}
		if (a.Provider == "azure" && a.AzureTenant == "") || (a.Provider == "gcp" && a.OrganizationID == "") {
			return nil, ErrContract
		}
		keys[a.AccountKey] = true
		ids[a.Provider+":"+a.AccountID] = true
		out = append(out, a)
	}
	return out, nil
}
func (c *ACEClient) Account(ctx context.Context, key string) (*ACEAccount, error) {
	if ValidateAppVizName(key) != nil {
		return nil, errors.New("nonempty exact account_key required")
	}
	v, e := c.Accounts(ctx)
	if e != nil {
		return nil, e
	}
	for _, a := range v {
		if a.AccountKey == key {
			return &a, nil
		}
	}
	return nil, ErrNotFound
}
func (c *ACEClient) createAccount(ctx context.Context, v ACEAccount, in any) (string, error) {
	if e := ValidateACEAccount(v); e != nil {
		return "", e
	}
	all, e := c.Accounts(ctx)
	if e != nil {
		return "", e
	}
	for _, a := range all {
		if (a.Provider == v.Provider && a.AccountID == v.AccountID) || a.Name == v.Name {
			return "", errors.New("account identity or name exists; import explicitly")
		}
	}
	raw, e := c.requestCode(ctx, "POST", aceAccountPath+"/"+v.Provider, nil, in, 201)
	if e != nil {
		return "", e
	}
	var ack struct {
		Key *string `json:"accountKey"`
	}
	if aceDecode(raw, &ack) != nil || ack.Key == nil || ValidateAppVizName(*ack.Key) != nil {
		return "", ErrContract
	}
	for _, a := range all {
		if a.AccountKey == *ack.Key {
			return "", ErrContract
		}
	}
	return *ack.Key, nil
}
func SameACEAccount(a, b ACEAccount) bool {
	return a.AccountKey == b.AccountKey && a.AccountID == b.AccountID && a.Provider == b.Provider && a.Name == b.Name && a.AutoOnboarded == b.AutoOnboarded && (a.Provider != "azure" || a.AzureTenant == b.AzureTenant) && (a.Provider != "gcp" || a.OrganizationID == b.OrganizationID)
}
func (c *ACEClient) RenameAccount(ctx context.Context, old ACEAccount, name string) error {
	if ValidateAppVizName(name) != nil {
		return errors.New("name must be nonempty without controls")
	}
	current, e := c.Account(ctx, old.AccountKey)
	if e != nil {
		return e
	}
	if current.AutoOnboarded || !SameACEAccount(*current, old) {
		return errors.New("account provenance or configuration changed; refresh before mutation")
	}
	segment, e := Segment(current.AccountID)
	if e != nil {
		return e
	}
	_, e = c.requestCode(ctx, "PATCH", aceAccountPath+"/"+current.Provider+"/"+segment, nil, struct {
		Name string `json:"name"`
	}{name}, 204)
	return e
}
func (c *ACEClient) DeleteAccount(ctx context.Context, old ACEAccount) error {
	current, e := c.Account(ctx, old.AccountKey)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if current.AutoOnboarded || !SameACEAccount(*current, old) {
		return errors.New("account provenance or configuration changed; deletion refused")
	}
	segment, e := Segment(current.AccountID)
	if e != nil {
		return e
	}
	if _, e = c.requestCode(ctx, "DELETE", aceAccountPath+"/"+current.Provider+"/"+segment, nil, nil, 204); e != nil {
		return e
	}
	if _, e = c.Account(ctx, old.AccountKey); errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	return errors.New("account deletion unconfirmed; state retained")
}

var aceUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var aceAWSID = regexp.MustCompile(`^[0-9]{12}$`)
var aceGCPID = regexp.MustCompile(`^[a-z][a-z0-9\-]{4,28}[a-z0-9]$`)

func ValidateACEAccount(v ACEAccount) error {
	if ValidateACEProvider(v.Provider) != nil || ValidateAppVizName(v.Name) != nil || v.AutoOnboarded {
		return errors.New("manual account requires valid provider and nonempty name")
	}
	switch v.Provider {
	case "aws":
		if !aceAWSID.MatchString(v.AccountID) {
			return errors.New("AWS account_id must be 12 digits")
		}
	case "azure":
		if !aceUUID.MatchString(v.AccountID) || !aceUUID.MatchString(v.AzureTenant) {
			return errors.New("Azure account_id and azure_tenant must be UUIDs")
		}
	case "gcp":
		if !aceGCPID.MatchString(v.AccountID) || ValidateAppVizName(v.OrganizationID) != nil {
			return errors.New("GCP account_id must be a project ID and organization_id must be supplied")
		}
	}
	return nil
}

type ACEAWSBootstrap struct {
	RoleARN        string `json:"roleArn"`
	ExternalID     string `json:"externalId"`
	Name           string `json:"name"`
	SupportChanges bool   `json:"supportChanges"`
	FlowLogs       bool   `json:"flowLogs"`
}
type ACEAzureBootstrap struct {
	TenantID          string `json:"tenantId"`
	SubscriptionID    string `json:"subscriptionId"`
	ApplicationID     string `json:"applicationId"`
	ApplicationSecret string `json:"applicationSecret"`
	Name              string `json:"name"`
	SupportChanges    bool   `json:"supportChanges"`
}
type ACEGCPBootstrap struct {
	OrganizationID string `json:"organization_id"`
	Type           string `json:"type"`
	ProjectID      string `json:"project_id"`
	PrivateKeyID   string `json:"private_key_id"`
	PrivateKey     string `json:"private_key"`
	ClientEmail    string `json:"client_email"`
	ClientID       string `json:"client_id"`
	AuthURI        string `json:"auth_uri"`
	TokenURI       string `json:"token_uri"`
	AuthCertURL    string `json:"auth_provider_x509_cert_url"`
	ClientCertURL  string `json:"client_x509_cert_url"`
	Name           string `json:"name"`
}

func ValidateACEAWSBootstrap(v ACEAccount, b ACEAWSBootstrap) error {
	if ValidateACEBootstrapField("role_arn_wo", b.RoleARN, v.AccountID) != nil || ValidateACESecret(b.ExternalID) != nil {
		return errors.New("valid matching AWS role_arn_wo and nonempty external_id_wo are required")
	}
	return nil
}

func ValidateACEAzureBootstrap(b ACEAzureBootstrap) error {
	if !aceUUID.MatchString(b.ApplicationID) || ValidateACESecret(b.ApplicationSecret) != nil {
		return errors.New("Azure application_id_wo UUID and nonempty application_secret_wo are required")
	}
	return nil
}
func ValidateACEGCPBootstrap(b ACEGCPBootstrap) error {
	if b.Type != "service_account" || ValidateACESecret(b.PrivateKeyID) != nil || ValidateACEEmail(b.ClientEmail) != nil || ValidateAppVizName(b.ClientID) != nil {
		return errors.New("complete typed GCP service-account bootstrap fields are required")
	}
	block, rest := pem.Decode([]byte(b.PrivateKey))
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("private_key_wo must contain one PKCS8 private key")
	}
	if _, e := x509.ParsePKCS8PrivateKey(block.Bytes); e != nil {
		return errors.New("private_key_wo must contain a valid PKCS8 private key")
	}
	for _, s := range []string{b.AuthURI, b.TokenURI, b.AuthCertURL, b.ClientCertURL} {
		u, e := url.Parse(s)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.New("GCP bootstrap URLs must be HTTPS without credentials or fragments")
		}
	}
	return nil
}
func (c *ACEClient) CreateAWSAccount(ctx context.Context, v ACEAccount, b ACEAWSBootstrap) (string, error) {
	if v.Provider != "aws" {
		return "", ErrContract
	}
	if e := ValidateACEAWSBootstrap(v, b); e != nil {
		return "", e
	}
	b.Name = v.Name
	return c.createAccount(ctx, v, b)
}
func (c *ACEClient) CreateAzureAccount(ctx context.Context, v ACEAccount, b ACEAzureBootstrap) (string, error) {
	if v.Provider != "azure" {
		return "", ErrContract
	}
	if e := ValidateACEAzureBootstrap(b); e != nil {
		return "", e
	}
	b.Name = v.Name
	b.TenantID = v.AzureTenant
	b.SubscriptionID = v.AccountID
	return c.createAccount(ctx, v, b)
}
func (c *ACEClient) CreateGCPAccount(ctx context.Context, v ACEAccount, b ACEGCPBootstrap) (string, error) {
	if v.Provider != "gcp" {
		return "", ErrContract
	}
	if e := ValidateACEGCPBootstrap(b); e != nil {
		return "", e
	}
	b.Name = v.Name
	b.OrganizationID = v.OrganizationID
	b.ProjectID = v.AccountID
	return c.createAccount(ctx, v, b)
}

// ValidateACEBootstrapField checks each known field independently so unresolved
// siblings cannot hide deterministic errors during planning.
func ValidateACEBootstrapField(field, value, accountID string) error {
	switch field {
	case "role_arn_wo":
		if !regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[^\s]+$`).MatchString(value) {
			return errors.New("role_arn_wo must be an AWS IAM role ARN")
		}
		if accountID != "" && !strings.HasPrefix(value, "arn:aws:iam::"+accountID+":role/") {
			return errors.New("role_arn_wo must match account_id")
		}
	case "application_id_wo":
		if !aceUUID.MatchString(value) {
			return errors.New("application_id_wo must be a UUID")
		}
	case "credential_type_wo":
		if value != "service_account" {
			return errors.New("credential_type_wo must be service_account")
		}
	case "client_email_wo":
		if ValidateACEEmail(value) != nil {
			return errors.New("client_email_wo must be a plain email address")
		}
	case "private_key_wo":
		block, rest := pem.Decode([]byte(value))
		if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
			return errors.New("private_key_wo must contain one PKCS8 private key")
		}
		if _, e := x509.ParsePKCS8PrivateKey(block.Bytes); e != nil {
			return errors.New("invalid PKCS8 private_key_wo")
		}
	case "auth_uri_wo", "token_uri_wo", "auth_provider_x509_cert_url_wo", "client_x509_cert_url_wo":
		u, e := url.Parse(value)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.New("bootstrap URI must be HTTPS without embedded credentials or fragments")
		}
	default:
		return ValidateACESecret(value)
	}
	return nil
}
