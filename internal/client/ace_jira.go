// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
)

const aceJiraPath = "/prevasio/api/v1/configurations/integrations/jira"

type ACEJira struct {
	ServerURL  string `json:"serverUrl"`
	UserName   string `json:"userName"`
	ProjectKey string `json:"projectKey"`
	IssueType  string `json:"defaultIssueType"`
	Priority   string `json:"defaultPriority"`
}

func ValidateACEJira(v ACEJira) error {
	if ValidateURL(v.ServerURL) != nil {
		return errors.New("server_url must be an HTTPS origin without credentials")
	}
	if ValidateACEEmail(v.UserName) != nil || strings.Contains(v.UserName, ":") {
		return errors.New("user_name must be a plain email address without colon")
	}
	for _, s := range []string{v.ProjectKey, v.IssueType, v.Priority} {
		if ValidateAppVizName(s) != nil {
			return errors.New("project_key, default_issue_type and default_priority must be nonempty without controls")
		}
	}
	return nil
}
func ValidateACESecret(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("a nonempty write-only token without control characters is required for creation or replacement")
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return errors.New("write-only token must not contain control characters")
		}
	}
	return nil
}
func (c *ACEClient) Jira(ctx context.Context) (*ACEJira, error) {
	raw, e := c.request(ctx, "GET", aceJiraPath, nil, nil)
	if e != nil {
		return nil, e
	}
	var w struct {
		Data *struct {
			ServerURL  *string `json:"serverUrl"`
			UserName   *string `json:"userName"`
			Token      *string `json:"apiToken"`
			ProjectKey *string `json:"projectKey"`
			IssueType  *string `json:"defaultIssueType"`
			Priority   *string `json:"defaultPriority"`
		} `json:"data"`
	}
	if aceDecode(raw, &w) != nil || w.Data == nil {
		return nil, ErrContract
	}
	d := w.Data
	// Only a literal empty object is absence; explicit null fields are incomplete.
	var empty struct {
		Data *struct{} `json:"data"`
	}
	if aceDecode(raw, &empty) == nil && empty.Data != nil {
		return nil, ErrNotFound
	}
	if d.ServerURL == nil || d.UserName == nil || d.Token == nil || d.ProjectKey == nil || d.IssueType == nil || d.Priority == nil {
		return nil, ErrContract
	}
	v := &ACEJira{*d.ServerURL, *d.UserName, *d.ProjectKey, *d.IssueType, *d.Priority}
	// Empty optional defaults are readable/importable even though new submissions
	// require explicit defaults. The masked token never enters managed state.
	if ValidateURL(v.ServerURL) != nil || ValidateACEEmail(v.UserName) != nil || ValidateAppVizName(v.ProjectKey) != nil {
		return nil, ErrContract
	}
	return v, nil
}
func (c *ACEClient) CreateJira(ctx context.Context, v ACEJira, rawToken string) error {
	if e := ValidateACEJira(v); e != nil {
		return e
	}
	if e := ValidateACESecret(rawToken); e != nil {
		return e
	}
	if _, e := c.Jira(ctx); !errors.Is(e, ErrNotFound) {
		if e != nil {
			return e
		}
		return errors.New("Jira integration exists; import it explicitly")
	}
	in := struct {
		ACEJira
		Token string `json:"apiToken"`
	}{v, base64.StdEncoding.EncodeToString([]byte(v.UserName + ":" + rawToken))}
	raw, e := c.request(ctx, "POST", aceJiraPath, nil, in)
	if e != nil {
		return e
	}
	return aceAck(raw, "Your Jira project settings were successfully tested and saved.")
}
func (c *ACEClient) DeleteJira(ctx context.Context, old ACEJira) error {
	current, e := c.Jira(ctx)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if *current != old {
		return errors.New("Jira configuration changed since refresh; refresh before deletion")
	}
	raw, e := c.request(ctx, "DELETE", aceJiraPath, nil, nil)
	if e != nil {
		return e
	}
	if e = aceAck(raw, "Jira settings have been deleted."); e != nil {
		return e
	}
	if _, e = c.Jira(ctx); errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	return errors.New("Jira deletion unconfirmed; state retained")
}
