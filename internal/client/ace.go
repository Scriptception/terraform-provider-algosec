// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const aceCDPath = "/prevasio/api/v1/configurations/integrations/cd-mitigation"

// ACEClient is a separate SaaS bearer-authenticated client. It never uses AFA
// cookies, obtains credentials, follows redirects, or refreshes/replays writes.
type ACEClient struct {
	base, token       string
	http              *http.Client
	readOnly, enabled bool
}

func NewACEClient(origin, token string, timeout time.Duration, readOnly, enabled bool) (*ACEClient, error) {
	if err := ValidateURL(origin); err != nil {
		return nil, err
	}
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("set a nonempty ACE SaaS bearer token without whitespace")
	}
	for _, b := range []byte(token) {
		if b < 33 || b > 126 {
			return nil, errors.New("invalid ACE SaaS bearer token format")
		}
	}
	if timeout < time.Second || timeout > 300*time.Second {
		return nil, errors.New("timeout must be between 1 and 300 seconds")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = timeout
	return &ACEClient{base: strings.TrimRight(origin, "/"), token: token, http: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, readOnly: readOnly, enabled: enabled}, nil
}
func (c *ACEClient) request(ctx context.Context, method, path string, q url.Values, in any) ([]byte, error) {
	return c.requestCode(ctx, method, path, q, in, http.StatusOK)
}
func (c *ACEClient) requestCode(ctx context.Context, method, path string, q url.Values, in any, status int) ([]byte, error) {
	if c == nil || !c.enabled {
		return nil, errors.New("ACE requires experimental_ace_public_contracts=true and separate SaaS configuration")
	}
	if method != "GET" && c.readOnly {
		return nil, errors.New("provider read_only is enabled; mutation refused")
	}
	var data []byte
	var err error
	if in != nil {
		data, err = json.Marshal(in)
		if err != nil {
			return nil, ErrContract
		}
		if len(data) > maxBody {
			return nil, errors.New("API request exceeds 8 MiB limit")
		}
	}
	target := c.base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("cannot construct ACE request")
	}
	if method != "GET" {
		req.GetBody = nil
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "terraform-provider-algosec")
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("ACE transport request failed; check connectivity, timeout and TLS trust")
	}
	defer res.Body.Close()
	if res.StatusCode != status {
		return nil, &HTTPError{res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, errors.New("cannot read ACE response")
	}
	if len(raw) > maxBody {
		return nil, errors.New("ACE response exceeds 8 MiB limit")
	}
	if status == http.StatusNoContent {
		if len(raw) != 0 {
			return nil, ErrContract
		}
		return raw, nil
	}
	if !json.Valid(raw) {
		return nil, ErrContract
	}
	if err = trustedJSON(raw); err != nil {
		return nil, ErrContract
	}
	return raw, nil
}

// Decode only typed contracts; reject unknown envelope/error fields, duplicate keys,
// missing required fields and malformed JSON without exposing response content.
func aceDecode(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if !utf8.Valid(raw) || !json.Valid(raw) || trustedJSON(raw) != nil || aceJSONFieldCollision(raw) != nil || d.Decode(out) != nil {
		return ErrContract
	}
	return nil
}

// encoding/json matches struct fields case-insensitively and with Unicode
// simple-folding. Reject those aliases before decoding so a contradictory
// acknowledgement cannot be reduced to whichever key appeared last.
func aceJSONFieldCollision(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return ErrContract
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			var seen []string
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return ErrContract
				}
				name, ok := key.(string)
				if !ok {
					return ErrContract
				}
				for _, prior := range seen {
					if strings.EqualFold(prior, name) {
						return ErrContract
					}
				}
				seen = append(seen, name)
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return ErrContract
		}
		if _, err := dec.Token(); err != nil {
			return ErrContract
		}
		return nil
	}
	return walk()
}

// ValidateACESerializedPayload applies the same Go JSON encoding and 8 MiB
// request limit used by ACE mutations. Callers may omit unresolved fields to
// validate a conservative known-field lower bound during planning.
func ValidateACESerializedPayload(in any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return ErrContract
	}
	if len(b) > maxBody {
		return errors.New("API request exceeds 8 MiB limit")
	}
	return nil
}
func aceAck(raw []byte, expected string) error {
	var w struct {
		Data *struct {
			Message *string `json:"message"`
		} `json:"data"`
	}
	if aceDecode(raw, &w) != nil || w.Data == nil || w.Data.Message == nil || *w.Data.Message != expected {
		return ErrContract
	}
	return nil
}
func ValidateACEProvider(p string) error {
	if !slices.Contains([]string{"aws", "azure", "gcp"}, p) {
		return errors.New("cloud_provider must be aws, azure or gcp")
	}
	return nil
}
func ValidateACEEmail(s string) error {
	a, e := mail.ParseAddress(s)
	if e != nil || a.Address != s || a.Name != "" || strings.ContainsAny(s, "\r\n") {
		return errors.New("emails must contain nonempty plain email addresses")
	}
	return nil
}
func validateACEEmails(v []string) error {
	seen := map[string]bool{}
	for _, s := range v {
		if ValidateACEEmail(s) != nil || seen[s] {
			return errors.New("emails must contain unique valid addresses")
		}
		seen[s] = true
	}
	return nil
}
func SameACEEmails(a, b []string) bool {
	a = slices.Clone(a)
	b = slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
func (c *ACEClient) CDEmails(ctx context.Context, p string) ([]string, error) {
	if e := ValidateACEProvider(p); e != nil {
		return nil, e
	}
	raw, e := c.request(ctx, "GET", aceCDPath, url.Values{"provider": {p}}, nil)
	if e != nil {
		return nil, e
	}
	var w struct {
		Data *struct {
			Threat *struct {
				Enabled  *bool `json:"enabled"`
				Severity *int  `json:"minimumSeverityLevel"`
			} `json:"threatManagement"`
			Notifications *struct {
				Emails []*string `json:"emails"`
			} `json:"violationNotifications"`
		} `json:"data"`
	}
	if aceDecode(raw, &w) != nil || w.Data == nil || w.Data.Threat == nil || w.Data.Threat.Enabled == nil || w.Data.Threat.Severity == nil || *w.Data.Threat.Severity < 0 || *w.Data.Threat.Severity > 2 || w.Data.Notifications == nil || w.Data.Notifications.Emails == nil {
		return nil, ErrContract
	}
	emails := []string{}
	for _, s := range w.Data.Notifications.Emails {
		if s == nil {
			return nil, ErrContract
		}
		emails = append(emails, *s)
	}
	if validateACEEmails(emails) != nil {
		return nil, ErrContract
	}
	slices.Sort(emails)
	return emails, nil
}
func (c *ACEClient) patchCDEmails(ctx context.Context, p string, emails []string) error {
	in := struct {
		Notifications struct {
			Emails []string `json:"emails"`
		} `json:"violationNotifications"`
	}{}
	in.Notifications.Emails = append([]string{}, emails...)
	raw, e := c.request(ctx, "PATCH", aceCDPath, url.Values{"provider": {p}}, in)
	if e != nil {
		return e
	}
	return aceAck(raw, "Your CD mitigation settings were successfully updated.")
}

// CreateCDEmails returns success only after the operation-specific acknowledgement.
// The caller records identity before its subsequent readback.
func (c *ACEClient) CreateCDEmails(ctx context.Context, p string, emails []string) error {
	if len(emails) == 0 {
		return errors.New("managed emails must be nonempty")
	}
	if e := validateACEEmails(emails); e != nil {
		return e
	}
	current, e := c.CDEmails(ctx, p)
	if e != nil {
		return e
	}
	if len(current) != 0 {
		return errors.New("email set already exists; import it explicitly")
	}
	return c.patchCDEmails(ctx, p, emails)
}
func (c *ACEClient) ChangeCDEmails(ctx context.Context, p string, old, next []string) error {
	if e := validateACEEmails(next); e != nil {
		return e
	}
	current, e := c.CDEmails(ctx, p)
	if e != nil {
		return e
	}
	if len(next) == 0 && len(current) == 0 {
		return nil
	}
	if !SameACEEmails(current, old) {
		return errors.New("email set changed since refresh; refresh before mutation")
	}
	return c.patchCDEmails(ctx, p, next)
}
