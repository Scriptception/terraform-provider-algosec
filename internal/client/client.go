// SPDX-License-Identifier: MPL-2.0
// Package client implements the documented ASMS A32.60 REST contracts and separately gated experimental A33.20 device groups.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBody = 8 << 20
const api = "/afa/api/v1"

var ErrNotFound = errors.New("object absent from complete inventory")
var ErrContract = errors.New("API response does not match the documented contract")

type Options struct {
	AppVizURL, AppVizToken             string
	ExperimentalAppVizRoles            bool
	ExperimentalTrustedRules           bool
	ExperimentalDeviceGroups           bool
	URL, Username, Password, SessionID string
	Timeout                            time.Duration
	Insecure, ReadOnly                 bool
}
type Client struct {
	AppViz                      *AppVizClient
	experimentalTrustedRules    bool
	experimentalDeviceGroups    bool
	loginGate                   chan struct{}
	base                        string
	http                        *http.Client
	username, password, session string
	authMu                      sync.Mutex
	readOnly                    bool
}

// ValidateURL accepts an HTTPS origin only, without credentials, path, query or fragment.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("url must be an HTTPS origin without credentials, path, query or fragment")
	}
	if strings.ContainsAny(u.Host, "\\ \t\r\n") {
		return errors.New("invalid URL host")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("URL port must be between 1 and 65535")
		}
	}
	return nil
}
func New(o Options) (*Client, error) {
	if o.URL != "" || o.AppVizURL == "" {
		if err := ValidateURL(o.URL); err != nil {
			return nil, err
		}
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.Timeout < time.Second || o.Timeout > 5*time.Minute {
		return nil, errors.New("timeout must be between 1 and 300 seconds")
	}
	var appviz *AppVizClient
	if o.AppVizURL != "" || o.AppVizToken != "" {
		var err error
		appviz, err = NewAppVizClient(o.AppVizURL, o.AppVizToken, o.Timeout, o.ReadOnly, o.ExperimentalAppVizRoles)
		if err != nil {
			return nil, err
		}
	}
	if o.URL == "" && appviz != nil {
		if o.Username != "" || o.Password != "" || o.SessionID != "" {
			return nil, errors.New("AFA credentials require a separate url")
		}
		return &Client{AppViz: appviz, readOnly: o.ReadOnly}, nil
	}
	if o.SessionID != "" && (o.Username != "" || o.Password != "") {
		return nil, errors.New("session_id and username/password authentication are mutually exclusive")
	}
	if o.SessionID == "" && (o.Username == "" || o.Password == "") {
		return nil, errors.New("set session_id or both username and password")
	}
	if o.SessionID != "" && !validSession(o.SessionID) {
		return nil, errors.New("invalid session ID format")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.Insecure} // explicit opt-in only
	tr.ResponseHeaderTimeout = o.Timeout
	return &Client{AppViz: appviz, loginGate: make(chan struct{}, 1), base: strings.TrimRight(o.URL, "/"), http: &http.Client{Transport: tr, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, username: o.Username, password: o.Password, session: o.SessionID, readOnly: o.ReadOnly, experimentalDeviceGroups: o.ExperimentalDeviceGroups, experimentalTrustedRules: o.ExperimentalTrustedRules}, nil
}
func validSession(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == ',') {
			return false
		}
	}
	return s != ""
}

// Segment escapes identifiers exactly once. Dot segments and control bytes are refused.
func Segment(s string) (string, error) {
	if s == "" || s == "." || s == ".." {
		return "", errors.New("identifier must be nonempty and cannot be a dot segment")
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return "", errors.New("identifier contains a control character")
		}
	}
	return url.PathEscape(s), nil
}

// HTTPError deliberately excludes URLs, headers, and response bodies.
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("AlgoSec request failed (HTTP %d); check permissions and appliance availability", e.Status)
}
func (c *Client) login(ctx context.Context) error {
	if c.base == "" {
		return errors.New("AFA operations require separate url and AFA authentication")
	}
	select {
	case c.loginGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.loginGate }()
	c.authMu.Lock()
	authenticated := c.session != ""
	c.authMu.Unlock()
	if authenticated {
		return nil
	}
	var out struct {
		Status    *bool  `json:"status"`
		SessionID string `json:"SessionID"`
	}
	if err := c.request(ctx, "POST", "/fa/server/connection/login", nil, struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{c.username, c.password}, &out, ""); err != nil {
		return err
	}
	if out.Status == nil || !*out.Status || !validSession(out.SessionID) {
		return errors.New("AlgoSec login failed or returned an invalid session")
	}
	c.authMu.Lock()
	c.session = out.SessionID
	c.authMu.Unlock()
	return nil
}
func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	if method != "GET" && c.readOnly {
		return errors.New("provider read_only is enabled; mutation refused")
	}
	if err := c.login(ctx); err != nil {
		return err
	}
	c.authMu.Lock()
	session := c.session
	c.authMu.Unlock()
	return c.request(ctx, method, path, q, in, out, session)
}
func (c *Client) request(ctx context.Context, method, path string, q url.Values, in, out any, session string) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\r\n") {
		return errors.New("invalid API path")
	}
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return errors.New("cannot encode API request")
		}
		if len(body) > maxBody {
			return errors.New("API request exceeds 8 MiB limit")
		}
	}
	target := c.base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot construct API request")
	}
	// Disable net/http's replay facility, including on stale connections, for writes.
	if method != "GET" {
		req.GetBody = nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "terraform-provider-algosec")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: session})
	}
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("AlgoSec transport request failed; check connectivity, timeout and TLS trust")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return &HTTPError{res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("cannot read AlgoSec response")
	}
	if len(raw) > maxBody {
		return errors.New("AlgoSec response exceeds 8 MiB limit")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || !json.Valid(raw) {
		return ErrContract
	}
	// Success HTTP status alone is insufficient: documented APIs also return application errors.
	var status struct {
		Status     json.RawMessage `json:"status"`
		HTTPStatus string          `json:"httpStatus"`
		Error      json.RawMessage `json:"error"`
	}
	if raw[0] == '{' {
		if err := json.Unmarshal(raw, &status); err != nil {
			return ErrContract
		}
		if len(status.Status) > 0 && string(status.Status) != "true" && string(status.Status) != "\"true\"" {
			return errors.New("AlgoSec returned an unsuccessful application status")
		}
		if status.HTTPStatus != "" && status.HTTPStatus != "200" {
			return errors.New("AlgoSec returned an unsuccessful application HTTP status")
		}
		if len(status.Error) > 0 && string(status.Error) != "null" {
			return errors.New("AlgoSec returned an application error")
		}
	}
	if out == nil {
		return nil
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrContract
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ErrContract
	}
	return nil
}
