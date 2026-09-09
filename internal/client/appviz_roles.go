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
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const appVizRolePath = "/BusinessFlow/rest/v1/settings/permissions/role"

// AppVizClient is a separate SaaS bearer-authenticated client. It never uses AFA
// cookies, obtains credentials, follows redirects, or refreshes/replays writes.
type AppVizClient struct {
	base, token       string
	http              *http.Client
	readOnly, enabled bool
}

func NewAppVizClient(origin, token string, timeout time.Duration, readOnly, enabled bool) (*AppVizClient, error) {
	if err := ValidateURL(origin); err != nil {
		return nil, err
	}
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("set a nonempty AppViz SaaS bearer token without whitespace")
	}
	for _, b := range []byte(token) {
		if b < 33 || b > 126 {
			return nil, errors.New("invalid AppViz SaaS bearer token format")
		}
	}
	if timeout < time.Second || timeout > 300*time.Second {
		return nil, errors.New("timeout must be between 1 and 300 seconds")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = timeout
	return &AppVizClient{base: strings.TrimRight(origin, "/"), token: token, http: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, readOnly: readOnly, enabled: enabled}, nil
}
func (c *AppVizClient) request(ctx context.Context, method, path string, q url.Values, in any) ([]byte, error) {
	if c == nil || !c.enabled {
		return nil, errors.New("AppViz SaaS roles require experimental_appviz_roles=true and separate SaaS configuration")
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
		return nil, errors.New("cannot construct AppViz request")
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
		return nil, errors.New("AppViz transport request failed; check connectivity, timeout and TLS trust")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, &HTTPError{res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, errors.New("cannot read AppViz response")
	}
	if len(raw) > maxBody {
		return nil, errors.New("AppViz response exceeds 8 MiB limit")
	}
	if !json.Valid(raw) {
		return nil, ErrContract
	}
	if err = trustedJSON(raw); err != nil {
		return nil, ErrContract
	}
	return raw, nil
}

// AppVizRole owns the complete readable users/global/application permission sets.
// Description and LDAP linkage are deliberately not managed: GET omits them.
type AppVizRole struct {
	Name               string
	Enabled            bool
	Users, Permissions []string
	Applications       map[string]string
}
type roleWire struct {
	Name        *string  `json:"name"`
	Enabled     *bool    `json:"enabled"`
	Users       []string `json:"roleUsers"`
	Permissions []struct {
		Name    *string `json:"name"`
		Allowed *bool   `json:"allowed"`
	} `json:"authorizedViewsAndActions"`
	Applications []struct {
		ID         *int64  `json:"applicationID"`
		Name       *string `json:"name"`
		Permission *string `json:"permission"`
	} `json:"authorizedApplications"`
}

func ValidateAppVizName(s string) error {
	if !utf8.ValidString(s) || strings.TrimSpace(s) == "" {
		return errors.New("name must be nonblank UTF-8")
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return errors.New("name contains a control character")
		}
	}
	return nil
}

// The only documented implication selected here: refresh confers viewing.
func ValidateAppVizPermissionClosure(permissions []string) error {
	if slices.Contains(permissions, "refreshVulnerability") && !slices.Contains(permissions, "viewVulnerability") {
		return errors.New("refreshVulnerability requires explicitly owning viewVulnerability; viewing cannot be revoked while refresh remains")
	}
	return nil
}
func ValidateAppVizRole(r AppVizRole) error {
	if e := ValidateAppVizName(r.Name); e != nil {
		return e
	}
	for _, items := range [][]string{r.Users, r.Permissions} {
		seen := map[string]bool{}
		for _, v := range items {
			if ValidateAppVizName(v) != nil || seen[v] {
				return errors.New("users and permissions must contain unique nonblank names")
			}
			seen[v] = true
		}
	}
	for id, p := range r.Applications {
		n, e := strconv.ParseInt(id, 10, 64)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
			return errors.New("application permission keys must be canonical positive integer revision IDs")
		}
		if p != "view" && p != "edit" {
			return errors.New("application permission must be view or edit")
		}
	}
	return nil
}
func decodeRole(raw []byte, name string) (*AppVizRole, error) {
	var w roleWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&w); e != nil {
		return nil, ErrContract
	}
	if w.Name == nil || *w.Name != name || w.Enabled == nil || w.Users == nil || w.Permissions == nil || w.Applications == nil {
		return nil, ErrContract
	}
	r := &AppVizRole{Name: *w.Name, Enabled: *w.Enabled, Users: w.Users, Permissions: []string{}, Applications: map[string]string{}}
	seen := map[string]bool{}
	for _, p := range w.Permissions {
		if p.Name == nil || p.Allowed == nil || ValidateAppVizName(*p.Name) != nil || seen[*p.Name] {
			return nil, ErrContract
		}
		seen[*p.Name] = true
		if *p.Allowed {
			r.Permissions = append(r.Permissions, *p.Name)
		}
	}
	for _, a := range w.Applications {
		if a.ID == nil || a.Name == nil || a.Permission == nil {
			return nil, ErrContract
		}
		id := strconv.FormatInt(*a.ID, 10)
		if _, ok := r.Applications[id]; ok {
			return nil, ErrContract
		}
		r.Applications[id] = *a.Permission
	}
	if ValidateAppVizRole(*r) != nil {
		return nil, ErrContract
	}
	slices.Sort(r.Users)
	slices.Sort(r.Permissions)
	return r, nil
}
func (c *AppVizClient) Role(ctx context.Context, name string) (*AppVizRole, error) {
	if e := ValidateAppVizName(name); e != nil {
		return nil, e
	}
	raw, e := c.request(ctx, "GET", appVizRolePath, url.Values{"name": {name}}, nil)
	if e != nil {
		var h *HTTPError
		if errors.As(e, &h) && h.Status == 404 {
			return nil, ErrNotFound
		}
		return nil, e
	}
	return decodeRole(raw, name)
}

type appPermission struct {
	ID         string `json:"applicationID"`
	Permission string `json:"permission"`
}

func appPermissions(m map[string]string) []appPermission {
	a := []appPermission{}
	for id, p := range m {
		a = append(a, appPermission{id, p})
	}
	slices.SortFunc(a, func(a, b appPermission) int { return strings.Compare(a.ID, b.ID) })
	return a
}

// Share the exact wire representation with planning: JSON escaping affects size.
func appVizRoleCreatePayload(r AppVizRole) any {
	return struct {
		Name         string          `json:"name"`
		Enabled      bool            `json:"enabled"`
		Users        []string        `json:"users"`
		Permissions  []string        `json:"authorizedViewsAndActions"`
		Applications []appPermission `json:"authorizedApplications"`
	}{r.Name, r.Enabled, append([]string{}, r.Users...), append([]string{}, r.Permissions...), appPermissions(r.Applications)}
}
func ValidateAppVizRoleCreateSize(r AppVizRole) error {
	raw, err := json.Marshal(appVizRoleCreatePayload(r))
	if err != nil {
		return ErrContract
	}
	if len(raw) > maxBody {
		return errors.New("API request exceeds 8 MiB limit")
	}
	return nil
}
func (c *AppVizClient) CreateRole(ctx context.Context, r AppVizRole) (*AppVizRole, error) {
	if e := ValidateAppVizRole(r); e != nil {
		return nil, e
	}
	if e := ValidateAppVizPermissionClosure(r.Permissions); e != nil {
		return nil, e
	}
	if e := ValidateAppVizRoleCreateSize(r); e != nil {
		return nil, e
	}
	if _, e := c.Role(ctx, r.Name); !errors.Is(e, ErrNotFound) {
		if e != nil {
			return nil, e
		}
		return nil, errors.New("AppViz role already exists; import it explicitly")
	}
	in := appVizRoleCreatePayload(r)
	raw, e := c.request(ctx, "POST", appVizRolePath+"/new", nil, in)
	if e != nil {
		return nil, e
	}
	// Only this operation's returned role establishes ownership; no failed-create GET.
	return decodeRole(raw, r.Name)
}
func SameAppVizRole(a, b AppVizRole) bool {
	a.Users = slices.Clone(a.Users)
	b.Users = slices.Clone(b.Users)
	a.Permissions = slices.Clone(a.Permissions)
	b.Permissions = slices.Clone(b.Permissions)
	slices.Sort(a.Users)
	slices.Sort(b.Users)
	slices.Sort(a.Permissions)
	slices.Sort(b.Permissions)
	return a.Name == b.Name && a.Enabled == b.Enabled && slices.Equal(a.Users, b.Users) && slices.Equal(a.Permissions, b.Permissions) && reflect.DeepEqual(a.Applications, b.Applications)
}

type namesChange struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

func nameDelta(old, next []string) namesChange {
	d := namesChange{[]string{}, []string{}}
	for _, x := range next {
		if !slices.Contains(old, x) {
			d.Add = append(d.Add, x)
		}
	}
	for _, x := range old {
		if !slices.Contains(next, x) {
			d.Remove = append(d.Remove, x)
		}
	}
	return d
}
func (c *AppVizClient) UpdateRole(ctx context.Context, old, next AppVizRole) (*AppVizRole, error) {
	if e := ValidateAppVizRole(next); e != nil {
		return nil, e
	}
	if e := ValidateAppVizPermissionClosure(next.Permissions); e != nil {
		return nil, e
	}
	if old.Name != next.Name || old.Enabled != next.Enabled || !reflect.DeepEqual(old.Applications, next.Applications) {
		return nil, errors.New("role name, enabled and application permission changes require replacement")
	}
	current, e := c.Role(ctx, old.Name)
	if e != nil {
		return nil, e
	}
	if !SameAppVizRole(*current, old) {
		return nil, errors.New("AppViz role changed since refresh; refresh the plan before updating")
	}
	in := struct {
		Users        namesChange `json:"users"`
		Permissions  namesChange `json:"authorizedViewsAndActionChanges"`
		Applications struct {
			Add    []appPermission `json:"add"`
			Remove []int64         `json:"remove"`
		} `json:"authorizedApplicationsChanges"`
	}{Users: nameDelta(old.Users, next.Users), Permissions: nameDelta(old.Permissions, next.Permissions)}
	in.Applications.Add = []appPermission{}
	in.Applications.Remove = []int64{}
	raw, e := c.request(ctx, "POST", appVizRolePath, url.Values{"name": {old.Name}}, in)
	if e != nil {
		return nil, e
	}
	return decodeRole(raw, old.Name)
}
func (c *AppVizClient) DeleteRole(ctx context.Context, old AppVizRole) error {
	current, e := c.Role(ctx, old.Name)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if !SameAppVizRole(*current, old) {
		return errors.New("AppViz role changed since refresh; refresh the plan before deleting")
	}
	raw, e := c.request(ctx, "DELETE", appVizRolePath, url.Values{"name": {old.Name}}, nil)
	if e != nil {
		return e
	}
	var ack struct {
		Body  json.RawMessage `json:"body"`
		Code  *string         `json:"statusCode"`
		Value *int            `json:"statusCodeValue"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&ack) != nil || ack.Code == nil || *ack.Code == "" || ack.Value == nil || (*ack.Value != 0 && (*ack.Value < 100 || *ack.Value >= 300)) || len(ack.Body) == 0 {
		return ErrContract
	}
	// The body is untyped, but explicit failure indicators cannot be ignored.
	var body map[string]json.RawMessage
	if json.Unmarshal(ack.Body, &body) != nil || body == nil {
		return ErrContract
	}
	for key, value := range body {
		text := strings.TrimSpace(string(value))
		switch strings.ToLower(key) {
		case "success", "status":
			if text == "false" || strings.EqualFold(text, `"Failure"`) || strings.EqualFold(text, `"Error"`) {
				return ErrContract
			}
		case "error", "errors":
			if text != "null" && text != "{}" && text != "[]" && text != `""` {
				return ErrContract
			}
		}
	}
	code := strings.ToUpper(*ack.Code)
	if strings.HasPrefix(code, "3") || strings.HasPrefix(code, "4") || strings.HasPrefix(code, "5") || strings.Contains(code, "ERROR") || strings.Contains(code, "FAIL") {
		return ErrContract
	}
	// The published wrapper uses statusCodeValue=0 / "100 CONTINUE". These
	// placeholder fields are not a deletion acknowledgement; exact GET decides.
	// The generic deletion wrapper is not an ownership acknowledgement. Require the
	// operation-specific GET's documented 404 before discarding already-owned state.
	_, e = c.Role(ctx, old.Name)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	return errors.New("AppViz role still exists after deletion; state retained")
}
