// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Tag is the selected A33.30 CentralTagDTO contract. Relations are never written.
type Tag struct {
	ID        int64         `json:"id"`
	Name      string        `json:"name"`
	Scope     string        `json:"scope"`
	Type      string        `json:"type"`
	Relations []TagRelation `json:"relations"`
}

// Scope may be omitted (the documented empty default), but explicit null is invalid.
func (t *Tag) UnmarshalJSON(raw []byte) error {
	type plain Tag
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return ErrContract
	}
	for key, value := range fields {
		switch key {
		case "id", "name", "scope", "type":
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return ErrContract
			}
		case "relations":
		default:
			return ErrContract
		}
	}
	var out plain
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&out) != nil {
		return ErrContract
	}
	*t = Tag(out)
	return nil
}

type TagRelation struct {
	Hostgroup      string `json:"hostgroup"`
	DeviceDataID   int64  `json:"deviceDataId"`
	TagID          int64  `json:"tagId"`
	DeviceTreeName string `json:"deviceTreeName,omitempty"`
}
type TagClient struct {
	c       *Client
	enabled bool
}

func NewTagClient(c *Client, enabled bool) *TagClient { return &TagClient{c: c, enabled: enabled} }
func ValidateTagInput(name, scope string) error {
	if name == "" || strings.TrimSpace(name) != name || strings.TrimSpace(scope) != scope || !utf8.ValidString(name) || !utf8.ValidString(scope) {
		return errors.New("tag name must be nonempty; name and scope must be canonical UTF-8 without surrounding whitespace")
	}
	for _, v := range []string{name, scope} {
		for _, r := range v {
			if r < 32 || r == 127 {
				return errors.New("tag name and scope cannot contain control characters")
			}
		}
	}
	return nil
}
func validTag(v Tag) bool {
	return v.ID > 0 && ValidateTagInput(v.Name, v.Scope) == nil && (v.Type == "ALGOSEC" || v.Type == "DEVICE")
}
func tagID(id int64) (string, error) {
	if id <= 0 {
		return "", errors.New("tag ID must be a positive int64")
	}
	return strconv.FormatInt(id, 10), nil
}

// request deliberately selects exact 200 and operation-specific empty acknowledgements.
// It does not weaken JSON handling for any existing AFA operation.
func (t *TagClient) request(ctx context.Context, method, path string, q url.Values, empty bool, out any) error {
	if t == nil || !t.enabled {
		return errors.New("A33.30 vendor EA tags require experimental_tags=true")
	}
	if t.c == nil || t.c.base == "" {
		return errors.New("tags require AFA URL and authentication")
	}
	if method != "GET" && t.c.readOnly {
		return errors.New("provider read_only is enabled; mutation refused")
	}
	if err := t.c.login(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, t.c.base+path+"?"+q.Encode(), nil)
	if err != nil {
		return errors.New("cannot construct tag request")
	}
	t.c.authMu.Lock()
	session := t.c.session
	t.c.authMu.Unlock()
	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: session})
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "terraform-provider-algosec")
	req.GetBody = nil
	res, err := t.c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("tag transport request failed; check connectivity, timeout and TLS trust")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return &HTTPError{res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return errors.New("cannot read tag response")
	}
	if len(raw) > maxBody {
		return ErrContract
	}
	if empty {
		if len(raw) != 0 {
			return ErrContract
		}
		return nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || !json.Valid(raw) {
		return ErrContract
	}
	if trustedJSON(raw) != nil {
		return ErrContract
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return ErrContract
	}
	return nil
}

// List selects short-page termination for the documented zero-based paginated array.
// No totals are documented. Full administrator visibility and exclusive writers are required.
func (t *TagClient) List(ctx context.Context) ([]Tag, error) {
	all := []Tag{}
	seen := map[int64]bool{}
	for page := 0; page < 1000; page++ {
		var part []Tag
		if err := t.request(ctx, "GET", api+"/tags", url.Values{"page": {strconv.Itoa(page)}, "pageSize": {"100"}}, false, &part); err != nil {
			return nil, err
		}
		if part == nil || len(part) > 100 {
			return nil, ErrContract
		}
		for _, v := range part {
			if !validTag(v) || seen[v.ID] {
				return nil, ErrContract
			}
			seen[v.ID] = true
			all = append(all, v)
		}
		if len(part) < 100 {
			return all, nil
		}
	}
	return nil, errors.New("tag inventory exceeds 1000-page bound; absence cannot be established")
}
func (t *TagClient) Get(ctx context.Context, id int64) (Tag, error) {
	if _, err := tagID(id); err != nil {
		return Tag{}, err
	}
	all, err := t.List(ctx)
	if err != nil {
		return Tag{}, err
	}
	for _, v := range all {
		if v.ID == id {
			if v.Type != "ALGOSEC" {
				return Tag{}, errors.New("only ALGOSEC tags can be managed")
			}
			return v, nil
		}
	}
	return Tag{}, ErrNotFound
}
func (t *TagClient) Create(ctx context.Context, name, scope string) (Tag, error) {
	if err := ValidateTagInput(name, scope); err != nil {
		return Tag{}, err
	}
	var out Tag
	if err := t.request(ctx, "POST", api+"/tags", url.Values{"name": {name}, "scope": {scope}}, false, &out); err != nil {
		return Tag{}, err
	}
	if !validTag(out) || out.Type != "ALGOSEC" || out.Name != name || out.Scope != scope {
		return Tag{}, ErrContract
	}
	return out, nil
}
func (t *TagClient) Rename(ctx context.Context, id int64, name string) error {
	part, err := tagID(id)
	if err != nil {
		return err
	}
	if err = ValidateTagInput(name, ""); err != nil {
		return err
	}
	return t.request(ctx, "PUT", api+"/tags/"+part+"/name", url.Values{"name": {name}}, true, nil)
}
func (t *TagClient) Associations(ctx context.Context, tag Tag) ([]TagRelation, error) {
	if !validTag(tag) || tag.Type != "ALGOSEC" {
		return nil, ErrContract
	}
	var out []Tag
	if err := t.request(ctx, "GET", api+"/tags/details", url.Values{"name": {tag.Name}, "scope": {tag.Scope}, "includeAssociations": {"true"}}, false, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, ErrContract
	}
	var match *Tag
	seen := map[int64]bool{}
	for i, v := range out {
		if !validTag(v) || seen[v.ID] || v.Name != tag.Name || v.Scope != tag.Scope {
			return nil, ErrContract
		}
		seen[v.ID] = true
		if v.ID == tag.ID {
			match = &out[i]
		}
	}
	if match == nil || match.Type != tag.Type || match.Relations == nil {
		return nil, ErrContract
	}
	tuples := map[TagRelation]bool{}
	for _, v := range match.Relations {
		if v.TagID != tag.ID || v.DeviceDataID <= 0 || strings.TrimSpace(v.Hostgroup) == "" || tuples[v] {
			return nil, ErrContract
		}
		tuples[v] = true
	}
	return match.Relations, nil
}
func (t *TagClient) Delete(ctx context.Context, id int64) error {
	part, err := tagID(id)
	if err != nil {
		return err
	}
	tag, err := t.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	relations, err := t.Associations(ctx, tag)
	if err != nil {
		return err
	}
	if len(relations) != 0 {
		return errors.New("tag has hostgroup associations; remove separately owned bindings before deleting the tag")
	}
	if err := t.request(ctx, "DELETE", api+"/tags/"+part, nil, true, nil); err != nil {
		return err
	}
	_, err = t.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("deleted tag remains in complete inventory")
}
