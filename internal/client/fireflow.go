// SPDX-License-Identifier: MPL-2.0
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const fireFlowRolePath = "/FireFlow/api/roles/"

// FireFlowClient exclusively uses externally supplied FireFlow_Session cookies.
// It never logs in, follows redirects, refreshes sessions or replays writes.
type FireFlowClient struct {
	base, session     string
	http              *http.Client
	readOnly, enabled bool
}

func NewFireFlowClient(origin, session string, timeout time.Duration, readOnly, enabled bool) (*FireFlowClient, error) {
	if err := ValidateURL(origin); err != nil {
		return nil, err
	}
	if session == "" {
		return nil, errors.New("set an externally supplied FireFlow_Session value")
	}
	for _, b := range []byte(session) {
		if b < 33 || b > 126 || strings.ContainsRune("\";,\\", rune(b)) {
			return nil, errors.New("invalid FireFlow session cookie format")
		}
	}
	if timeout < time.Second || timeout > 300*time.Second {
		return nil, errors.New("timeout must be between 1 and 300 seconds")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = timeout
	return &FireFlowClient{base: strings.TrimRight(origin, "/"), session: session, http: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, readOnly: readOnly, enabled: enabled}, nil
}

type fireFlowEnvelope struct {
	Status   *string           `json:"status"`
	Messages []json.RawMessage `json:"messages"`
	Data     json.RawMessage   `json:"data"`
}

func (c *FireFlowClient) request(ctx context.Context, method, path string, q url.Values, in any) (json.RawMessage, error) {
	if c == nil || !c.enabled {
		return nil, errors.New("FireFlow bindings require experimental_fireflow_bindings=true and separate FireFlow URL/session")
	}
	if method != "GET" && c.readOnly {
		return nil, errors.New("provider read_only is enabled; mutation refused")
	}
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return nil, ErrContract
		}
		if len(body) > maxBody {
			return nil, errors.New("API request exceeds 8 MiB limit")
		}
	}
	target := c.base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot construct FireFlow request")
	}
	if method != "GET" {
		req.GetBody = nil
	}
	req.AddCookie(&http.Cookie{Name: "FireFlow_Session", Value: c.session})
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "terraform-provider-algosec")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("FireFlow transport request failed; check connectivity, timeout and TLS trust")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, &HTTPError{res.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, errors.New("cannot read FireFlow response")
	}
	if len(raw) > maxBody || !json.Valid(raw) || trustedJSON(raw) != nil || jsonFieldCollision(raw) != nil {
		return nil, ErrContract
	}
	var out fireFlowEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&out) != nil || out.Status == nil || *out.Status != "Success" || out.Messages == nil || len(out.Messages) != 0 || len(out.Data) == 0 {
		return nil, ErrContract
	}
	return out.Data, nil
}
func fireFlowID(id int64) (string, error) {
	if id <= 0 || id > math.MaxInt32 {
		return "", errors.New("FireFlow role/principal ID must be a positive int32")
	}
	return strconv.FormatInt(id, 10), nil
}

type FireFlowMemberRef struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}
type FireFlowMember struct {
	FireFlowMemberRef
	Name   string
	Direct bool
}
type FireFlowPermissionRef struct {
	Name       string `json:"permissionName"`
	ObjectType string `json:"objectType"`
	ObjectID   int64  `json:"objectId"`
}
type FireFlowPermission struct {
	FireFlowPermissionRef
	Direct, Inherited bool
}

func ValidateFireFlowMember(roleID int64, member FireFlowMemberRef) error {
	if _, err := fireFlowID(roleID); err != nil {
		return err
	}
	if _, err := fireFlowID(member.ID); err != nil {
		return err
	}
	if member.Type != "User" && member.Type != "Role" {
		return errors.New("member_type must be User or Role")
	}
	if member.Type == "Role" && member.ID == roleID {
		return errors.New("a role cannot be a member of itself")
	}
	return nil
}
func ValidateFireFlowPermission(roleID int64, p FireFlowPermissionRef) error {
	if _, err := fireFlowID(roleID); err != nil {
		return err
	}
	if err := ValidateAppVizName(p.Name); err != nil {
		return errors.New("permission_name must be nonblank UTF-8 without control characters")
	}
	switch p.ObjectType {
	case "System":
		if p.ObjectID != 0 {
			return errors.New("System permission object_id must be 0")
		}
	case "CustomField", "RequestTemplate":
		if p.ObjectID <= 0 || p.ObjectID > math.MaxInt32 {
			return errors.New("CustomField/RequestTemplate object_id must be a positive int32")
		}
	default:
		return errors.New("object_type must be System, CustomField or RequestTemplate")
	}
	return nil
}
func (c *FireFlowClient) Members(ctx context.Context, roleID int64) ([]FireFlowMember, error) {
	part, err := fireFlowID(roleID)
	if err != nil {
		return nil, err
	}
	raw, err := c.request(ctx, "GET", fireFlowRolePath+part+"/members", url.Values{"fetchIndirect": {"false"}}, nil)
	if err != nil {
		return nil, err
	}
	var wire []struct {
		ID     *int64  `json:"id"`
		Name   *string `json:"name"`
		Type   *string `json:"type"`
		Direct *bool   `json:"isDirectMember"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil || wire == nil {
		return nil, ErrContract
	}
	out := []FireFlowMember{}
	seen := map[FireFlowMemberRef]bool{}
	for _, v := range wire {
		if v.ID == nil || v.Name == nil || v.Type == nil || v.Direct == nil || ValidateAppVizName(*v.Name) != nil {
			return nil, ErrContract
		}
		ref := FireFlowMemberRef{ID: *v.ID, Type: *v.Type}
		if ValidateFireFlowMember(roleID, ref) != nil || seen[ref] {
			return nil, ErrContract
		}
		seen[ref] = true
		out = append(out, FireFlowMember{FireFlowMemberRef: ref, Name: *v.Name, Direct: *v.Direct})
	}
	return out, nil
}
func (c *FireFlowClient) Permissions(ctx context.Context, roleID int64) ([]FireFlowPermission, error) {
	part, err := fireFlowID(roleID)
	if err != nil {
		return nil, err
	}
	raw, err := c.request(ctx, "GET", fireFlowRolePath+part+"/permissions", nil, nil)
	if err != nil {
		return nil, err
	}
	type permissionWire struct {
		Name       *string `json:"permissionName"`
		ObjectType *string `json:"objectType"`
		ObjectID   *int64  `json:"objectId"`
		Direct     *bool   `json:"direct"`
		Inherited  *bool   `json:"inherited"`
	}
	var wire struct {
		System          []permissionWire `json:"system"`
		CustomField     []permissionWire `json:"customField"`
		RequestTemplate []permissionWire `json:"requestTemplate"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil || wire.System == nil || wire.CustomField == nil || wire.RequestTemplate == nil {
		return nil, ErrContract
	}
	out := []FireFlowPermission{}
	seen := map[FireFlowPermissionRef]bool{}
	for _, group := range []struct {
		kind string
		rows []permissionWire
	}{{"System", wire.System}, {"CustomField", wire.CustomField}, {"RequestTemplate", wire.RequestTemplate}} {
		for _, v := range group.rows {
			if v.Name == nil || v.ObjectType == nil || v.ObjectID == nil || v.Direct == nil || v.Inherited == nil || *v.ObjectType != group.kind {
				return nil, ErrContract
			}
			ref := FireFlowPermissionRef{Name: *v.Name, ObjectType: *v.ObjectType, ObjectID: *v.ObjectID}
			if ValidateFireFlowPermission(roleID, ref) != nil || seen[ref] {
				return nil, ErrContract
			}
			seen[ref] = true
			out = append(out, FireFlowPermission{FireFlowPermissionRef: ref, Direct: *v.Direct, Inherited: *v.Inherited})
		}
	}
	return out, nil
}
func (c *FireFlowClient) ChangeMember(ctx context.Context, roleID int64, member FireFlowMemberRef, add bool) error {
	if err := ValidateFireFlowMember(roleID, member); err != nil {
		return err
	}
	part, _ := fireFlowID(roleID)
	in := struct {
		Add    []FireFlowMemberRef `json:"addMembers"`
		Remove []FireFlowMemberRef `json:"removeMembers"`
	}{Add: []FireFlowMemberRef{}, Remove: []FireFlowMemberRef{}}
	if add {
		in.Add = append(in.Add, member)
	} else {
		in.Remove = append(in.Remove, member)
	}
	raw, err := c.request(ctx, "POST", fireFlowRolePath+part+"/members", nil, in)
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrContract
	}
	return nil
}
func fireFlowPermissionPayload(p FireFlowPermissionRef, add bool) any {
	in := struct {
		Add    []FireFlowPermissionRef `json:"addPermissions"`
		Remove []FireFlowPermissionRef `json:"removePermissions"`
	}{Add: []FireFlowPermissionRef{}, Remove: []FireFlowPermissionRef{}}
	if add {
		in.Add = append(in.Add, p)
	} else {
		in.Remove = append(in.Remove, p)
	}
	return in
}
func ValidateFireFlowPermissionSize(p FireFlowPermissionRef) error {
	raw, err := json.Marshal(fireFlowPermissionPayload(p, true))
	if err != nil {
		return ErrContract
	}
	if len(raw) > maxBody {
		return errors.New("API request exceeds 8 MiB limit")
	}
	return nil
}
func (c *FireFlowClient) ChangePermission(ctx context.Context, roleID int64, p FireFlowPermissionRef, add bool) error {
	if err := ValidateFireFlowPermission(roleID, p); err != nil {
		return err
	}
	part, _ := fireFlowID(roleID)
	in := fireFlowPermissionPayload(p, add)
	raw, err := c.request(ctx, "POST", fireFlowRolePath+part+"/permissions", nil, in)
	if err != nil {
		return err
	}
	var data map[string]json.RawMessage
	if json.Unmarshal(raw, &data) != nil || data == nil || len(data) != 0 {
		return ErrContract
	}
	return nil
}
