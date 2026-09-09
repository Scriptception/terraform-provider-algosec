// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// TrustedRule manages trust metadata only, never the underlying firewall rule.
type TrustedRule struct {
	RuleID         string `json:"ruleId"`
	Comment        string `json:"comment"`
	ExpirationDate string `json:"expirationDate"`
}
type trustedDevice struct {
	DeviceName        string        `json:"deviceName"`
	DeviceDisplayName string        `json:"deviceDisplayName"`
	DeviceID          string        `json:"deviceId"`
	TrustedRules      []TrustedRule `json:"trustedRules"`
}
type trustedAcknowledgement struct {
	TrustedRuleIDs []string          `json:"trustedRuleIds"`
	FailedRuleIDs  []string          `json:"failedRuleIds"`
	FailureReasons map[string]string `json:"failureReasons"`
}

func (a trustedAcknowledgement) confirms(id string) bool {
	return len(a.TrustedRuleIDs) == 1 && a.TrustedRuleIDs[0] == id && len(a.FailedRuleIDs) == 0 && len(a.FailureReasons) == 0
}
func ValidateTrustedIdentity(device, rule string) error {
	if !utf8.ValidString(device) || !utf8.ValidString(rule) || strings.TrimSpace(device) == "" || strings.TrimSpace(rule) == "" || device == "ALL_FIREWALLS" || strings.Contains(device, ",") {
		return errors.New("device and rule must be nonblank UTF-8 identifiers; ALL_FIREWALLS and comma-delimited device names are unsupported")
	}
	for _, s := range []string{device, rule} {
		for _, r := range s {
			if r < 32 || r == 127 {
				return errors.New("identifiers cannot contain control characters")
			}
		}
	}
	return nil
}
func ValidateTrustedDate(s string, future bool) error {
	if s == "" {
		return nil
	}
	d, e := time.Parse("2006-01-02", s)
	if e != nil || d.Format("2006-01-02") != s {
		return errors.New("expiration_date must be a valid YYYY-MM-DD date")
	}
	if future && !d.After(time.Now().UTC()) {
		return errors.New("expiration_date must be a future UTC date; extend or remove an expired date before recreating")
	}
	return nil
}
func (c *Client) TrustedRulesEnabled() error {
	if c == nil || !c.experimentalTrustedRules {
		return errors.New("A33.20 trusted rules require experimental_trusted_rules=true; public-contract implementation has no live acceptance")
	}
	return nil
}
func (c *Client) TrustedRule(ctx context.Context, device, rule string) (*TrustedRule, error) {
	if e := c.TrustedRulesEnabled(); e != nil {
		return nil, e
	}
	if e := ValidateTrustedIdentity(device, rule); e != nil {
		return nil, e
	}
	var out []trustedDevice
	if e := c.do(ctx, "GET", api+"/trusted-rules/rules", url.Values{"deviceNames": {device}}, nil, &out); e != nil {
		return nil, e
	}
	// An omitted device cannot prove visibility or absence. Require its explicit full list.
	if len(out) != 1 || out[0].DeviceName != device || out[0].DeviceID == "" || out[0].DeviceDisplayName == "" || out[0].TrustedRules == nil {
		return nil, ErrContract
	}
	seen := map[string]bool{}
	var found *TrustedRule
	for _, r := range out[0].TrustedRules {
		if ValidateTrustedIdentity(device, r.RuleID) != nil || seen[r.RuleID] || ValidateTrustedDate(r.ExpirationDate, false) != nil {
			return nil, ErrContract
		}
		seen[r.RuleID] = true
		if r.RuleID == rule {
			copy := r
			found = &copy
		}
	}
	if found == nil {
		return nil, ErrNotFound
	}
	return found, nil
}
func (c *Client) CreateTrustedRule(ctx context.Context, device string, rule TrustedRule, accepted func()) (*TrustedRule, error) {
	if e := c.TrustedRulesEnabled(); e != nil {
		return nil, e
	}
	if c.readOnly {
		return nil, errors.New("provider read_only is enabled; mutation refused")
	}
	if e := ValidateTrustedIdentity(device, rule.RuleID); e != nil {
		return nil, e
	}
	if e := ValidateTrustedDate(rule.ExpirationDate, true); e != nil {
		return nil, e
	}
	_, e := c.TrustedRule(ctx, device, rule.RuleID)
	if e == nil {
		return nil, errors.New("trusted assignment already exists; explicitly import it")
	}
	if !errors.Is(e, ErrNotFound) {
		return nil, e
	}
	type entry struct {
		ID             string `json:"id"`
		Comment        string `json:"comment,omitempty"`
		ExpirationDate string `json:"expirationDate,omitempty"`
	}
	in := struct {
		DeviceName string  `json:"deviceName"`
		Rules      []entry `json:"rules"`
	}{device, []entry{{rule.RuleID, rule.Comment, rule.ExpirationDate}}}
	var ack trustedAcknowledgement
	e = c.do(ctx, "POST", api+"/trusted-rules/rules", nil, in, &ack)
	if e == nil && !ack.confirms(rule.RuleID) {
		e = ErrContract
	}
	if e != nil {
		return nil, errors.Join(e, errors.New("create unconfirmed; no ownership recorded. Inspect remote assignment before import or retry"))
	}
	if accepted != nil {
		accepted()
	}
	got, e := c.TrustedRule(ctx, device, rule.RuleID)
	if e != nil {
		return nil, e
	}
	if *got != rule {
		return got, errors.New("trusted assignment readback differs from plan; confirmed identity retained")
	}
	return got, nil
}

func (c *Client) DeleteTrustedRule(ctx context.Context, device string, prior TrustedRule) error {
	if e := c.TrustedRulesEnabled(); e != nil {
		return e
	}
	if c.readOnly {
		return errors.New("provider read_only is enabled; mutation refused")
	}
	got, e := c.TrustedRule(ctx, device, prior.RuleID)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if *got != prior {
		return errors.New("concurrent trust metadata change; refresh and plan before deleting")
	}
	in := struct {
		DeviceName string   `json:"deviceName"`
		RuleIDs    []string `json:"ruleIds"`
	}{device, []string{prior.RuleID}}
	var ack trustedAcknowledgement
	if e = c.do(ctx, "DELETE", api+"/trusted-rules/rules", nil, in, &ack); e != nil {
		return e
	}
	if !ack.confirms(prior.RuleID) {
		return ErrContract
	}
	_, e = c.TrustedRule(ctx, device, prior.RuleID)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	return errors.New("trusted assignment still present after acknowledged deletion; state retained")
}

// Presence checks distinguish omitted metadata from explicitly empty/null metadata.
func (r *TrustedRule) UnmarshalJSON(b []byte) error {
	if e := trustedJSON(b); e != nil {
		return e
	}
	type plain TrustedRule
	var v plain
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || json.Unmarshal(b, &v) != nil {
		return ErrContract
	}
	for key := range fields {
		switch key {
		case "ruleId", "comment", "expirationDate", "source", "destination", "service":
		default:
			return ErrContract
		}
	}
	if fields["ruleId"] == nil || fields["comment"] == nil || fields["expirationDate"] == nil || fields["error"] != nil {
		return ErrContract
	}
	*r = TrustedRule(v)
	return nil
}
func (d *trustedDevice) UnmarshalJSON(b []byte) error {
	if e := trustedJSON(b); e != nil {
		return e
	}
	type plain trustedDevice
	var v plain
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || json.Unmarshal(b, &v) != nil || fields["error"] != nil {
		return ErrContract
	}
	for key := range fields {
		switch key {
		case "deviceName", "deviceDisplayName", "deviceId", "trustedRules":
		default:
			return ErrContract
		}
	}
	*d = trustedDevice(v)
	return nil
}

// Reject duplicate object keys rather than allowing encoding/json's last-key-wins
// behavior to turn a conflicting failure response into positive ownership.
func trustedJSON(b []byte) error {
	return jsonUniqueKeys(b, func(int) bool { return true })
}

func jsonUniqueKeys(b []byte, fold func(int) bool) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	var value func(int) error
	value = func(depth int) error {
		token, e := dec.Token()
		if e != nil {
			return ErrContract
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, e := dec.Token()
				if e != nil {
					return ErrContract
				}
				k, ok := key.(string)
				if fold(depth) {
					k = strings.ToLower(k)
				}
				if !ok || seen[k] {
					return ErrContract
				}
				seen[k] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for dec.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return ErrContract
		}
		_, e = dec.Token()
		return e
	}
	return value(0)
}
func (a *trustedAcknowledgement) UnmarshalJSON(b []byte) error {
	if e := trustedJSON(b); e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return ErrContract
	}
	for key := range fields {
		switch strings.ToLower(key) {
		case "trustedruleids", "failedruleids", "failurereasons":
		default:
			return ErrContract
		}
	}
	type plain trustedAcknowledgement
	var v plain
	if e := json.Unmarshal(b, &v); e != nil {
		return ErrContract
	}
	*a = trustedAcknowledgement(v)
	return nil
}
