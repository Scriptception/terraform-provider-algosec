// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
)

const aceThreatPath = "/prevasio/api/v1/threat-management/details"

type ACEThreatEntry struct{ ThreatType, ListType, Destination, Description, Severity string }

func ValidateACEThreatType(v string) error {
	if !slices.Contains([]string{"ip-addresses", "domains", "open-ports", "countries", "cve", "malware-names"}, v) {
		return errors.New("invalid threat_type")
	}
	return nil
}
func ValidateACEListType(v string) error {
	if v != "block-list" && v != "allow-list" {
		return errors.New("list_type must be block-list or allow-list")
	}
	return nil
}
func ValidateACEThreat(v ACEThreatEntry) error {
	if e := ValidateACEThreatType(v.ThreatType); e != nil {
		return e
	}
	if e := ValidateACEListType(v.ListType); e != nil {
		return e
	}
	if ValidateAppVizName(v.Destination) != nil {
		return errors.New("destination must be nonempty UTF-8 without controls; bulk deletion is forbidden")
	}
	if v.ListType == "block-list" && !slices.Contains([]string{"low", "medium", "high", "critical"}, v.Severity) {
		return errors.New("block-list requires severity low, medium, high or critical")
	}
	if v.ListType == "allow-list" && v.Severity != "" {
		return errors.New("allow-list must omit severity")
	}
	return nil
}
func (c *ACEClient) ThreatEntry(ctx context.Context, threat, list, destination string) (*ACEThreatEntry, error) {
	if e := ValidateACEThreatType(threat); e != nil {
		return nil, e
	}
	if e := ValidateACEListType(list); e != nil {
		return nil, e
	}
	if ValidateAppVizName(destination) != nil {
		return nil, errors.New("nonempty exact destination required")
	}
	seen := map[string]bool{}
	total, items, limit := -1, -1, -1
	var found *ACEThreatEntry
	for page := 1; page <= 1000; page++ {
		raw, e := c.request(ctx, "GET", aceThreatPath, url.Values{"threatType": {threat}, "listType": {list}, "page": {strconv.Itoa(page)}, "limit": {"1000"}}, nil)
		if e != nil {
			return nil, e
		}
		var w struct {
			Data []struct {
				Destination *string `json:"destination"`
				Description *string `json:"description"`
				Severity    *string `json:"severity,omitempty"`
			} `json:"data"`
			Page *struct {
				Current *int `json:"current"`
				Limit   *int `json:"limit"`
				Total   *int `json:"total"`
				Items   *int `json:"totalItems"`
			} `json:"page"`
		}
		if aceDecode(raw, &w) != nil || w.Data == nil || w.Page == nil || w.Page.Current == nil || w.Page.Limit == nil || w.Page.Total == nil || w.Page.Items == nil {
			return nil, ErrContract
		}
		p := w.Page
		if *p.Current != page || *p.Limit < 1 || *p.Limit > 1000 || *p.Total < 0 || *p.Total > 1000 || *p.Items < 0 {
			return nil, ErrContract
		}
		if page == 1 {
			total = *p.Total
			items = *p.Items
			limit = *p.Limit
		} else if total != *p.Total || items != *p.Items || limit != *p.Limit {
			return nil, ErrContract
		}
		if len(w.Data) > limit || (page < total && len(w.Data) != limit) || (items > 0 && total != (items+limit-1)/limit) || (items == 0 && (total > 1 || len(w.Data) != 0)) {
			return nil, ErrContract
		}
		for _, d := range w.Data {
			if d.Destination == nil || d.Description == nil || seen[*d.Destination] || (list == "block-list" && d.Severity == nil) || (list == "allow-list" && d.Severity != nil) {
				return nil, ErrContract
			}
			v := ACEThreatEntry{ThreatType: threat, ListType: list, Destination: *d.Destination, Description: *d.Description}
			if d.Severity != nil {
				v.Severity = *d.Severity
			}
			if ValidateACEThreat(v) != nil {
				return nil, ErrContract
			}
			seen[v.Destination] = true
			if v.Destination == destination {
				found = &v
			}
		}
		if page >= total {
			if len(seen) != items {
				return nil, ErrContract
			}
			if found == nil {
				return nil, ErrNotFound
			}
			return found, nil
		}
	}
	return nil, ErrContract
}
func (c *ACEClient) CreateThreatEntry(ctx context.Context, v ACEThreatEntry) error {
	if e := ValidateACEThreat(v); e != nil {
		return e
	}
	if _, e := c.ThreatEntry(ctx, v.ThreatType, v.ListType, v.Destination); !errors.Is(e, ErrNotFound) {
		if e != nil {
			return e
		}
		return errors.New("threat entry exists; import it explicitly")
	}
	in := struct {
		Destination string `json:"destination"`
		Description string `json:"description"`
		Severity    string `json:"severity,omitempty"`
	}{v.Destination, v.Description, v.Severity}
	raw, e := c.request(ctx, "POST", aceThreatPath, url.Values{"threatType": {v.ThreatType}, "listType": {v.ListType}}, in)
	if e != nil {
		return e
	}
	return aceAck(raw, fmt.Sprintf("Successfully added %s entry to %s for threat - %s.", v.Destination, v.ListType, v.ThreatType))
}
func (c *ACEClient) DeleteThreatEntry(ctx context.Context, v ACEThreatEntry) error {
	if e := ValidateACEThreat(v); e != nil {
		return e
	}
	current, e := c.ThreatEntry(ctx, v.ThreatType, v.ListType, v.Destination)
	if errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	if *current != v {
		return errors.New("threat entry changed since refresh; refresh before deletion")
	}
	raw, e := c.request(ctx, "DELETE", aceThreatPath, url.Values{"threatType": {v.ThreatType}, "listType": {v.ListType}, "destination": {v.Destination}}, nil)
	if e != nil {
		return e
	}
	if e = aceAck(raw, fmt.Sprintf("Successfully deleted %s from the %s of threat type %s.", v.Destination, v.ListType, v.ThreatType)); e != nil {
		return e
	}
	if _, e = c.ThreatEntry(ctx, v.ThreatType, v.ListType, v.Destination); errors.Is(e, ErrNotFound) {
		return nil
	}
	if e != nil {
		return e
	}
	return errors.New("threat deletion unconfirmed; state retained")
}
