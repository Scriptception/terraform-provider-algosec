// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
)

// Some security-zone pages document both a bare array and a status/data envelope.
func decodeList[T any](raw json.RawMessage) ([]T, error) {
	var out []T
	if len(raw) > 0 && raw[0] == '[' {
		if json.Unmarshal(raw, &out) != nil || out == nil {
			return nil, ErrContract
		}
		return out, nil
	}
	var wrap struct {
		Data   *[]T            `json:"data"`
		Status json.RawMessage `json:"status"`
	}
	if json.Unmarshal(raw, &wrap) != nil || wrap.Data == nil || (string(wrap.Status) != "true" && string(wrap.Status) != "\"true\"") {
		return nil, ErrContract
	}
	return *wrap.Data, nil
}
func (c *Client) RiskProfileFiles(ctx context.Context) ([]string, error) {
	var raw json.RawMessage
	if err := c.do(ctx, "GET", api+"/security_zones/get_profiles_list", nil, nil, &raw); err != nil {
		return nil, err
	}
	return decodeList[string](raw)
}
func (c *Client) RiskProfiles(ctx context.Context) ([]string, error) {
	var out []string
	if err := c.do(ctx, "GET", api+"/risks/profiles", nil, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, ErrContract
	}
	return out, nil
}

type SecurityZone struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

func (c *Client) SecurityZones(ctx context.Context, file string) ([]SecurityZone, error) {
	p, err := Segment(file)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err = c.do(ctx, "GET", api+"/security_zones/"+p+"/get_zones", nil, nil, &raw); err != nil {
		return nil, err
	}
	out, err := decodeList[SecurityZone](raw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, v := range out {
		if v.Name == "" || v.Addresses == nil || seen[v.Name] {
			return nil, ErrContract
		}
		seen[v.Name] = true
	}
	return out, nil
}

type DeviceZone struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
	IPAddress  string   `json:"ipaddress"`
	DeviceName string   `json:"deviceName"`
}

func (c *Client) DeviceZones(ctx context.Context, device string) ([]DeviceZone, error) {
	var out struct {
		Zones      []DeviceZone `json:"deviceZones"`
		Additional []string     `json:"additionalInformation"`
	}
	if err := c.do(ctx, "GET", api+"/deviceZones", url.Values{"device": {device}}, nil, &out); err != nil {
		return nil, err
	}
	if out.Zones == nil || len(out.Additional) > 0 {
		return nil, ErrContract
	}
	for _, v := range out.Zones {
		if v.Name == "" || v.DeviceName == "" || v.Interfaces == nil {
			return nil, ErrContract
		}
	}
	return out.Zones, nil
}

type NetworkObject struct {
	ID            int64  `json:"id"`
	CanonizedName string `json:"canonizedName"`
	OriginalName  string `json:"originalName"`
	IPAddress     string `json:"ipaddress"`
	IPType        string `json:"ipType"`
	Members       string `json:"members"`
	Zone          string `json:"zone"`
}
type TrustedTraffic struct {
	ID                  int64  `json:"trusted_traffic_id"`
	Source              string `json:"source"`
	Destination         string `json:"destination"`
	Service             string `json:"service"`
	Comment             string `json:"comment"`
	ExpirationDate      *int64 `json:"expirationDate"`
	DisplayTrafficLevel string `json:"display_traffic_level"`
	TrustFutureChanges  *bool  `json:"trust_future_host_group_changes"`
}

// page uses pointer metadata to reject absent/null pagination fields instead of silently truncating.
type page[T any] struct {
	Content       []T   `json:"content"`
	Last          *bool `json:"last"`
	Number        *int  `json:"number"`
	TotalElements *int  `json:"totalElements"`
	TotalPages    *int  `json:"totalPages"`
}

func paginate[T any](ctx context.Context, c *Client, path string, q url.Values, pageKey, sizeKey string, id func(T) int64) ([]T, error) {
	out := []T{}
	seen := map[int64]bool{}
	total := -1
	for n := 0; n < 1000; n++ {
		q.Set(pageKey, strconv.Itoa(n))
		q.Set(sizeKey, "100")
		var p page[T]
		if err := c.do(ctx, "GET", path, q, nil, &p); err != nil {
			return nil, err
		}
		if p.Content == nil || p.Last == nil || p.Number == nil || *p.Number != n || p.TotalElements == nil || p.TotalPages == nil || *p.TotalElements < 0 || *p.TotalPages < 0 {
			return nil, ErrContract
		}
		if total < 0 {
			total = *p.TotalElements
		}
		if total != *p.TotalElements {
			return nil, ErrContract
		}
		for _, item := range p.Content {
			k := id(item)
			if k <= 0 || seen[k] {
				return nil, ErrContract
			}
			seen[k] = true
			out = append(out, item)
		}
		if *p.Last {
			if len(out) != total || (*p.TotalPages != n+1 && !(n == 0 && total == 0 && *p.TotalPages == 0)) {
				return nil, ErrContract
			}
			sort.Slice(out, func(i, j int) bool { return id(out[i]) < id(out[j]) })
			return out, nil
		}
		if len(p.Content) == 0 || n+1 >= *p.TotalPages {
			return nil, ErrContract
		}
	}
	return nil, ErrContract
}
func (c *Client) NetworkObjects(ctx context.Context, device, query string) ([]NetworkObject, error) {
	return paginate(ctx, c, api+"/networkObject/search/findByOriginalNameContaining", url.Values{"deviceName": {device}, "query": {query}, "direction": {"ASC"}, "sort": {"id"}, "onlyFireflowSupportedDevices": {"false"}}, "page", "size", func(v NetworkObject) int64 { return v.ID })
}
func (c *Client) TrustedTraffic(ctx context.Context, device string) ([]TrustedTraffic, error) {
	p, err := Segment(device)
	if err != nil {
		return nil, err
	}
	return paginate(ctx, c, api+"/trustedTraffic/firewalls/"+p, url.Values{}, "pageNo", "pageSize", func(v TrustedTraffic) int64 { return v.ID })
}
