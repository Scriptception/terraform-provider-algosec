// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
)

// Device is an allowlist: device passwords and secret-bearing fields are never retained.
type Device struct {
	Name            string `json:"name"`
	DisplayName     string `json:"display_name"`
	OriginalName    string `json:"original_name"`
	Brand           string `json:"brand"`
	BrandName       string `json:"brand_name"`
	HostName        string `json:"host_name"`
	NodeType        string `json:"nodeType"`
	Collector       string `json:"collector"`
	BaselineProfile string `json:"baseline_profile"`
	Monitoring      string `json:"monitoring"`
}

func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var out []Device
	if err := c.do(ctx, "GET", api+"/devices", nil, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, ErrContract
	}
	seen := map[string]bool{}
	for _, v := range out {
		if v.Name == "" || seen[v.Name] {
			return nil, ErrContract
		}
		seen[v.Name] = true
	}
	return out, nil
}

// Device queries the documented complete admin inventory, avoiding ambiguous detail 400/404 responses.
func (c *Client) Device(ctx context.Context, name string) (Device, error) {
	all, err := c.Devices(ctx)
	if err != nil {
		return Device{}, err
	}
	for _, v := range all {
		if v.Name == name {
			return v, nil
		}
	}
	return Device{}, ErrNotFound
}
