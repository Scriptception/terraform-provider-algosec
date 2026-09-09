// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

// URLIPClient owns one assignment under an existing category and URL, A33.20+.
type URLIPClient struct {
	c       *Client
	enabled bool
}

func NewURLIPClient(c *Client, enabled bool) *URLIPClient {
	return &URLIPClient{c: c, enabled: enabled}
}
func ValidateURLIP(category, url, ip string) error {
	if _, err := Segment(category); err != nil {
		return err
	}
	if _, err := Segment(url); err != nil {
		return err
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return errors.New("IP must be one unscoped IPv4 or IPv6 address, without CIDR prefix")
	}
	return nil
}
func (t *URLIPClient) check() error {
	if t == nil || !t.enabled {
		return errors.New("URL/IP assignments require experimental_url_ip_memberships=true (A33.20+)")
	}
	if t.c == nil || t.c.base == "" {
		return errors.New("URL/IP assignments require AFA configuration")
	}
	return nil
}
func (t *URLIPClient) Present(ctx context.Context, category, url, ip string) (bool, error) {
	if err := ValidateURLIP(category, url, ip); err != nil {
		return false, err
	}
	if err := t.check(); err != nil {
		return false, err
	}
	cat, err := t.c.Category(ctx, category)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return slices.Contains(cat.URLs[url], ip), nil
}
func (t *URLIPClient) RequireParent(ctx context.Context, category, url string) error {
	if err := t.check(); err != nil {
		return err
	}
	cat, err := t.c.Category(ctx, category)
	if err != nil {
		return err
	}
	if _, ok := cat.URLs[url]; !ok {
		return errors.New("URL must already exist in the category")
	}
	return nil
}
func (t *URLIPClient) Change(ctx context.Context, category, url, ip string, add bool) error {
	if err := ValidateURLIP(category, url, ip); err != nil {
		return err
	}
	if err := t.check(); err != nil {
		return err
	}
	categoryPart, _ := Segment(category)
	urlPart, _ := Segment(url)
	method := "DELETE"
	if add {
		method = "PUT"
	}
	var out Categories
	if err := t.c.do(ctx, method, categoryPath+categoryPart+"/URL/"+urlPart+"/IP/", nil, []string{ip}, &out); err != nil {
		return err
	}
	all, err := validateCategories(out)
	if err != nil {
		return err
	}
	cat, ok := all[category]
	if !ok {
		return ErrContract
	}
	ips, ok := cat.URLs[url]
	if !ok || slices.Contains(ips, ip) != add {
		return ErrContract
	}
	return nil
}
