// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

const categoryPath = api + "/plugins/panorama/URLCategory/"

type Category struct {
	URLs map[string][]string `json:"urls"`
}
type Categories struct {
	Categories map[string]Category `json:"categories"`
}

func (c *Client) Categories(ctx context.Context) (map[string]Category, error) {
	var out Categories
	if err := c.do(ctx, "GET", categoryPath, nil, nil, &out); err != nil {
		return nil, err
	}
	return validateCategories(out)
}

func validateCategories(out Categories) (map[string]Category, error) {
	if out.Categories == nil {
		return nil, ErrContract
	}
	for name, v := range out.Categories {
		if _, err := Segment(name); err != nil || v.URLs == nil {
			return nil, ErrContract
		}
		if err := ValidateURLs(v.URLs); err != nil {
			return nil, ErrContract
		}
	}
	return out.Categories, nil
}
func ValidateURLs(urls map[string][]string) error {
	if urls == nil {
		return errors.New("urls must be a non-null map")
	}
	for name, ips := range urls {
		if _, err := Segment(name); err != nil {
			return err
		}
		if ips == nil {
			return errors.New("IP sets must not be null")
		}
		seen := map[string]bool{}
		for _, ip := range ips {
			if _, err := netip.ParseAddr(ip); err != nil {
				return errors.New("IP values must be individual IPv4 or IPv6 addresses")
			}
			if seen[ip] {
				return errors.New("duplicate IP in API response")
			}
			seen[ip] = true
		}
	}
	return nil
}
func (c *Client) Category(ctx context.Context, name string) (Category, error) {
	all, err := c.Categories(ctx)
	if err != nil {
		return Category{}, err
	}
	v, ok := all[name]
	if !ok {
		return Category{}, ErrNotFound
	}
	return v, nil
}
func (c *Client) CreateCategory(ctx context.Context, name string, v Category) error {
	if _, err := Segment(name); err != nil {
		return err
	}
	if err := ValidateURLs(v.URLs); err != nil {
		return err
	}
	var out Categories
	if err := c.do(ctx, "PUT", categoryPath, nil, Categories{map[string]Category{name: v}}, &out); err != nil {
		return err
	}
	all, err := validateCategories(out)
	if err != nil {
		return err
	}
	got, ok := all[name]
	if !ok || !categoryMembershipEqual(got, v) {
		return ErrContract
	}
	return nil
}
func (c *Client) RenameCategory(ctx context.Context, oldName, newName string, expected Category) error {
	part, err := Segment(oldName)
	if err != nil {
		return err
	}
	if _, err = Segment(newName); err != nil {
		return err
	}
	var out Categories
	if err := c.do(ctx, "PUT", categoryPath+part+"/", nil, newName, &out); err != nil {
		return err
	}
	all, err := validateCategories(out)
	if err != nil {
		return err
	}
	if _, ok := all[oldName]; ok {
		return ErrContract
	}
	if got, ok := all[newName]; !ok || !categoryMembershipEqual(got, expected) {
		return ErrContract
	}
	return nil
}
func (c *Client) DeleteCategory(ctx context.Context, name string) error {
	if _, err := Segment(name); err != nil {
		return err
	}
	// Select the response table's post-deletion categories map, shared with GET.
	// The contradictory nested example is not an alternate contract or retry path.
	var out Categories
	if err := c.do(ctx, "DELETE", categoryPath, nil, []string{name}, &out); err != nil {
		return err
	}
	all, err := validateCategories(out)
	if err != nil {
		return err
	}
	if _, ok := all[name]; ok {
		return ErrContract
	}
	return nil
}

func categoryMembershipEqual(a, b Category) bool {
	if len(a.URLs) != len(b.URLs) {
		return false
	}
	for url, ips := range a.URLs {
		other, ok := b.URLs[url]
		if !ok {
			return false
		}
		x, y := slices.Clone(ips), slices.Clone(other)
		slices.Sort(x)
		slices.Sort(y)
		if !slices.Equal(x, y) {
			return false
		}
	}
	return true
}
