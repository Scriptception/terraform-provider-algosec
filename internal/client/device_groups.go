// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"sort"
	"strings"
)

// DeviceGroup is the EXPERIMENTAL A33.20 EA inventory contract.
type DeviceGroup struct {
	EntityType  string          `json:"entityType"`
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	Firewalls   []GroupFirewall `json:"firewalls"`
}
type GroupFirewall struct {
	EntityType  string `json:"entityType"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

func ValidateGroupName(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("display names must be nonblank; exact spelling and case are preserved")
	}
	_, err := Segment(s)
	return err
}
func ValidateGroupMembers(names []string) error {
	if len(names) == 0 {
		return errors.New("device groups require at least one device display name")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if strings.TrimSpace(n) == "" || seen[n] {
			return errors.New("device display names must be nonblank and unique")
		}
		seen[n] = true
	}
	return nil
}
func (c *Client) DeviceGroupsEnabled() error {
	if c == nil || !c.experimentalDeviceGroups {
		return errors.New("EXPERIMENTAL A33.20 device groups require explicit experimental_device_groups=true")
	}
	return nil
}
func (c *Client) groupWriteAllowed() error {
	if err := c.DeviceGroupsEnabled(); err != nil {
		return err
	}
	if c.readOnly {
		return errors.New("provider read_only is enabled; mutation refused")
	}
	return nil
}
func (g DeviceGroup) Members() []string {
	out := make([]string, 0, len(g.Firewalls))
	for _, f := range g.Firewalls {
		out = append(out, f.DisplayName)
	}
	sort.Strings(out)
	return out
}
func (c *Client) DeviceGroups(ctx context.Context) ([]DeviceGroup, error) {
	if err := c.DeviceGroupsEnabled(); err != nil {
		return nil, err
	}
	var out []DeviceGroup
	if err := c.do(ctx, "GET", api+"/groups", nil, nil, &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, ErrContract
	}
	displays, names := map[string]bool{}, map[string]bool{}
	for _, g := range out {
		if g.EntityType != "GROUP" || strings.TrimSpace(g.Name) == "" || ValidateGroupName(g.DisplayName) != nil || displays[g.DisplayName] || names[g.Name] || len(g.Firewalls) == 0 {
			return nil, ErrContract
		}
		displays[g.DisplayName] = true
		names[g.Name] = true
		fn, fd := map[string]bool{}, map[string]bool{}
		for _, f := range g.Firewalls {
			if strings.TrimSpace(f.EntityType) == "" || strings.TrimSpace(f.Name) == "" || strings.TrimSpace(f.DisplayName) == "" || fn[f.Name] || fd[f.DisplayName] {
				return nil, ErrContract
			}
			fn[f.Name] = true
			fd[f.DisplayName] = true
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
	return out, nil
}

// DeviceGroup only reports absence after successfully validating the whole inventory.
func (c *Client) DeviceGroup(ctx context.Context, name string) (*DeviceGroup, error) {
	if err := ValidateGroupName(name); err != nil {
		return nil, err
	}
	all, err := c.DeviceGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range all {
		if g.DisplayName == name {
			return &g, nil
		}
	}
	return nil, ErrNotFound
}
func sameGroup(a, b DeviceGroup) bool {
	return a.Name == b.Name && a.DisplayName == b.DisplayName && reflect.DeepEqual(a.Members(), b.Members())
}
func membershipMatches(g *DeviceGroup, want []string) bool {
	n := append([]string(nil), want...)
	sort.Strings(n)
	return g != nil && reflect.DeepEqual(g.Members(), n)
}

// Observe even failed writes: an appliance may have applied a mutation before failing.
func (c *Client) observeGroupWrite(ctx context.Context, name string, want []string, writeErr error) (*DeviceGroup, error) {
	g, readErr := c.DeviceGroup(ctx, name)
	if writeErr != nil {
		return g, errors.Join(writeErr, readErr)
	}
	if readErr != nil {
		return nil, readErr
	}
	if !membershipMatches(g, want) {
		return g, errors.New("group read-back membership differs from intended membership; observed state retained")
	}
	return g, nil
}

// CreateDeviceGroup establishes ownership only after a validated positive acknowledgment.
// afterCreateAccepted persists recoverable identity before inventory readback.
func (c *Client) CreateDeviceGroup(ctx context.Context, name string, members []string, afterCreateAccepted func()) (*DeviceGroup, error) {
	if err := c.groupWriteAllowed(); err != nil {
		return nil, err
	}
	if err := ValidateGroupName(name); err != nil {
		return nil, err
	}
	if err := ValidateGroupMembers(members); err != nil {
		return nil, err
	}
	g, err := c.DeviceGroup(ctx, name)
	if err == nil {
		return nil, errors.New("device group already exists; import it by display_name instead")
	}
	if !errors.Is(err, ErrNotFound) {
		return g, err
	}
	var out struct {
		Message string `json:"message"`
	}
	err = c.do(ctx, "POST", api+"/groups", url.Values{"displayName": {name}}, members, &out)
	if err == nil && out.Message != "Group created successfully." {
		err = ErrContract
	}
	if err != nil {
		return nil, errors.Join(err, errors.New("group create was not confirmed; no Terraform ownership recorded. If the POST outcome was ambiguous, inspect the remote group and verify ownership before importing it or retrying"))
	}
	if afterCreateAccepted != nil {
		afterCreateAccepted()
	}
	return c.observeGroupWrite(ctx, name, members, nil)
}

// UpdateDeviceGroup applies authoritative membership, adding before removing, with no mutation retries.
// The returned observation is usable even when err != nil.
func (c *Client) UpdateDeviceGroup(ctx context.Context, prior DeviceGroup, want []string) (*DeviceGroup, error) {
	if err := c.groupWriteAllowed(); err != nil {
		return nil, err
	}
	if err := ValidateGroupMembers(want); err != nil {
		return nil, err
	}
	current, err := c.DeviceGroup(ctx, prior.DisplayName)
	if err != nil {
		return nil, err
	}
	if !sameGroup(prior, *current) {
		return current, errors.New("concurrent group change detected before write; refresh and plan again")
	}
	old, newSet := map[string]bool{}, map[string]bool{}
	for _, n := range current.Members() {
		old[n] = true
	}
	for _, n := range want {
		newSet[n] = true
	}
	add, remove := []string{}, []string{}
	for n := range newSet {
		if !old[n] {
			add = append(add, n)
		}
	}
	for n := range old {
		if !newSet[n] {
			remove = append(remove, n)
		}
	}
	sort.Strings(add)
	sort.Strings(remove)
	part, err := Segment(prior.DisplayName)
	if err != nil {
		return current, err
	}
	for _, step := range []struct {
		method, suffix, message string
		names                   []string
	}{{"POST", "addDevices", "Devices added successfully", add}, {"DELETE", "removeDevices", "Devices removed successfully", remove}} {
		if len(step.names) == 0 {
			continue
		}
		check, e := c.DeviceGroup(ctx, prior.DisplayName)
		if e != nil {
			return current, e
		}
		if !sameGroup(*current, *check) {
			return check, errors.New("concurrent group change detected before write; refresh and plan again")
		}
		expected := map[string]bool{}
		for _, n := range current.Members() {
			expected[n] = true
		}
		for _, n := range step.names {
			if step.method == "POST" {
				expected[n] = true
			} else {
				delete(expected, n)
			}
		}
		target := []string{}
		for n := range expected {
			target = append(target, n)
		}
		var message string
		e = c.do(ctx, step.method, api+"/groups/"+part+"/"+step.suffix, nil, step.names, &message)
		if e == nil && message != step.message {
			e = ErrContract
		}
		observed, e := c.observeGroupWrite(ctx, prior.DisplayName, target, e)
		if observed != nil {
			current = observed
		}
		if e != nil {
			return current, e
		}
		if current.Name != prior.Name {
			return current, errors.New("group internal identity changed during update")
		}
	}
	if !membershipMatches(current, want) {
		return current, ErrContract
	}
	return current, nil
}
func (c *Client) DeleteDeviceGroup(ctx context.Context, prior DeviceGroup) (*DeviceGroup, error) {
	if err := c.groupWriteAllowed(); err != nil {
		return nil, err
	}
	current, err := c.DeviceGroup(ctx, prior.DisplayName)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !sameGroup(prior, *current) {
		return current, errors.New("concurrent group change detected before delete; refresh and plan again")
	}
	part, err := Segment(prior.DisplayName)
	if err != nil {
		return current, err
	}
	var message string
	writeErr := c.do(ctx, "DELETE", api+"/groups/"+part, nil, nil, &message)
	if writeErr == nil && message != "Group deleted successfully" {
		writeErr = ErrContract
	}
	observed, readErr := c.DeviceGroup(ctx, prior.DisplayName)
	if writeErr != nil {
		if errors.Is(readErr, ErrNotFound) {
			readErr = nil
		}
		return observed, errors.Join(writeErr, readErr)
	}
	if errors.Is(readErr, ErrNotFound) {
		return nil, nil
	}
	if readErr != nil {
		return current, readErr
	}
	return observed, errors.New("group deletion not confirmed by complete inventory")
}
