// SPDX-License-Identifier: MPL-2.0
package client_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/Scriptception/terraform-provider-algosec/internal/testserver"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func groupClient(t *testing.T, s *testserver.GroupsServer, enabled, readonly bool) *client.Client {
	t.Helper()
	c, e := client.New(client.Options{URL: s.URL, SessionID: testserver.Session, Insecure: true, ExperimentalDeviceGroups: enabled, ReadOnly: readonly})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestGroupsLifecycleAndEscaping(t *testing.T) {
	ctx := context.Background()
	s := testserver.NewGroups()
	defer s.Close()
	c := groupClient(t, s, true, false)
	name := "Case /雪?%+#"
	persisted := false
	g, e := c.CreateDeviceGroup(ctx, name, []string{"Old /雪", " Old "}, func() { persisted = true })
	if e != nil || !persisted || g.Name == name {
		t.Fatalf("create: %v", e)
	}
	if _, e = c.CreateDeviceGroup(ctx, name, []string{"x"}, nil); e == nil || !strings.Contains(e.Error(), "import") {
		t.Fatal("existing group adopted")
	}
	g, e = c.UpdateDeviceGroup(ctx, *g, []string{"New A", "new a"})
	if e != nil || !reflect.DeepEqual(g.Members(), []string{"New A", "new a"}) {
		t.Fatalf("update: %v", e)
	}
	if _, e = c.DeviceGroup(ctx, strings.ToLower(name)); !errors.Is(e, client.ErrNotFound) {
		t.Fatal("case-insensitive lookup")
	}
	if _, e = c.DeleteDeviceGroup(ctx, *g); e != nil {
		t.Fatal(e)
	}
	if _, e = c.DeviceGroup(ctx, name); !errors.Is(e, client.ErrNotFound) {
		t.Fatal(e)
	}
	if _, e = c.DeleteDeviceGroup(ctx, *g); e != nil {
		t.Fatal(e)
	}
	writes := []string{}
	for i, call := range s.Calls {
		if !strings.HasPrefix(call, "GET") {
			writes = append(writes, call)
			if i+1 >= len(s.Calls) || s.Calls[i+1] != "GET /afa/api/v1/groups" {
				t.Fatal("missing immediate readback")
			}
		}
	}
	want := []string{"POST /afa/api/v1/groups", "POST /afa/api/v1/groups/" + url.PathEscape(name) + "/addDevices", "DELETE /afa/api/v1/groups/" + url.PathEscape(name) + "/removeDevices", "DELETE /afa/api/v1/groups/" + url.PathEscape(name)}
	if !reflect.DeepEqual(writes, want) {
		t.Fatalf("writes %v", writes)
	}
}
func TestGroupsInvalidInventory(t *testing.T) {
	valid := `{"entityType":"GROUP","name":"internal","displayName":"group","firewalls":[{"entityType":"FW_PIX","name":"fw","displayName":"FW"}]}`
	for _, body := range []string{`null`, `{}`, `{"error":"synthetic-secret-must-not-leak"}`, `{"status":false}`, `[`, `[{"entityType":"GROUP","name":"x","displayName":"x"}]`, `[` + valid + `,` + valid + `]`, `[` + valid + `,{}]`, strings.Replace(`[`+valid+`]`, `"firewalls":[{"entityType":"FW_PIX","name":"fw","displayName":"FW"}]`, `"firewalls":[]`, 1), strings.Replace(`[`+valid+`]`, `"displayName":"FW"`, `"displayName":null`, 1)} {
		t.Run(fmt.Sprintf("body%d", len(body)), func(t *testing.T) {
			s := testserver.NewGroups()
			defer s.Close()
			s.ReadBody = body
			c := groupClient(t, s, true, false)
			if _, e := c.DeviceGroup(context.Background(), "absent"); e == nil || errors.Is(e, client.ErrNotFound) || strings.Contains(e.Error(), "synthetic-secret") {
				t.Fatalf("unsafe inventory result: %v", e)
			}
		})
	}
}
func TestGroupsFailuresAndPartialProgress(t *testing.T) {
	for _, status := range []int{401, 403, 404, 423, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := testserver.NewGroups()
			defer s.Close()
			prior := testserver.SyntheticGroup("group", "old")
			s.Groups["group"] = prior
			c := groupClient(t, s, true, false)
			s.ReadStatus = status
			if _, e := c.DeviceGroup(context.Background(), "group"); e == nil || errors.Is(e, client.ErrNotFound) {
				t.Fatal("endpoint failure treated as absence")
			}
			s.ReadStatus = 0
			s.WriteStatus = status
			s.FailWrite = 2
			got, e := c.UpdateDeviceGroup(context.Background(), prior, []string{"new"})
			if e == nil || got == nil || !reflect.DeepEqual(got.Members(), []string{"new", "old"}) || strings.Contains(e.Error(), "synthetic-secret") {
				t.Fatalf("partial state: %#v %v", got, e)
			}
			if s.WriteCount != 2 {
				t.Fatal("mutation retried")
			}
			s.WriteStatus = 0
			got, e = c.UpdateDeviceGroup(context.Background(), *got, []string{"new"})
			if e != nil || !reflect.DeepEqual(got.Members(), []string{"new"}) {
				t.Fatal("recovery failed", e)
			}
		})
	}
}
func TestGroupsGateAndReadOnly(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := testserver.NewGroups()
		c := groupClient(t, s, enabled, true)
		ctx := context.Background()
		g := testserver.SyntheticGroup("g", "a")
		if _, e := c.CreateDeviceGroup(ctx, "g", []string{"a"}, nil); e == nil {
			t.Fatal("create allowed")
		}
		if _, e := c.UpdateDeviceGroup(ctx, g, []string{"b"}); e == nil {
			t.Fatal("update allowed")
		}
		if _, e := c.DeleteDeviceGroup(ctx, g); e == nil {
			t.Fatal("delete allowed")
		}
		if !enabled {
			if _, e := c.DeviceGroups(ctx); e == nil {
				t.Fatal("read allowed")
			}
		}
		if len(s.Calls) != 0 {
			t.Fatal("gate made calls")
		}
		s.Close()
	}
}
func TestGroupsConcurrencyAndReadback(t *testing.T) {
	for _, mode := range []string{"before", "between", "noop", "identity", "failed_readback", "error_envelope", "false_message"} {
		t.Run(mode, func(t *testing.T) {
			s := testserver.NewGroups()
			defer s.Close()
			prior := testserver.SyntheticGroup("g", "old")
			s.Groups["g"] = prior
			c := groupClient(t, s, true, false)
			switch mode {
			case "before":
				s.Groups["g"] = testserver.SyntheticGroup("g", "drift")
			case "between":
				reads := 0
				s.BeforeRead = func(s *testserver.GroupsServer) {
					reads++
					if reads == 4 {
						s.Groups["g"] = testserver.SyntheticGroup("g", "drift")
					}
				}
			case "noop":
				s.Noop = true
			case "identity":
				s.AfterWrite = func(s *testserver.GroupsServer) { g := s.Groups["g"]; g.Name = "replacement"; s.Groups["g"] = g }
			case "failed_readback":
				s.AfterWrite = func(s *testserver.GroupsServer) { s.ReadStatus = 500 }
			case "error_envelope":
				s.WriteBody = `{"error":"synthetic-secret-must-not-leak"}`
			case "false_message":
				s.WriteBody = `"failed"`
			}
			got, e := c.UpdateDeviceGroup(context.Background(), prior, []string{"new"})
			if e == nil || got == nil {
				t.Fatal("failure lost observation", e)
			}
			if s.WriteCount > 1 {
				t.Fatal("continued unsafe writes")
			}
		})
	}
}
func TestGroupsDeleteVerificationAndCreateIdentity(t *testing.T) {
	for _, mode := range []string{"noop", "error", "read_error"} {
		t.Run(mode, func(t *testing.T) {
			s := testserver.NewGroups()
			defer s.Close()
			g := testserver.SyntheticGroup("g", "a")
			s.Groups["g"] = g
			c := groupClient(t, s, true, false)
			switch mode {
			case "noop":
				s.Noop = true
			case "error":
				s.WriteBody = `{"status":false,"message":"synthetic-secret-must-not-leak"}`
			case "read_error":
				s.AfterWrite = func(s *testserver.GroupsServer) { s.ReadStatus = 404 }
			}
			if _, e := c.DeleteDeviceGroup(context.Background(), g); e == nil {
				t.Fatal("delete accepted")
			}
		})
	}
	s := testserver.NewGroups()
	defer s.Close()
	c := groupClient(t, s, true, false)
	persisted := false
	s.BeforeRead = func(s *testserver.GroupsServer) {
		if s.WriteCount == 0 {
			return
		}
		if !persisted {
			t.Error("identity not persisted before read")
		}
		s.ReadStatus = 500
	}
	if _, e := c.CreateDeviceGroup(context.Background(), "g", []string{"a"}, func() { persisted = true }); e == nil || !persisted {
		t.Fatal("identity failure")
	}
}
func TestGroupsInputValidation(t *testing.T) {
	for _, n := range []string{"", " \t", ".", ".."} {
		if client.ValidateGroupName(n) == nil {
			t.Fatal("invalid name accepted")
		}
	}
	for _, m := range [][]string{nil, {}, {""}, {" "}, {"a", "a"}} {
		if client.ValidateGroupMembers(m) == nil {
			t.Fatal("invalid members accepted")
		}
	}
	if client.ValidateGroupName(" a /雪?% ") != nil || client.ValidateGroupMembers([]string{" a ", "A"}) != nil {
		t.Fatal("exact names rejected")
	}
}
