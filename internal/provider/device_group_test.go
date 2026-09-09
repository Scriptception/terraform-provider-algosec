// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/Scriptception/terraform-provider-algosec/internal/testserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func groupResourceFixture(t *testing.T) (*testserver.GroupsServer, *deviceGroupResource, tfsdk.State) {
	t.Helper()
	s := testserver.NewGroups()
	t.Cleanup(s.Close)
	c, e := client.New(client.Options{URL: s.URL, SessionID: testserver.Session, Insecure: true, ExperimentalDeviceGroups: true})
	if e != nil {
		t.Fatal(e)
	}
	r := &deviceGroupResource{c}
	var schema resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schema)
	state := tfsdk.State{Schema: schema.Schema}
	g := testserver.SyntheticGroup("Group /雪?%", "old")
	s.Groups[g.DisplayName] = g
	if d := setGroupState(context.Background(), &state, &g); d.HasError() {
		t.Fatal(d)
	}
	return s, r, state
}
func groupPlan(t *testing.T, state tfsdk.State, names ...string) tfsdk.Plan {
	t.Helper()
	ctx := context.Background()
	var m deviceGroupModel
	if d := state.Get(ctx, &m); d.HasError() {
		t.Fatal(d)
	}
	m.Members, _ = types.SetValueFrom(ctx, types.StringType, names)
	m.InternalName = types.StringUnknown()
	p := tfsdk.Plan{Schema: state.Schema}
	if d := p.Set(ctx, &m); d.HasError() {
		t.Fatal(d)
	}
	return p
}
func TestGroupFrameworkPartialUpdateRecovery(t *testing.T) {
	s, r, state := groupResourceFixture(t)
	s.FailWrite = 2
	s.WriteStatus = 500
	ctx := context.Background()
	plan := groupPlan(t, state, "new")
	resp := resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{State: state, Plan: plan}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("missing partial failure diagnostic")
	}
	var m deviceGroupModel
	resp.State.Get(ctx, &m)
	var members []string
	m.Members.ElementsAs(ctx, &members, false)
	if !reflect.DeepEqual(members, []string{"new", "old"}) {
		t.Fatalf("partial state %v", members)
	}
	s.Mu.Lock()
	s.WriteStatus = 0
	s.Mu.Unlock()
	state = resp.State
	resp = resource.UpdateResponse{State: state}
	r.Update(ctx, resource.UpdateRequest{State: state, Plan: plan}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	resp.State.Get(ctx, &m)
	m.Members.ElementsAs(ctx, &members, false)
	if !reflect.DeepEqual(members, []string{"new"}) {
		t.Fatal(members)
	}
}
func TestGroupFrameworkReadAndDeleteRetention(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s, r, state := groupResourceFixture(t)
			s.ReadStatus = status
			ctx := context.Background()
			read := resource.ReadResponse{State: state}
			r.Read(ctx, resource.ReadRequest{State: state}, &read)
			if !read.Diagnostics.HasError() || !read.State.Raw.Equal(state.Raw) {
				t.Fatal("read discarded state")
			}
			del := resource.DeleteResponse{State: state}
			r.Delete(ctx, resource.DeleteRequest{State: state}, &del)
			if !del.Diagnostics.HasError() || !del.State.Raw.Equal(state.Raw) {
				t.Fatal("delete discarded state")
			}
		})
	}
	s, r, state := groupResourceFixture(t)
	s.Groups = map[string]client.DeviceGroup{}
	resp := resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, &resp)
	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Fatal("absence not removed")
	}
}
func TestGroupFrameworkCreateReadFailureIdentity(t *testing.T) {
	s, r, state := groupResourceFixture(t)
	s.Groups = map[string]client.DeviceGroup{}
	s.AfterWrite = func(s *testserver.GroupsServer) { s.ReadStatus = 500 }
	plan := groupPlan(t, state, "new")
	resp := resource.CreateResponse{State: tfsdk.State{Schema: state.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, &resp)
	var m deviceGroupModel
	d := resp.State.Get(context.Background(), &m)
	if !resp.Diagnostics.HasError() || d.HasError() || m.ID.ValueString() != "Group /雪?%" {
		t.Fatal("create lost identity", d)
	}
}
func TestGroupFrameworkUnknownNullInputs(t *testing.T) {
	for _, tc := range []struct {
		name    types.String
		members types.Set
	}{{types.StringNull(), types.SetUnknown(types.StringType)}, {types.StringUnknown(), types.SetNull(types.StringType)}, {types.StringValue("g"), types.SetNull(types.StringType)}, {types.StringValue("g"), types.SetUnknown(types.StringType)}} {
		s, r, state := groupResourceFixture(t)
		p := tfsdk.Plan{Schema: state.Schema}
		m := deviceGroupModel{ID: types.StringUnknown(), InternalName: types.StringUnknown(), DisplayName: tc.name, Members: tc.members}
		if d := p.Set(context.Background(), m); d.HasError() {
			t.Fatal(d)
		}
		resp := resource.CreateResponse{State: tfsdk.State{Schema: state.Schema}}
		r.Create(context.Background(), resource.CreateRequest{Plan: p}, &resp)
		if !resp.Diagnostics.HasError() || len(s.Calls) != 0 {
			t.Fatal("unknown/null input reached API")
		}
	}
}
func groupProtocolConfig(s *testserver.GroupsServer, members string) string {
	return fmt.Sprintf(`provider "algosec" {
 url = %q
 session_id = %q
 insecure = true
 experimental_device_groups = true
 read_only = false
}
resource "algosec_device_group" "test" {
 display_name = "Group /雪?%%"
 members = %s
}
data "algosec_device_group" "test" { display_name = algosec_device_group.test.display_name }
data "algosec_device_groups" "test" { depends_on = [algosec_device_group.test] }
`, s.URL, testserver.Session, members)
}

// Real Terraform CLI against a controlled SYNTHETIC HTTPS fixture. No live acceptance.
func TestProtocolDeviceGroupLifecycle(t *testing.T) {
	requireTerraform(t)
	s := testserver.NewGroups()
	defer s.Close()
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		s.Mu.Lock()
		defer s.Mu.Unlock()
		if len(s.Groups) != 0 {
			return fmt.Errorf("synthetic group leaked")
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: groupProtocolConfig(s, `["old A", "old B"]`), Check: tfresource.ComposeTestCheckFunc(tfresource.TestCheckResourceAttr("algosec_device_group.test", "id", "Group /雪?%"), tfresource.TestCheckResourceAttr("algosec_device_group.test", "internal_name", "internal:Group /雪?%"), tfresource.TestCheckResourceAttr("data.algosec_device_groups.test", "groups.#", "1"), tfresource.TestCheckResourceAttr("data.algosec_device_group.test", "group.firewalls.#", "2"))},
		{ResourceName: "algosec_device_group.test", ImportState: true, ImportStateVerify: true},
		{Config: groupProtocolConfig(s, `["new A", "new B"]`), Check: tfresource.TestCheckResourceAttr("algosec_device_group.test", "members.#", "2")},
		{PreConfig: func() {
			s.Mu.Lock()
			s.Groups["Group /雪?%"] = testserver.SyntheticGroup("Group /雪?%", "drift")
			s.Mu.Unlock()
		}, Config: groupProtocolConfig(s, `["new A", "new B"]`)},
		{PreConfig: func() { s.Mu.Lock(); delete(s.Groups, "Group /雪?%"); s.Mu.Unlock() }, Config: groupProtocolConfig(s, `["new A", "new B"]`)},
	}})
}
func TestProtocolDeviceGroupValidation(t *testing.T) {
	requireTerraform(t)
	for _, members := range []string{`[]`, `[" "]`, `null`, `[null]`} {
		t.Run(members, func(t *testing.T) {
			s := testserver.NewGroups()
			defer s.Close()
			tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{{Config: groupProtocolConfig(s, members), ExpectError: regexp.MustCompile("(?i)(invalid|nonblank|required|null|at least)")}}})
			s.Mu.Lock()
			defer s.Mu.Unlock()
			if s.WriteCount != 0 {
				t.Fatal("invalid input wrote")
			}
		})
	}
}
func TestProtocolDeviceGroupUnknownPlan(t *testing.T) {
	requireTerraform(t)
	s := testserver.NewGroups()
	defer s.Close()
	cfg := groupProtocolConfig(s, `[terraform_data.member.output]`) + `resource "terraform_data" "member" { input = "Member" }`
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{{Config: cfg}}})
}

func TestProtocolDeviceGroupSafetyDefaults(t *testing.T) {
	requireTerraform(t)
	for _, tc := range []struct{ name, settings, body, pattern string }{
		{"gate_default", "", `data "algosec_device_groups" "test" {}`, "experimental_device_groups"},
		{"gate_null", "experimental_device_groups = null", `data "algosec_device_group" "test" { display_name = "g" }`, "experimental_device_groups"},
		{"gate_false", "experimental_device_groups = false\nread_only = false", `resource "algosec_device_group" "test" {
display_name = "g"
members = ["a"]
}`, "experimental_device_groups"},
		{"readonly_default", "experimental_device_groups = true", `resource "algosec_device_group" "test" {
display_name = "g"
members = ["a"]
}`, "read_only"},
		{"readonly_null", "experimental_device_groups = true\nread_only = null", `resource "algosec_device_group" "test" {
display_name = "g"
members = ["a"]
}`, "read_only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testserver.NewGroups()
			defer s.Close()
			cfg := fmt.Sprintf("provider \"algosec\" {\nurl = %q\nsession_id = %q\ninsecure = true\n%s\n}\n%s", s.URL, testserver.Session, tc.settings, tc.body)
			tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{{Config: cfg, ExpectError: regexp.MustCompile(tc.pattern)}}})
			s.Mu.Lock()
			defer s.Mu.Unlock()
			if len(s.Calls) != 0 {
				t.Fatal("safety defaults allowed calls")
			}
		})
	}
}
func TestProtocolDeviceGroupPartialRecovery(t *testing.T) {
	requireTerraform(t)
	s := testserver.NewGroups()
	defer s.Close()
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{
		{Config: groupProtocolConfig(s, `["old"]`)},
		{PreConfig: func() { s.Mu.Lock(); s.FailWrite = s.WriteCount + 2; s.WriteStatus = 500; s.Mu.Unlock() }, Config: groupProtocolConfig(s, `["new"]`), ExpectError: regexp.MustCompile("HTTP 500")},
		{PreConfig: func() {
			s.Mu.Lock()
			defer s.Mu.Unlock()
			if !reflect.DeepEqual(s.Groups["Group /雪?%"].Members(), []string{"new", "old"}) {
				t.Error("missing intermediate membership")
			}
			s.WriteStatus = 0
		}, Config: groupProtocolConfig(s, `["new"]`), Check: tfresource.TestCheckResourceAttr("algosec_device_group.test", "members.#", "1")},
	}})
}
func TestGroupFrameworkMalformedInventoryRetention(t *testing.T) {
	for _, body := range []string{`{"error":"synthetic-secret-must-not-leak"}`, `{"status":false}`, `[{}]`, `null`} {
		s, r, state := groupResourceFixture(t)
		s.ReadBody = body
		read := resource.ReadResponse{State: state}
		r.Read(context.Background(), resource.ReadRequest{State: state}, &read)
		if !read.Diagnostics.HasError() || !read.State.Raw.Equal(state.Raw) {
			t.Fatal("malformed inventory discarded state")
		}
	}
}
func TestProtocolDeviceGroupRenameReplacement(t *testing.T) {
	requireTerraform(t)
	s := testserver.NewGroups()
	defer s.Close()
	cfg := groupProtocolConfig(s, `["a"]`)
	renamed := strings.ReplaceAll(cfg, "Group /雪?%", "Renamed /雪?%")
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{{Config: cfg}, {Config: renamed, Check: tfresource.TestCheckResourceAttr("algosec_device_group.test", "id", "Renamed /雪?%")}}})
}
