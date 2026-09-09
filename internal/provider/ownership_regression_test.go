// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/Scriptception/terraform-provider-algosec/internal/testserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// A definitive rejection must not acquire an object created by another actor.
func TestGroupRejectedCreateDoesNotAdoptConcurrentObject(t *testing.T) {
	s, r, state := groupResourceFixture(t)
	s.Groups = map[string]client.DeviceGroup{}
	s.WriteStatus = 403
	reads := 0
	s.BeforeRead = func(s *testserver.GroupsServer) {
		reads++
		if reads == 2 {
			s.Groups["Group /雪?%"] = testserver.SyntheticGroup("Group /雪?%", "foreign-member")
		}
	}
	plan := groupPlan(t, state, "new")
	resp := resource.CreateResponse{State: tfsdk.State{Schema: state.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: plan}, &resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected forbidden create diagnostic")
	}
	if !resp.State.Raw.IsNull() {
		t.Fatal("definitively rejected create retained ownership of another actor's group")
	}
}

// Synthetic HTTP outcomes: another actor wins the race after the empty preflight,
// or the server applies our POST but its acknowledgment never reaches the client.
func TestGroupUnconfirmedCreateHasNoOwnership(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		disconnect bool
	}{
		{"conflict400", 400, "", false}, {"conflict409", 409, "", false},
		{"forbidden", 403, "", false}, {"unauthorized", 401, "", false},
		{"malformed", 200, "{", false}, {"unsuccessful", 200, `{"message":"failed synthetic-secret"}`, false},
		{"false_success", 200, `{"status":false,"message":"Group created successfully."}`, false},
		{"ambiguous500", 500, "", false}, {"transport", 0, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, r, state := groupResourceFixture(t)
			reads, writes := 0, 0
			visible := false
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if q.Method == "GET" {
					reads++
					if visible {
						json.NewEncoder(w).Encode([]client.DeviceGroup{testserver.SyntheticGroup("Group /雪?%", "foreign-member")})
					} else {
						w.Write([]byte(`[]`))
					}
					return
				}
				writes++
				visible = true
				if tc.disconnect {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			var err error
			r.c, err = client.New(client.Options{URL: srv.URL, SessionID: testserver.Session, Insecure: true, ExperimentalDeviceGroups: true})
			if err != nil {
				t.Fatal(err)
			}
			resp := resource.CreateResponse{State: tfsdk.State{Schema: state.Schema}}
			r.Create(context.Background(), resource.CreateRequest{Plan: groupPlan(t, state, "new")}, &resp)
			if !resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
				t.Fatalf("unconfirmed create acquired state: %v", resp.Diagnostics)
			}
			if reads != 1 || writes != 1 {
				t.Fatalf("unexpected observation or retry: reads=%d writes=%d", reads, writes)
			}
			details := fmt.Sprint(resp.Diagnostics)
			if strings.Contains(details, "synthetic-secret") || !strings.Contains(details, "import") {
				t.Fatalf("unsafe/unhelpful diagnostic: %s", details)
			}
			g, err := r.c.DeviceGroup(context.Background(), "Group /雪?%")
			if err != nil || g == nil {
				t.Fatal("fixture group must remain visible", err)
			}
		})
	}
}

func TestGroupAcknowledgedCreateReadFailureRetainsOwnership(t *testing.T) {
	for _, status := range []int{403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s, r, state := groupResourceFixture(t)
			s.Groups = map[string]client.DeviceGroup{}
			s.AfterWrite = func(s *testserver.GroupsServer) { s.ReadStatus = status }
			resp := resource.CreateResponse{State: tfsdk.State{Schema: state.Schema}}
			r.Create(context.Background(), resource.CreateRequest{Plan: groupPlan(t, state, "new")}, &resp)
			var got deviceGroupModel
			d := resp.State.Get(context.Background(), &got)
			if !resp.Diagnostics.HasError() || d.HasError() || got.ID.ValueString() != "Group /雪?%" || !got.InternalName.IsNull() {
				t.Fatalf("acknowledged create lost recoverable identity: %v %v", resp.Diagnostics, d)
			}
			s.Mu.Lock()
			s.ReadStatus = 0
			s.Mu.Unlock()
			read := resource.ReadResponse{State: resp.State}
			r.Read(context.Background(), resource.ReadRequest{State: resp.State}, &read)
			d = read.State.Get(context.Background(), &got)
			if read.Diagnostics.HasError() || d.HasError() || got.InternalName.IsNull() {
				t.Fatal("refresh did not recover acknowledged create")
			}
		})
	}
}
