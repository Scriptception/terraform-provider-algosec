// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Synthetic negative lifecycle cases assert ownership, not only diagnostics.
func TestTagURLRecovery(t *testing.T) {
	for _, kind := range []string{"tag", "url"} {
		for _, mode := range []string{"unconfirmed", "ack_read_error", "read_error", "delete_error", "preexisting"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				reads, writes := 0, 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
					if q.Method == "GET" {
						reads++
						if mode == "read_error" || mode == "delete_error" || mode == "ack_read_error" && writes > 0 {
							w.WriteHeader(403)
							return
						}
						if kind == "tag" {
							if writes == 0 && mode != "preexisting" {
								fmt.Fprint(w, `[]`)
							} else {
								fmt.Fprint(w, `[{"id":7,"name":"Example","scope":"","type":"ALGOSEC","relations":[]}]`)
							}
						} else {
							ips := `[]`
							if writes > 0 || mode == "preexisting" {
								ips = `["192.0.2.1"]`
							}
							fmt.Fprintf(w, `{"categories":{"Example":{"urls":{"www.example.com":%s}}}}`, ips)
						}
						return
					}
					writes++
					if mode == "unconfirmed" {
						fmt.Fprint(w, `{}`)
						return
					}
					if kind == "tag" {
						fmt.Fprint(w, `{"id":7,"name":"Example","scope":"","type":"ALGOSEC","relations":[]}`)
					} else {
						fmt.Fprint(w, `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1"]}}}}`)
					}
				}))
				defer server.Close()
				c, err := client.New(client.Options{URL: server.URL, SessionID: "synthetic", Insecure: true, ExperimentalTags: true, ExperimentalURLIPs: true})
				if err != nil {
					t.Fatal(err)
				}
				var r resource.Resource
				var model any
				id := "7"
				if kind == "tag" {
					r = &tagResource{c: c.Tags}
					model = tagState(client.Tag{ID: 7, Name: "Example", Scope: "", Type: "ALGOSEC"})
				} else {
					id = urlIPID("Example", "www.example.com", "192.0.2.1")
					m, e := parseURLIPID(id)
					if e != nil {
						t.Fatal(e)
					}
					model = m
					r = &urlIPResource{c: c.URLIPs}
				}
				ctx := context.Background()
				var sr resource.SchemaResponse
				r.Schema(ctx, resource.SchemaRequest{}, &sr)
				state := tfsdk.State{Schema: sr.Schema}
				if d := state.Set(ctx, model); d.HasError() {
					t.Fatal(d)
				}
				plan := tfsdk.Plan{Schema: sr.Schema}
				if d := plan.Set(ctx, model); d.HasError() {
					t.Fatal(d)
				}
				switch mode {
				case "read_error":
					resp := resource.ReadResponse{State: state}
					r.Read(ctx, resource.ReadRequest{State: state}, &resp)
					if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
						t.Fatal("lost owned read state")
					}
				case "delete_error":
					resp := resource.DeleteResponse{State: state}
					r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
					if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) || writes != 0 {
						t.Fatal("unsafe delete after permission error")
					}
				default:
					resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema}}
					r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
					if !resp.Diagnostics.HasError() {
						t.Fatal("missing error")
					}
					if mode == "ack_read_error" {
						var got types.String
						if d := resp.State.GetAttribute(ctx, path.Root("id"), &got); d.HasError() || got.ValueString() != id {
							t.Fatal("lost acknowledged identity", resp.Diagnostics)
						}
					} else {
						if !resp.State.Raw.IsNull() && resp.State.Raw.IsKnown() {
							t.Fatal("adopted unowned tuple")
						}
						expected := 1
						if kind == "url" {
							expected = 2
						}
						if reads != expected {
							t.Fatal("unconfirmed create used recovery GET", reads)
						}
						if mode == "preexisting" && writes != 0 {
							t.Fatal("wrote existing tuple")
						}
					}
				}
				if strings.Contains(fmt.Sprint(state.Raw), "synthetic") {
					t.Fatal("credential in resource state")
				}
			})
		}
	}
}
