// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Synthetic failures must preserve ownership, never reinterpret partial success.
func TestFireFlowRecovery(t *testing.T) {
	for _, kind := range []string{"member", "permission"} {
		for _, mode := range []string{"partial", "ack_read_error", "preexisting", "read_error", "dependency_error", "drift"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				reads, writes := 0, 0
				s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "GET" {
						reads++
						if mode == "read_error" || mode == "ack_read_error" && writes > 0 {
							w.WriteHeader(403)
							return
						}
						present := mode == "preexisting" || mode == "dependency_error" || writes > 0
						if kind == "member" {
							if present {
								fmt.Fprint(w, `{"status":"Success","messages":[],"data":[{"id":8,"name":"Example","type":"Role","isDirectMember":true}]}`)
							} else {
								fmt.Fprint(w, `{"status":"Success","messages":[],"data":[]}`)
							}
						} else {
							fmt.Fprintf(w, `{"status":"Success","messages":[],"data":{"system":[{"permissionName":"SeeRole","objectType":"System","objectId":0,"direct":%t,"inherited":true}],"customField":[],"requestTemplate":[]}}`, present)
						}
						return
					}
					writes++
					if mode == "dependency_error" {
						w.WriteHeader(409)
						return
					}
					if mode == "partial" {
						fmt.Fprint(w, `{"status":"PartiallySuccess","messages":[{"code":"CIRCULAR_DEPENDENCY"}],"data":null}`)
						return
					}
					data := "null"
					if kind == "permission" {
						data = "{}"
					}
					fmt.Fprintf(w, `{"status":"Success","messages":[],"data":%s}`, data)
				}))
				defer s.Close()
				ca := filepath.Join(t.TempDir(), "ca.pem")
				if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); e != nil {
					t.Fatal(e)
				}
				t.Setenv("SSL_CERT_FILE", ca)
				c, e := client.NewFireFlowClient(s.URL, "synthetic-session", time.Second, false, true)
				if e != nil {
					t.Fatal(e)
				}
				var r resource.Resource
				var model any
				id := "v1.7.Role.8"
				if kind == "member" {
					m, e := parseFireFlowMemberID(id)
					if e != nil {
						t.Fatal(e)
					}
					model = m
					r = &fireFlowMemberResource{c: c}
				} else {
					id = fireFlowPermissionID(7, client.FireFlowPermissionRef{Name: "SeeRole", ObjectType: "System", ObjectID: 0})
					m, e := parseFireFlowPermissionID(id)
					if e != nil {
						t.Fatal(e)
					}
					m.Inherited = types.BoolValue(true)
					model = m
					r = &fireFlowPermissionResource{c: c}
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
				case "read_error", "drift":
					resp := resource.ReadResponse{State: state}
					r.Read(ctx, resource.ReadRequest{State: state}, &resp)
					if mode == "drift" {
						if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
							t.Fatal("direct drift did not remove state")
						}
					} else if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
						t.Fatal("permission error lost state")
					}
				case "dependency_error":
					resp := resource.DeleteResponse{State: state}
					r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
					if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) || writes != 1 {
						t.Fatal("dependency failure lost state or retried")
					}
				default:
					resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema}}
					r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
					if !resp.Diagnostics.HasError() {
						t.Fatal("missing failure")
					}
					if mode == "ack_read_error" {
						var got types.String
						if d := resp.State.GetAttribute(ctx, path.Root("id"), &got); d.HasError() || got.ValueString() != id {
							t.Fatal("lost acknowledged tuple", resp.Diagnostics)
						}
					} else {
						if !resp.State.Raw.IsNull() && resp.State.Raw.IsKnown() {
							t.Fatal("adopted partial or existing tuple")
						}
						if reads != 1 {
							t.Fatal("unconfirmed create used readback", reads)
						}
						if mode == "preexisting" && writes != 0 {
							t.Fatal("wrote preexisting tuple")
						}
					}
				}
				if strings.Contains(fmt.Sprint(state.Raw), "synthetic-session") {
					t.Fatal("session stored in resource state")
				}
			})
		}
	}
}
func TestFireFlowImportCanonical(t *testing.T) {
	for _, id := range []string{"v1.07.Role.8", "v1.7.Role.7", "v1.7.Other.8", "v1.7.User.0", "v1.7.User.2147483648"} {
		if _, e := parseFireFlowMemberID(id); e == nil {
			t.Fatal("bad member import", id)
		}
	}
	for _, id := range []string{"v1.07.System.0.U2VlUm9sZQ", "v1.7.System.1.U2VlUm9sZQ", "v1.7.System.0.U2VlUm9sZQ==", "v1.7.CustomField.0.U2VlUm9sZQ"} {
		if _, e := parseFireFlowPermissionID(id); e == nil {
			t.Fatal("bad permission import", id)
		}
	}
}
