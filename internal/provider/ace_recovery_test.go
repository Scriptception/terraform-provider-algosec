// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"fmt"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"net/http"
	"strings"
	"testing"
)

// Synthetic HTTPS state recovery checks use actual Framework state/config types.
func TestACEFrameworkRecovery(t *testing.T) {
	for _, family := range []string{"emails", "jira", "threat", "account"} {
		for _, mode := range []string{"unconfirmed", "readback_failure", "read_failure", "delete_failure", "update_failure"} {
			t.Run(family+"/"+mode, func(t *testing.T) {
				reads, writes := 0, 0
				present, empty, ack := "", "", ""
				switch family {
				case "emails":
					present = `{"data":{"threatManagement":{"enabled":true,"minimumSeverityLevel":0},"violationNotifications":{"emails":["test@example.invalid"]}}}`
					empty = strings.Replace(present, `["test@example.invalid"]`, `[]`, 1)
					ack = `{"data":{"message":"Your CD mitigation settings were successfully updated."}}`
				case "jira":
					present = `{"data":{"serverUrl":"https://jira.example.invalid","userName":"test@example.invalid","projectKey":"TEST","defaultIssueType":"Task","defaultPriority":"High","apiToken":"MASKED-SYNTHETIC"}}`
					empty = `{"data":{}}`
					ack = `{"data":{"message":"Your Jira project settings were successfully tested and saved."}}`
				case "threat":
					present = `{"data":[{"destination":"example.invalid","description":"synthetic","severity":"high"}],"page":{"current":1,"limit":1000,"total":1,"totalItems":1}}`
					empty = `{"data":[],"page":{"current":1,"limit":1000,"total":1,"totalItems":0}}`
					ack = `{"data":{"message":"Successfully added example.invalid entry to block-list for threat - domains."}}`
				case "account":
					present = `[{"accountKey":"opaque-key","accountId":"123456789012","provider":"aws","name":"synthetic","autoOnboarded":false}]`
					empty = `[]`
					ack = `{"accountKey":"opaque-key"}`
				}
				origin := aceProtocolServer(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "GET" {
						reads++
						if mode == "read_failure" || (mode == "readback_failure" && reads > 1) {
							w.WriteHeader(403)
							w.Write([]byte(`{"error":"synthetic-secret-never-log"}`))
							return
						}
						if (mode == "unconfirmed" || mode == "readback_failure") && reads == 1 {
							fmt.Fprint(w, empty)
							return
						}
						fmt.Fprint(w, present)
						return
					}
					writes++
					if mode == "delete_failure" || mode == "update_failure" {
						w.WriteHeader(500)
						return
					}
					if family == "account" {
						w.WriteHeader(201)
					}
					if mode == "unconfirmed" {
						fmt.Fprint(w, `{"success":true}`)
					} else {
						fmt.Fprint(w, ack)
					}
				})
				c, e := client.NewACEClient(origin, "synthetic-token", 30e9, false, true)
				if e != nil {
					t.Fatal(e)
				}
				var r resource.Resource
				var m any
				switch family {
				case "emails":
					r = &aceEmailsResource{c: c}
					m = aceEmailsState("aws", []string{"test@example.invalid"})
				case "jira":
					r = &aceJiraResource{c: c}
					v := aceJiraModel{Version: types.StringValue("1")}
					v.set(client.ACEJira{ServerURL: "https://jira.example.invalid", UserName: "test@example.invalid", ProjectKey: "TEST", IssueType: "Task", Priority: "High"})
					v.Token = types.StringValue("synthetic-raw-token")
					m = v
				case "threat":
					r = &aceThreatResource{c: c}
					m = aceThreatState(client.ACEThreatEntry{ThreatType: "domains", ListType: "block-list", Destination: "example.invalid", Description: "synthetic", Severity: "high"})
				case "account":
					r = &aceAccountResource{c: c}
					v := aceAccountModel{Version: types.StringValue("1")}
					v.set(client.ACEAccount{AccountKey: "opaque-key", AccountID: "123456789012", Provider: "aws", Name: "synthetic"})
					v.RoleARN = types.StringValue("arn:aws:iam::123456789012:role/Synthetic")
					v.ExternalID = types.StringValue("synthetic-external")
					v.SupportChanges = types.BoolValue(false)
					v.FlowLogs = types.BoolValue(false)
					m = v
				}
				ctx := context.Background()
				var sr resource.SchemaResponse
				r.Schema(ctx, resource.SchemaRequest{}, &sr)
				plan := tfsdk.Plan{Schema: sr.Schema}
				if d := plan.Set(ctx, m); d.HasError() {
					t.Fatal(d)
				}
				cfg := tfsdk.Config{Schema: sr.Schema, Raw: plan.Raw}
				state := tfsdk.State{Schema: sr.Schema}
				state.Set(ctx, m)
				if mode == "unconfirmed" || mode == "readback_failure" {
					resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema}}
					r.Create(ctx, resource.CreateRequest{Config: cfg, Plan: plan}, &resp)
					if !resp.Diagnostics.HasError() {
						t.Fatal("missing failure")
					}
					if mode == "unconfirmed" {
						if !resp.State.Raw.IsNull() && resp.State.Raw.IsKnown() {
							t.Fatal("unconfirmed ownership")
						}
						if reads != 1 || writes != 1 {
							t.Fatal("unconfirmed write adopted or replayed")
						}
					} else {
						if resp.State.Raw.IsNull() {
							t.Fatal("lost acknowledged identity")
						}
						var id types.String
						resp.State.GetAttribute(ctx, path.Root("id"), &id)
						if id.IsNull() || id.IsUnknown() || id.ValueString() == "" {
							t.Fatal("missing acknowledged ID")
						}
					}
					for _, secret := range []string{"synthetic-raw-token", "synthetic-external", "MASKED-SYNTHETIC", "synthetic-secret-never-log"} {
						if strings.Contains(fmt.Sprint(resp.State.Raw, resp.Diagnostics), secret) {
							t.Fatal("secret leaked in state/diagnostics")
						}
					}
				} else if mode == "read_failure" {
					resp := resource.ReadResponse{State: state}
					r.Read(ctx, resource.ReadRequest{State: state}, &resp)
					if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
						t.Fatal("read failure lost state")
					}
				} else if mode == "update_failure" {
					resp := resource.UpdateResponse{State: state}
					r.Update(ctx, resource.UpdateRequest{State: state, Plan: plan, Config: cfg}, &resp)
					if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
						t.Fatal("update failure lost state")
					}
				} else {
					resp := resource.DeleteResponse{State: state}
					r.Delete(ctx, resource.DeleteRequest{State: state}, &resp)
					if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
						t.Fatal("delete failure lost state")
					}
				}
			})
		}
	}
}
