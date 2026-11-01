package provider

import (
	"context"
	"fmt"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Synthetic adversarial server, NOT a live capture or asserted AlgoSec error schema.
// Expected safety invariant: unknown acknowledgement cannot create ownership.
func TestAuditCategoryUnconfirmedCreateMustNotAdopt(t *testing.T) {
	for _, body := range []string{`{}`, `false`, `{"message":"failure"}`, `{"categories":{}}`, `[]`, `null`, `{`, `{"status":false}`, `{"categories":{"other":{"urls":{}}}}`, `{"categories":{"test":{"urls":{"wrong":[]}}}}`, `{"categories":{"test":{"urls":null}}}`} {
		t.Run(body, func(t *testing.T) {
			reads := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if q.Method == "GET" {
					reads++
					if reads == 1 {
						fmt.Fprint(w, `{"categories":{}}`)
					} else {
						fmt.Fprint(w, `{"categories":{"test":{"urls":{}}}}`)
					}
					return
				}
				fmt.Fprint(w, body)
			}))
			defer srv.Close()
			c, err := client.New(client.Options{URL: srv.URL, SessionID: "audit-session", Insecure: true, ReadOnly: false})
			if err != nil {
				t.Fatal(err)
			}
			r := &urlCategoryResource{c}
			state := categoryState(t, r)
			resp := resource.CreateResponse{State: tfsdk.State{Schema: state.Schema}}
			r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}}, &resp)
			if !resp.Diagnostics.HasError() || reads != 1 {
				t.Fatalf("unconfirmed create must diagnose without adoption GET: reads=%d diagnostics=%v", reads, resp.Diagnostics)
			}
			if !resp.State.Raw.IsNull() {
				t.Fatalf("SAFETY FAILURE: category ownership acquired after unconfirmed body %s; read_count=%d diagnostics=%v", body, reads, resp.Diagnostics)
			}
		})
	}
}

// Synthetic positive acknowledgement must preserve recovery identity on failed GET.
func TestAuditCategoryConfirmedCreateFailedReadback(t *testing.T) {
	reads := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.Method == "GET" {
			reads++
			if reads == 1 {
				fmt.Fprint(w, `{"categories":{}}`)
				return
			}
			w.WriteHeader(503)
			return
		}
		fmt.Fprint(w, `{"categories":{"test":{"urls":{}}}}`)
	}))
	defer srv.Close()
	c, _ := client.New(client.Options{URL: srv.URL, SessionID: "synthetic", Insecure: true})
	r := &urlCategoryResource{c}
	state := categoryState(t, r)
	resp := resource.CreateResponse{State: tfsdk.State{Schema: state.Schema}}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}}, &resp)
	if !resp.Diagnostics.HasError() || resp.State.Raw.IsNull() || reads != 2 {
		t.Fatalf("lost confirmed ownership or skipped readback: %+v", resp)
	}
}

func TestAuditCategoryAmbiguousOwnedWritesRetainState(t *testing.T) {
	for _, body := range []string{`{}`, `false`, `{"message":"failure"}`, `{"categories":null}`, `{`, `{"categories":{"test":{"urls":{}}}}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Method == "GET" {
					fmt.Fprint(w, `{"categories":{"test":{"urls":{}}}}`)
					return
				}
				fmt.Fprint(w, body)
			}))
			defer srv.Close()
			c, _ := client.New(client.Options{URL: srv.URL, SessionID: "synthetic", Insecure: true})
			r := &urlCategoryResource{c}
			state := categoryState(t, r)
			del := resource.DeleteResponse{State: state}
			r.Delete(context.Background(), resource.DeleteRequest{State: state}, &del)
			if !del.Diagnostics.HasError() || !del.State.Raw.Equal(state.Raw) {
				t.Fatal("ambiguous delete lost owned state")
			}
			plan := state
			var m categoryModel
			plan.Get(context.Background(), &m)
			m.Name = types.StringValue("new")
			plan.Set(context.Background(), &m)
			upd := resource.UpdateResponse{State: state}
			r.Update(context.Background(), resource.UpdateRequest{State: state, Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, &upd)
			if !upd.Diagnostics.HasError() || !upd.State.Raw.Equal(state.Raw) {
				t.Fatal("ambiguous rename lost owned state")
			}
		})
	}
}

func TestAuditCategoryRenameWrongAcknowledgedMembership(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.Method == "GET" {
			fmt.Fprint(w, `{"categories":{"test":{"urls":{}}}}`)
			return
		}
		fmt.Fprint(w, `{"categories":{"new":{"urls":{"unexpected.invalid":[]}}}}`)
	}))
	defer srv.Close()
	c, _ := client.New(client.Options{URL: srv.URL, SessionID: "synthetic", Insecure: true})
	r := &urlCategoryResource{c}
	state := categoryState(t, r)
	plan := state
	var m categoryModel
	plan.Get(context.Background(), &m)
	m.Name = types.StringValue("new")
	plan.Set(context.Background(), &m)
	resp := resource.UpdateResponse{State: state}
	r.Update(context.Background(), resource.UpdateRequest{State: state, Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, &resp)
	if !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
		t.Fatal("wrong acknowledged rename membership changed owned state")
	}
}

func TestAuditCategoryAcknowledgedDeleteStillRequiresGET(t *testing.T) {
	reads := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.Method == "GET" {
			reads++
			fmt.Fprint(w, `{"categories":{"test":{"urls":{}}}}`)
			return
		}
		fmt.Fprint(w, `{"categories":{}}`)
	}))
	defer srv.Close()
	c, _ := client.New(client.Options{URL: srv.URL, SessionID: "synthetic", Insecure: true})
	r := &urlCategoryResource{c}
	state := categoryState(t, r)
	resp := resource.DeleteResponse{State: state}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, &resp)
	if reads != 2 || !resp.Diagnostics.HasError() || !resp.State.Raw.Equal(state.Raw) {
		t.Fatal("delete skipped authoritative GET or discarded owned state")
	}
}
