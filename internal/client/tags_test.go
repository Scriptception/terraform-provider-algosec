// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every tag and association in this suite is synthetic.
func tagFixture(t *testing.T, handler http.HandlerFunc) *TagClient {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	c, err := New(Options{URL: s.URL, SessionID: "synthetic-session"})
	if err != nil {
		t.Fatal(err)
	}
	c.http = s.Client()
	return NewTagClient(c, true)
}
func TestTagCreateAcknowledgement(t *testing.T) {
	for _, body := range []string{`{}`, `[]`, `null`, `{"id":0,"name":"Finance","scope":"","type":"ALGOSEC"}`, `{"id":7,"name":"Other","scope":"","type":"ALGOSEC"}`, `{"id":7,"name":"Finance","scope":"","type":"DEVICE"}`} {
		t.Run(body, func(t *testing.T) {
			c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := c.Create(context.Background(), "Finance", ""); err == nil {
				t.Fatal("unconfirmed create acquired identity")
			}
		})
	}
	c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/afa/api/v1/tags" || r.URL.Query().Get("name") != "Finance & HR" {
			t.Error("wrong request")
		}
		cookie, e := r.Cookie("PHPSESSID")
		if e != nil || cookie.Value != "synthetic-session" {
			t.Error("wrong authentication")
		}
		fmt.Fprint(w, `{"id":7,"name":"Finance & HR","scope":"","type":"ALGOSEC"}`)
	})
	got, err := c.Create(context.Background(), "Finance & HR", "")
	if err != nil || got.ID != 7 {
		t.Fatalf("create: %v %v", got, err)
	}
}
func TestTagPaginationAndRenameIdentity(t *testing.T) {
	calls := 0
	c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if len(q) != 2 || q.Get("pageSize") != "100" {
			t.Error("list must be unfiltered")
		}
		tags := []Tag{}
		if q.Get("page") == "0" {
			for i := int64(1); i <= 100; i++ {
				tags = append(tags, Tag{ID: i, Name: fmt.Sprintf("tag-%d", i), Scope: "", Type: "ALGOSEC"})
			}
		} else {
			tags = append(tags, Tag{ID: 101, Name: "External rename", Scope: "", Type: "ALGOSEC"})
		}
		json.NewEncoder(w).Encode(tags)
	})
	got, err := c.Get(context.Background(), 101)
	if err != nil || got.Name != "External rename" || calls != 2 {
		t.Fatalf("ID read %v %v calls=%d", got, err, calls)
	}
}
func TestTagDeleteRequiresLoadedExactIdentity(t *testing.T) {
	for _, details := range []string{`[]`, `[{"id":8,"name":"Finance","scope":"","type":"ALGOSEC","relations":[]}]`, `[{"id":7,"name":"Finance","scope":"","type":"ALGOSEC"}]`, `[{"id":7,"name":"Finance","scope":"","type":"ALGOSEC","relations":[{"hostgroup":"web","deviceDataId":2,"tagId":7}]}]`} {
		t.Run(details, func(t *testing.T) {
			writes := 0
			c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					writes++
					return
				}
				if r.URL.Path == "/afa/api/v1/tags/details" {
					if r.URL.Query().Get("includeAssociations") != "true" || !r.URL.Query().Has("scope") {
						t.Error("associations not requested")
					}
					fmt.Fprint(w, details)
				} else {
					fmt.Fprint(w, `[{"id":7,"name":"Finance","scope":"","type":"ALGOSEC","relations":[]}]`)
				}
			})
			if err := c.Delete(context.Background(), 7); err == nil || writes != 0 {
				t.Fatalf("unsafe delete err=%v writes=%d", err, writes)
			}
		})
	}
}
func TestTagRenameEmptyAcknowledgementIsExact200(t *testing.T) {
	for _, status := range []int{200, 201, 202, 204, 401, 409} {
		for _, body := range []string{"", `{}`, `null`} {
			t.Run(fmt.Sprintf("%d/%s", status, body), func(t *testing.T) {
				c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); fmt.Fprint(w, body) })
				err := c.Rename(context.Background(), 7, "Finance")
				if (err == nil) != (status == 200 && body == "") {
					t.Fatalf("ack err=%v", err)
				}
			})
		}
	}
}
func TestTagRejectInvalidBeforeRequest(t *testing.T) {
	c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Fatal("invalid input reached network") })
	for _, v := range [][2]string{{"", ""}, {" Finance", ""}, {"Finance", " scope "}, {"Finance\n", ""}} {
		if _, err := c.Create(context.Background(), v[0], v[1]); err == nil {
			t.Fatal("invalid accepted")
		}
	}
	if err := c.Rename(context.Background(), 0, "Finance"); err == nil {
		t.Fatal("invalid id")
	}
	if _, err := NewTagClient(c.c, false).Get(context.Background(), 7); err == nil {
		t.Fatal("opt-in bypass")
	}
}

func TestTagRejectAmbiguousJSON(t *testing.T) {
	for _, body := range []string{`{"id":8,"id":7,"name":"Finance","scope":"","type":"ALGOSEC"}`, `{"id":7,"name":"Finance","scope":null,"type":"ALGOSEC"}`, `{"id":7,"name":"Finance","scope":"","type":"ALGOSEC","error":"failure"}`} {
		t.Run(body, func(t *testing.T) {
			c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := c.Create(context.Background(), "Finance", ""); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}
