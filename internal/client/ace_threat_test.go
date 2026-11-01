// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"testing"
)

func TestACEThreatPagination(t *testing.T) {
	for _, mode := range []string{"complete", "duplicate", "missing", "totals", "null"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				p, _ := strconv.Atoi(r.URL.Query().Get("page"))
				if r.URL.Query().Get("listType") != "block-list" {
					t.Error("list scope")
				}
				v := []map[string]string{{"destination": "one", "description": "synthetic", "severity": "high"}}
				if p == 2 && mode != "duplicate" {
					v[0]["destination"] = "two"
				}
				if mode == "missing" {
					delete(v[0], "description")
				}
				total := 2
				if mode == "totals" && p == 2 {
					total = 3
				}
				if mode == "null" {
					v = nil
				}
				json.NewEncoder(w).Encode(map[string]any{"data": v, "page": map[string]int{"current": p, "limit": 1, "total": total, "totalItems": 2}})
			})
			got, e := c.ThreatEntry(context.Background(), "domains", "block-list", "two")
			if mode == "complete" {
				if e != nil || got.Destination != "two" || calls != 2 {
					t.Fatal("pagination", e)
				}
			} else if e == nil || errors.Is(e, ErrNotFound) {
				t.Fatal("incomplete visibility accepted")
			}
		})
	}
}
func TestACEThreatOwnership(t *testing.T) {
	var current *ACEThreatEntry
	writes := 0
	ack := true
	c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			v := []any{}
			if current != nil {
				v = append(v, map[string]string{"destination": current.Destination, "description": current.Description, "severity": current.Severity})
			}
			json.NewEncoder(w).Encode(map[string]any{"data": v, "page": map[string]int{"current": 1, "limit": 1000, "total": 1, "totalItems": len(v)}})
		case "POST":
			writes++
			var v struct{ Destination, Description, Severity string }
			json.NewDecoder(r.Body).Decode(&v)
			current = &ACEThreatEntry{"domains", "block-list", v.Destination, v.Description, v.Severity}
			message := "Successfully added example.invalid entry to block-list for threat - domains."
			if !ack {
				message = "OK"
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"message": message}})
		case "DELETE":
			if r.URL.Query().Get("destination") != "example.invalid" {
				t.Error("bulk deletion")
			}
			writes++
			current = nil
			w.Write([]byte(`{"data":{"message":"Successfully deleted example.invalid from the block-list of threat type domains."}}`))
		}
	})
	v := ACEThreatEntry{"domains", "block-list", "example.invalid", "synthetic", "high"}
	ctx := context.Background()
	if e := c.CreateThreatEntry(ctx, v); e != nil {
		t.Fatal(e)
	}
	if e := c.CreateThreatEntry(ctx, v); e == nil || writes != 1 {
		t.Fatal("adopted")
	}
	if e := c.DeleteThreatEntry(ctx, v); e != nil {
		t.Fatal(e)
	}
	ack = false
	if e := c.CreateThreatEntry(ctx, v); e == nil {
		t.Fatal("unconfirmed create")
	}
	v.Destination = ""
	before := writes
	if e := c.DeleteThreatEntry(ctx, v); e == nil || writes != before {
		t.Fatal("bulk deletion")
	}
}
