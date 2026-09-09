// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// Synthetic URL/IP delta contract; other URLs and IPs are never owned.
func TestURLIPExactAcknowledgement(t *testing.T) {
	for _, method := range []string{"PUT", "DELETE"} {
		for _, body := range []string{`{}`, `{"categories":{}}`, `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1","192.0.2.2"],"other.example":[]}}}}`, `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.2"],"other.example":[]}}}}`} {
			t.Run(method+body, func(t *testing.T) {
				c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method != method || r.URL.Path != "/afa/api/v1/plugins/panorama/URLCategory/Example/URL/www.example.com/IP/" {
						t.Error("wrong delta route")
					}
					var ips []string
					if json.NewDecoder(r.Body).Decode(&ips) != nil || len(ips) != 1 || ips[0] != "192.0.2.1" {
						t.Error("not singleton delta")
					}
					fmt.Fprint(w, body)
				})
				ip := NewURLIPClient(c.c, true)
				err := ip.Change(context.Background(), "Example", "www.example.com", "192.0.2.1", method == "PUT")
				want := method == "PUT" && body == `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1","192.0.2.2"],"other.example":[]}}}}` || method == "DELETE" && body == `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.2"],"other.example":[]}}}}`
				if (err == nil) != want {
					t.Fatalf("ack err=%v want success=%v", err, want)
				}
			})
		}
	}
}
func TestURLIPPrevalidate(t *testing.T) {
	c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid input reached network") })
	ip := NewURLIPClient(c.c, true)
	for _, v := range []string{"192.0.2.1/32", "not-ip", "192.0.2.01", ""} {
		if err := ip.Change(context.Background(), "Example", "www.example.com", v, true); err == nil {
			t.Fatal("invalid IP")
		}
	}
	if err := NewURLIPClient(c.c, false).Change(context.Background(), "Example", "www.example.com", "192.0.2.1", true); err == nil {
		t.Fatal("gate bypass")
	}
}
