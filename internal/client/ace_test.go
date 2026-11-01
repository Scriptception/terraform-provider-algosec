// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All values and local HTTPS responses are synthetic.
func aceFixture(t *testing.T, h http.HandlerFunc) *ACEClient {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, e := NewACEClient(s.URL, "synthetic-token", time.Second, false, true)
	if e != nil {
		t.Fatal(e)
	}
	c.http.Transport = s.Client().Transport
	return c
}
func TestACEEmailOwnership(t *testing.T) {
	emails := []string{}
	writes := 0
	ack := true
	c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prevasio/api/v1/configurations/integrations/cd-mitigation" || r.URL.Query().Get("provider") != "aws" || r.Header.Get("Authorization") != "Bearer synthetic-token" || r.Header.Get("Cookie") != "" {
			t.Error("incorrect boundary")
		}
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"threatManagement": map[string]any{"enabled": true, "minimumSeverityLevel": 0}, "violationNotifications": map[string]any{"emails": emails}}})
			return
		}
		if r.Method != "PATCH" {
			t.Error("incorrect method")
		}
		writes++
		var in map[string]map[string][]string
		if json.NewDecoder(r.Body).Decode(&in) != nil || len(in) != 1 || len(in["violationNotifications"]) != 1 || in["violationNotifications"]["emails"] == nil {
			t.Error("nonselective write")
		}
		emails = in["violationNotifications"]["emails"]
		if ack {
			w.Write([]byte(`{"data":{"message":"Your CD mitigation settings were successfully updated."}}`))
		} else {
			w.Write([]byte(`{"data":{"message":"OK"}}`))
		}
	})
	ctx := context.Background()
	want := []string{"alerts@example.invalid"}
	if e := c.CreateCDEmails(ctx, "aws", want); e != nil {
		t.Fatal(e)
	}
	if got, e := c.CDEmails(ctx, "aws"); e != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, e)
	}
	if e := c.CreateCDEmails(ctx, "aws", want); e == nil || writes != 1 {
		t.Fatal("adopted preexisting")
	}
	if e := c.ChangeCDEmails(ctx, "aws", want, []string{}); e != nil {
		t.Fatal(e)
	}
	ack = false
	if e := c.CreateCDEmails(ctx, "aws", want); e == nil {
		t.Fatal("unconfirmed ownership")
	}
	before := writes
	if e := c.ChangeCDEmails(ctx, "aws", []string{"other@example.invalid"}, []string{}); e == nil || writes != before {
		t.Fatal("deleted concurrent set")
	}
}
func TestACEReadFailsClosed(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"data":null}`, `{"data":{"violationNotifications":{"emails":[]}}}`, `{"data":{"threatManagement":{"enabled":true,"minimumSeverityLevel":0},"violationNotifications":{"emails":null}}}`, `{"data":{"threatManagement":{"enabled":true,"minimumSeverityLevel":0},"violationNotifications":{"emails":[null]}}}`} {
		t.Run(body, func(t *testing.T) {
			c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
			if _, e := c.CDEmails(context.Background(), "aws"); e == nil || errors.Is(e, ErrNotFound) {
				t.Fatal("accepted incomplete read")
			}
		})
	}
	for _, status := range []int{204, 301, 401, 403, 404, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/other")
				w.WriteHeader(status)
			})
			if _, e := c.CDEmails(context.Background(), "aws"); e == nil || errors.Is(e, ErrNotFound) || calls != 1 {
				t.Fatal("unsafe HTTP handling")
			}
		})
	}
}
func TestACESecurityBoundary(t *testing.T) {
	ctx := context.Background()
	calls := 0
	c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(403)
		w.Write([]byte(`{"error":"synthetic-private-value"}`))
	})
	c.enabled = false
	if _, e := c.CDEmails(ctx, "aws"); e == nil || calls != 0 {
		t.Fatal("experimental gate bypass")
	}
	c.enabled = true
	c.readOnly = true
	if e := c.patchCDEmails(ctx, "aws", []string{}); e == nil || calls != 0 {
		t.Fatal("read-only bypass")
	}
	c.readOnly = false
	if _, e := c.CDEmails(ctx, "aws"); e == nil || strings.Contains(e.Error(), "synthetic-private-value") || strings.Contains(e.Error(), c.base) {
		t.Fatal("unsafe diagnostics")
	}
	for _, origin := range []string{"http://example.invalid", "https://user:password@example.invalid", "https://example.invalid/prevasio", "https://example.invalid/?token=bad"} {
		if _, e := NewACEClient(origin, "synthetic-token", time.Second, false, true); e == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
	for _, token := range []string{"", "synthetic token", "synthetic\nsecret", "synthetic\x7f"} {
		if _, e := NewACEClient("https://example.invalid", token, time.Second, false, true); e == nil {
			t.Fatal("invalid token")
		}
	}
	// Trusted fixture transport above is distinct from the default verified transport.
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS request reached handler") }))
	defer untrusted.Close()
	u, e := NewACEClient(untrusted.URL, "synthetic-token", time.Second, false, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = u.CDEmails(ctx, "aws"); e == nil || strings.Contains(e.Error(), untrusted.URL) {
		t.Fatal("TLS verification or sanitization failed")
	}
}
func TestACEAcknowledgementsFailClosed(t *testing.T) {
	for _, b := range []string{`null`, `{}`, `{"data":null}`, `{"data":{}}`, `{"data":{"message":null}}`, `{"data":{"message":"OK"}}`, `{"data":{"message":"expected"},"error":"partial"}`, `{"data":{"message":"expected","failed":["synthetic"]}}`, `{"data":{"message":"expected","message":"expected"}}`, `{"data":{"message":"expected","meſſage":"expected"}}`, `{"data":{"message":"expected"}} {}`} {
		if e := aceAck([]byte(b), "expected"); e == nil {
			t.Fatal("accepted malformed/partial acknowledgement")
		}
	}
}
func TestACESerializedPayloadLimit(t *testing.T) {
	if e := ValidateACESerializedPayload(map[string]string{"description": "small"}); e != nil {
		t.Fatal(e)
	}
	if e := ValidateACESerializedPayload(map[string]string{"description": strings.Repeat("<", maxBody)}); e == nil {
		t.Fatal("accepted an oversized escaped JSON payload")
	}
}
func TestACEWriteTransportNeverReplayed(t *testing.T) {
	calls := 0
	c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		conn, _, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error(e)
			return
		}
		conn.Close()
	})
	if e := c.patchCDEmails(context.Background(), "aws", []string{"test@example.invalid"}); e == nil || calls != 1 {
		t.Fatal("ambiguous write replayed or accepted")
	}
}
