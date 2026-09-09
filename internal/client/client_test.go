// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// All payloads in this file are SYNTHETIC contract fixtures, never live captures.
func fixture(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, err := New(Options{URL: s.URL, SessionID: "syntheticSecret", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestURLValidation(t *testing.T) {
	for _, s := range []string{"http://example.invalid", "https://u:p@example.invalid", "https://example.invalid/afa", "https://example.invalid?secret=x", "https://example.invalid#x", "https://example.invalid?", "https:///", "//example.invalid", "https://example.invalid:bad", "https://example.invalid:0", "https://example.invalid:65536"} {
		if ValidateURL(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range []string{"https://example.invalid", "https://example.invalid:8443/", "https://[::1]:8443"} {
		if err := ValidateURL(s); err != nil {
			t.Errorf("rejected %q", s)
		}
	}
}
func TestOptions(t *testing.T) {
	for _, o := range []Options{{URL: "https://example.invalid"}, {URL: "https://example.invalid", Username: "u"}, {URL: "https://example.invalid", SessionID: "bad;cookie"}, {URL: "https://example.invalid", SessionID: "valid", Password: "p"}, {URL: "https://example.invalid", SessionID: "valid", Timeout: -time.Second}, {URL: "https://example.invalid", SessionID: "valid", Timeout: 301 * time.Second}} {
		if _, err := New(o); err == nil {
			t.Error("accepted invalid options")
		}
	}
}
func TestEscapedIdentifiers(t *testing.T) {
	name := "group/a b?x#%雪"
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/afa/api/v1/devices/group%2Fa%20b%3Fx%23%25%E9%9B%AA" {
			t.Errorf("unexpected escaped path %q", r.URL.EscapedPath())
		}
		if r.URL.RawQuery != "" {
			t.Error("identifier became query")
		}
		fmt.Fprint(w, `{"httpStatus":"200"}`)
	})
	part, err := Segment(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.do(context.Background(), "GET", api+"/devices/"+part, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", ".", "..", "x\ny"} {
		if _, err := Segment(s); err == nil {
			t.Error("accepted invalid segment")
		}
	}
}
func TestRedactionAndNoWriteRetry(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308, 400, 401, 403, 404, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			c := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "https://syntheticSecret.invalid/")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":"syntheticSecret"}`)
			})
			err := c.CreateCategory(context.Background(), "x", Category{URLs: map[string][]string{}})
			if err == nil || strings.Contains(err.Error(), "syntheticSecret") {
				t.Fatal("error not safely redacted")
			}
			if calls != 1 {
				t.Fatalf("write replayed %d times", calls)
			}
		})
	}
}
func TestRedirectNeverContactsTarget(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	if _, err := c.Categories(context.Background()); err == nil {
		t.Fatal("redirect accepted")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect target contacted")
	}
}
func TestTLSVerifiedByDefault(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"categories":{}}`) }))
	defer s.Close()
	c, err := New(Options{URL: s.URL, SessionID: "valid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Categories(context.Background()); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
func TestLoginConcurrency(t *testing.T) {
	var logins atomic.Int64
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fa/server/connection/login" {
			logins.Add(1)
			var b map[string]string
			_ = json.NewDecoder(r.Body).Decode(&b)
			if b["username"] != "test" || b["password"] != "syntheticSecret" {
				t.Error("wrong login payload")
			}
			fmt.Fprint(w, `{"status":true,"SessionID":"session123"}`)
			return
		}
		ck, err := r.Cookie("PHPSESSID")
		if err != nil || ck.Value != "session123" {
			t.Error("wrong session cookie")
		}
		if strings.Contains(r.URL.RawQuery, "session") {
			t.Error("session leaked to URL")
		}
		fmt.Fprint(w, `{"categories":{}}`)
	}))
	defer s.Close()
	c, err := New(Options{URL: s.URL, Username: "test", Password: "syntheticSecret", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, err := c.Categories(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if logins.Load() != 1 {
		t.Fatal("concurrent login duplication")
	}
}
func TestLoginFailures(t *testing.T) {
	for _, body := range []string{`{}`, `{"status":false,"message":"syntheticSecret"}`, `{"status":true,"SessionID":"bad;cookie"}`, `null`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer s.Close()
			c, _ := New(Options{URL: s.URL, Username: "u", Password: "syntheticSecret", Insecure: true})
			_, err := c.Categories(context.Background())
			if err == nil || strings.Contains(err.Error(), "syntheticSecret") {
				t.Fatal("unsafe login failure")
			}
		})
	}
}
func TestReadOnlyBeforeAuthentication(t *testing.T) {
	c, _ := New(Options{URL: "https://example.invalid", Username: "u", Password: "p", ReadOnly: true})
	err := c.CreateCategory(context.Background(), "x", Category{URLs: map[string][]string{}})
	if err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatal("write not blocked before login")
	}
}
func TestMalformedCategoryResponses(t *testing.T) {
	for _, body := range []string{"", `null`, `{}`, `[]`, `{"categories":null}`, `{"categories":{"x":{}}}`, `{"categories":{"x":{"urls":{"a":null}}}}`, `{"categories":{"x":{"urls":{"a":["invalid"]}}}}`, `{"categories":{"x":{"urls":{"a":["192.0.2.1","192.0.2.1"]}}}}`, `{"status":false,"categories":{}}`, `{"httpStatus":"500","categories":{}}`, `{"error":"syntheticSecret","categories":{}}`, `{"categories":{}} trailing`} {
		t.Run(body, func(t *testing.T) {
			c := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			_, err := c.Categories(context.Background())
			if err == nil || errors.Is(err, ErrNotFound) {
				t.Fatal("malformed response mistaken for absence")
			}
		})
	}
}
func TestDefinitiveAbsence(t *testing.T) {
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"categories":{}}`) })
	if _, err := c.Category(context.Background(), "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
func TestCancellation(t *testing.T) {
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := c.Categories(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline, got %v", err)
	}
}
func TestBodyBound(t *testing.T) {
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat(" ", maxBody+1)) })
	if _, err := c.Categories(context.Background()); err == nil {
		t.Fatal("oversize accepted")
	}
}
func TestDeviceSecretDiscard(t *testing.T) {
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[{"name":"test","passwd":"syntheticSecret","api_token":"syntheticSecret","root_psw":"syntheticSecret"}]`)
	})
	v, err := c.Devices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "syntheticSecret") {
		t.Fatal("secret retained")
	}
}
func TestSecurityZoneResponseVariants(t *testing.T) {
	for _, body := range []string{`[{"name":"x","addresses":[]}]`, `{"status":true,"data":[{"name":"x","addresses":[]}]}`, `{"status":"true","data":[{"name":"x","addresses":[]}]}`} {
		c := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		v, err := c.SecurityZones(context.Background(), "x.xlsx")
		if err != nil || len(v) != 1 {
			t.Fatalf("variant failed: %v", err)
		}
	}
}
func TestPagination(t *testing.T) {
	c := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("deviceName") != "a/b?c" || r.URL.Query().Get("query") != "a&b" {
			t.Error("query not encoded")
		}
		n := r.URL.Query().Get("page")
		if n == "0" {
			fmt.Fprint(w, `{"content":[{"id":2}],"number":0,"totalPages":2,"totalElements":2,"last":false}`)
		} else {
			fmt.Fprint(w, `{"content":[{"id":1}],"number":1,"totalPages":2,"totalElements":2,"last":true}`)
		}
	})
	v, err := c.NetworkObjects(context.Background(), "a/b?c", "a&b")
	if err != nil || len(v) != 2 || v[0].ID != 1 {
		t.Fatalf("pagination failed %v", err)
	}
}
func TestPaginationRejectsTruncation(t *testing.T) {
	for _, body := range []string{`{}`, `{"content":[],"number":0,"totalPages":2,"totalElements":2,"last":false}`, `{"content":[{"id":1}],"number":0,"totalPages":1,"totalElements":2,"last":true}`, `{"content":[{"id":1},{"id":1}],"number":0,"totalPages":1,"totalElements":2,"last":true}`, `{"content":[],"number":1,"totalPages":1,"totalElements":0,"last":true}`} {
		c := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := c.NetworkObjects(context.Background(), "x", ""); err == nil {
			t.Fatal("bad pagination accepted")
		}
	}
}

func TestCancellationWaitingForLogin(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fa/server/connection/login" {
			close(started)
			<-release
			fmt.Fprint(w, `{"status":true,"SessionID":"valid"}`)
			return
		}
		fmt.Fprint(w, `{"categories":{}}`)
	}))
	defer s.Close()
	c, err := New(Options{URL: s.URL, Username: "u", Password: "syntheticSecret", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.Categories(context.Background()); done <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = c.Categories(ctx)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiting login ignored cancellation: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Mutations must reject unsuccessful or unreadable synthetic acknowledgments.
func TestMutationResponseErrors(t *testing.T) {
	for _, body := range []string{" \n\t{\"status\":false}", " \r\n{\"error\":\"synthetic failure\"}", "", " \t", "null", "{", "not JSON", `{"status":false,"httpStatus":200}`} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			c := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			for _, call := range []func() error{
				func() error {
					return c.CreateCategory(context.Background(), "test", Category{URLs: map[string][]string{}})
				},
				func() error {
					return c.RenameCategory(context.Background(), "test", "new", Category{URLs: map[string][]string{}})
				},
				func() error { return c.DeleteCategory(context.Background(), "test") },
			} {
				if err := call(); err == nil {
					t.Fatal("mutation accepted unsuccessful response")
				}
			}
		})
	}
}

func TestCreateCategoryExactAcknowledgementMembership(t *testing.T) {
	for _, tc := range []struct {
		body string
		good bool
	}{
		{`{"categories":{"test":{"urls":{"example.invalid":["192.0.2.2","192.0.2.1"]}}}}`, true},
		{`{"categories":{"test":{"urls":{"example.invalid":["192.0.2.1"]}}}}`, false},
		{`{"categories":{"test":{"urls":{"example.invalid":["192.0.2.1","192.0.2.3"]}}}}`, false},
		{`{"categories":{"test":{"urls":{"wrong.invalid":["192.0.2.1","192.0.2.2"]}}}}`, false},
		{`{"categories":{"test":{"urls":{"example.invalid":["invalid"]}}}}`, false},
	} {
		c := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
		err := c.CreateCategory(context.Background(), "test", Category{URLs: map[string][]string{"example.invalid": {"192.0.2.1", "192.0.2.2"}}})
		if (err == nil) != tc.good {
			t.Fatalf("acknowledgement %s: %v", tc.body, err)
		}
	}
}
