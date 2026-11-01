// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Synthetic contract fixtures, never appliance responses.
const roleFixture = `{"name":"Test Role","enabled":true,"roleUsers":["alice"],"authorizedViewsAndActions":[{"name":"viewAllApplications","allowed":true}],"authorizedApplications":[{"applicationID":12,"name":"Example","permission":"view"}]}`

func roleClient(t *testing.T, h http.HandlerFunc) (*AppVizClient, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, e := NewAppVizClient(s.URL, "synthetic-token", 30e9, false, true)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	c.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return c, s
}
func TestAppVizRoleAcknowledgement(t *testing.T) {
	for _, body := range []string{roleFixture + `{}`, `{}`, `null`, `false`, `{"success":false}`, `{"name":"Test Role"}`, `{"name":"other","enabled":true,"roleUsers":[],"authorizedViewsAndActions":[],"authorizedApplications":[]}`, `{"name":"Test Role","name":"other"}`} {
		t.Run(body, func(t *testing.T) {
			reads, writes := 0, 0
			c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					reads++
					w.WriteHeader(404)
					return
				}
				writes++
				fmt.Fprint(w, body)
			})
			got, e := c.CreateRole(context.Background(), AppVizRole{Name: "Test Role", Enabled: true, Users: []string{}, Permissions: []string{}, Applications: map[string]string{}})
			if e == nil || got != nil || reads != 1 || writes != 1 {
				t.Fatalf("unconfirmed create acquired identity or read back: got=%v err=%v reads=%d writes=%d", got, e, reads, writes)
			}
		})
	}
}
func TestAppVizRoleReadFailClosed(t *testing.T) {
	for _, status := range []int{204, 400, 401, 403, 404, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
			_, e := c.Role(context.Background(), "Test Role")
			if e == nil || errors.Is(e, ErrNotFound) != (status == 404) {
				t.Fatalf("status %d: %v", status, e)
			}
		})
	}
	for _, body := range []string{roleFixture + `{}`, `{}`, `null`, `{"name":"Test Role","enabled":true,"roleUsers":null,"authorizedViewsAndActions":[],"authorizedApplications":[]}`, `{"name":"Test Role","enabled":true,"roleUsers":[],"authorizedViewsAndActions":[],"authorizedApplications":[],"nextPage":2}`} {
		t.Run(body, func(t *testing.T) {
			c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			_, e := c.Role(context.Background(), "Test Role")
			if e == nil || errors.Is(e, ErrNotFound) {
				t.Fatal("incomplete read accepted", e)
			}
		})
	}
}

func TestAppVizTransportAndOwnership(t *testing.T) {
	for _, mode := range []string{"existing", "readonly", "gate", "redirect", "ambiguous", "positive"} {
		t.Run(mode, func(t *testing.T) {
			reads, writes := 0, 0
			c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-token" || r.Header.Get("Cookie") != "" {
					t.Error("mixed authentication")
				}
				if r.Method == "GET" {
					reads++
					if mode == "existing" {
						fmt.Fprint(w, roleFixture)
					} else {
						w.WriteHeader(404)
					}
					return
				}
				writes++
				switch mode {
				case "redirect":
					w.Header().Set("Location", "https://example.invalid")
					w.WriteHeader(307)
				case "ambiguous":
					conn, _, e := w.(http.Hijacker).Hijack()
					if e != nil {
						t.Error(e)
						return
					}
					conn.Close()
				default:
					fmt.Fprint(w, roleFixture)
				}
			})
			c.readOnly = mode == "readonly"
			c.enabled = mode != "gate"
			got, e := c.CreateRole(context.Background(), AppVizRole{Name: "Test Role", Enabled: true, Users: []string{"alice"}, Permissions: []string{"viewAllApplications"}, Applications: map[string]string{"12": "view"}})
			if mode == "positive" {
				if e != nil || got == nil {
					t.Fatal("positive acknowledgement rejected", e)
				}
			} else if e == nil || got != nil {
				t.Fatal("unsafe ownership")
			}
			if reads > 1 || writes > 1 {
				t.Fatal("replayed request", reads, writes)
			}
			if (mode == "gate" && reads != 0) || ((mode == "gate" || mode == "readonly" || mode == "existing") && writes != 0) {
				t.Fatal("safety gate issued mutation")
			}
		})
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS reached handler") }))
	defer s.Close()
	c, e := NewAppVizClient(s.URL, "synthetic-token", 30e9, false, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Role(context.Background(), "Test Role"); e == nil {
		t.Fatal("TLS verification disabled")
	}
}
func TestAppVizRoleDeleteIntegrity(t *testing.T) {
	for _, mode := range []string{"ok", "still_exists", "denied", "unconfirmed", "different", "absent"} {
		t.Run(mode, func(t *testing.T) {
			reads, writes := 0, 0
			c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					reads++
					if mode == "absent" || reads > 1 && mode == "ok" {
						w.WriteHeader(404)
						return
					}
					if reads > 1 && mode == "denied" {
						w.WriteHeader(403)
						return
					}
					fmt.Fprint(w, roleFixture)
					return
				}
				writes++
				if mode == "unconfirmed" {
					fmt.Fprint(w, `{}`)
				} else {
					fmt.Fprint(w, `{"body":{},"statusCode":"OK","statusCodeValue":200}`)
				}
			})
			old := AppVizRole{Name: "Test Role", Enabled: true, Users: []string{"alice"}, Permissions: []string{"viewAllApplications"}, Applications: map[string]string{"12": "view"}}
			if mode == "different" {
				old.Users = []string{}
			}
			e := c.DeleteRole(context.Background(), old)
			if (e == nil) != (mode == "ok" || mode == "absent") {
				t.Fatal("incorrect deletion result", mode, e)
			}
			if mode == "different" && writes != 0 {
				t.Fatal("deleted changed role")
			}
			if mode == "unconfirmed" && reads != 1 {
				t.Fatal("read after unconfirmed deletion")
			}
		})
	}
}
func TestAppVizRoleMalformedFields(t *testing.T) {
	for _, body := range []string{
		`{"name":"Test Role","enabled":true,"roleUsers":["alice","alice"],"authorizedViewsAndActions":[],"authorizedApplications":[]}`,
		`{"name":"Test Role","enabled":true,"roleUsers":[],"authorizedViewsAndActions":[{"name":"x","allowed":true},{"name":"x","allowed":false}],"authorizedApplications":[]}`,
		`{"name":"Test Role","enabled":true,"roleUsers":[],"authorizedViewsAndActions":[],"authorizedApplications":[{"applicationID":12,"name":"x","permission":"admin"}]}`,
		`{"name":"Test Role","enabled":true,"roleUsers":[],"authorizedViewsAndActions":[],"authorizedApplications":[],"errors":{"failure":"synthetic"}}`,
	} {
		c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, e := c.Role(context.Background(), "Test Role"); e == nil {
			t.Fatal("accepted malformed permission state")
		}
	}
}
