// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// All sessions, principals and permissions in these fixtures are synthetic.
func fireFlowFixture(t *testing.T, h http.HandlerFunc) *FireFlowClient {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, err := NewFireFlowClient(s.URL, "synthetic-session", time.Second, false, true)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	c.http.Transport.(*http.Transport).TLSClientConfig.RootCAs = roots
	return c
}
func TestFireFlowMemberDelta(t *testing.T) {
	for _, kind := range []string{"User", "Role"} {
		for _, add := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/%v", kind, add), func(t *testing.T) {
				c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) {
					cookie, err := r.Cookie("FireFlow_Session")
					if err != nil || cookie.Value != "synthetic-session" || r.Header.Get("Authorization") != "" {
						t.Error("wrong auth boundary")
					}
					if r.URL.Path != "/FireFlow/api/roles/7/members" || r.Method != "POST" {
						t.Error("wrong route")
					}
					var body struct {
						Add    []FireFlowMemberRef `json:"addMembers"`
						Remove []FireFlowMemberRef `json:"removeMembers"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Fatal("invalid delta")
					}
					target, other := body.Add, body.Remove
					if !add {
						target, other = body.Remove, body.Add
					}
					if len(target) != 1 || target[0].ID != 8 || target[0].Type != kind || other == nil || len(other) != 0 {
						t.Error("not exact singleton delta")
					}
					fmt.Fprint(w, `{"status":"Success","messages":[],"data":null}`)
				})
				if err := c.ChangeMember(context.Background(), 7, FireFlowMemberRef{ID: 8, Type: kind}, add); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestFireFlowMutationAcknowledgements(t *testing.T) {
	for _, family := range []string{"member", "permission"} {
		for _, body := range []string{`{}`, `null`, `{"status":"Failure","messages":[],"data":null}`, `{"status":"PartiallySuccess","messages":[],"data":null}`, `{"status":"Success","messages":[{"code":"USER_DISABLED"}],"data":null}`, `{"status":"Success","data":null}`, `{"status":"Success","messages":[],"data":null}`, `{"status":"Success","messages":[],"data":{}}`} {
			t.Run(family+body, func(t *testing.T) {
				writes := 0
				c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) { writes++; fmt.Fprint(w, body) })
				var err error
				if family == "member" {
					err = c.ChangeMember(context.Background(), 7, FireFlowMemberRef{ID: 8, Type: "User"}, true)
				} else {
					err = c.ChangePermission(context.Background(), 7, FireFlowPermissionRef{Name: "SeeRole", ObjectType: "System", ObjectID: 0}, true)
				}
				wanted := family == "member" && body == `{"status":"Success","messages":[],"data":null}` || family == "permission" && body == `{"status":"Success","messages":[],"data":{}}`
				if (err == nil) != wanted || writes != 1 {
					t.Fatalf("ack err=%v writes=%d", err, writes)
				}
			})
		}
	}
}
func TestFireFlowDirectMemberRead(t *testing.T) {
	for _, body := range []string{`{"status":"Success","messages":[],"data":[{"id":8,"name":"Example","type":"User","isDirectMember":true}]}`, `{"status":"Success","messages":[],"data":[{"id":8,"name":"Example","type":"User"}]}`, `{"status":"Success","messages":[],"data":null}`, `{"status":"PartiallySuccess","messages":[],"data":[]}`} {
		t.Run(body, func(t *testing.T) {
			c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("fetchIndirect") != "false" {
					t.Error("indirect read requested")
				}
				fmt.Fprint(w, body)
			})
			rows, err := c.Members(context.Background(), 7)
			valid := body == `{"status":"Success","messages":[],"data":[{"id":8,"name":"Example","type":"User","isDirectMember":true}]}`
			if (err == nil) != valid {
				t.Fatal("read contract", err)
			}
			if valid && (len(rows) != 1 || !rows[0].Direct) {
				t.Fatal("lost direct flag")
			}
		})
	}
}
func TestFireFlowPermissionReadSeparatesInherited(t *testing.T) {
	c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"Success","messages":[],"data":{"system":[{"permissionName":"SeeRole","objectType":"System","objectId":0,"direct":false,"inherited":true}],"customField":[],"requestTemplate":[]}}`)
	})
	rows, err := c.Permissions(context.Background(), 7)
	if err != nil || len(rows) != 1 || rows[0].Direct || !rows[0].Inherited {
		t.Fatalf("direct/inherited conflated %v %v", rows, err)
	}
}
func TestFireFlowPrevalidate(t *testing.T) {
	c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid input reached API") })
	for _, m := range []FireFlowMemberRef{{ID: 7, Type: "Role"}, {ID: 0, Type: "User"}, {ID: 8, Type: "Invalid"}} {
		if err := c.ChangeMember(context.Background(), 7, m, true); err == nil {
			t.Fatal("invalid member")
		}
	}
	for _, p := range []FireFlowPermissionRef{{Name: "SeeRole", ObjectType: "System", ObjectID: 1}, {Name: "SeeRole", ObjectType: "CustomField", ObjectID: 0}, {Name: "", ObjectType: "System", ObjectID: 0}} {
		if err := c.ChangePermission(context.Background(), 7, p, true); err == nil {
			t.Fatal("invalid permission")
		}
	}
}

func TestFireFlowPermissionDelta(t *testing.T) {
	for _, kind := range []string{"System", "CustomField", "RequestTemplate"} {
		for _, add := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/%v", kind, add), func(t *testing.T) {
				id := int64(0)
				if kind != "System" {
					id = 12
				}
				p := FireFlowPermissionRef{Name: "Synthetic permission", ObjectType: kind, ObjectID: id}
				c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) {
					var body struct {
						Add    []FireFlowPermissionRef `json:"addPermissions"`
						Remove []FireFlowPermissionRef `json:"removePermissions"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						t.Fatal("bad payload")
					}
					target, other := body.Add, body.Remove
					if !add {
						target, other = body.Remove, body.Add
					}
					if len(target) != 1 || target[0] != p || other == nil || len(other) != 0 {
						t.Fatal("changed unrelated permission", body)
					}
					fmt.Fprint(w, `{"status":"Success","messages":[],"data":{}}`)
				})
				if err := c.ChangePermission(context.Background(), 7, p, add); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestFireFlowPermissionMalformedAndDuplicates(t *testing.T) {
	base := `{"status":"Success","messages":[],"data":{"system":[{"permissionName":"SeeRole","objectType":"System","objectId":0,"direct":true,"inherited":false}],"customField":[],"requestTemplate":[]}}`
	for _, body := range []string{strings.Replace(base, `"direct":true,`, "", 1), strings.Replace(base, `"inherited":false`, `"inherited":null`, 1), strings.Replace(base, `"objectId":0,`, "", 1), strings.Replace(base, `"system":[`, `"system":null,"system":[`, 1), strings.Replace(base, `"customField":[]`, `"customField":null`, 1), strings.Replace(base, `"objectType":"System"`, `"objectType":"CustomField"`, 1)} {
		t.Run(body, func(t *testing.T) {
			c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if _, err := c.Permissions(context.Background(), 7); err == nil {
				t.Fatal("malformed permissions accepted")
			}
		})
	}
}
func TestFireFlowTransportBoundaries(t *testing.T) {
	for _, status := range []int{201, 202, 204, 301, 401, 403, 404, 409, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			requests := 0
			c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Location", "https://example.invalid")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"status":"Success","messages":[],"data":null}`)
			})
			if err := c.ChangeMember(context.Background(), 7, FireFlowMemberRef{ID: 8, Type: "User"}, true); err == nil || requests != 1 {
				t.Fatal("failed write replayed or accepted", err, requests)
			}
		})
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted endpoint called") }))
	defer s.Close()
	c, err := NewFireFlowClient(s.URL, "synthetic", time.Second, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Members(context.Background(), 7); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	c = fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("disabled mutation reached network") })
	c.readOnly = true
	if err = c.ChangeMember(context.Background(), 7, FireFlowMemberRef{ID: 8, Type: "User"}, true); err == nil {
		t.Fatal("read_only bypass")
	}
	c.enabled = false
	if _, err = c.Members(context.Background(), 7); err == nil {
		t.Fatal("opt-in bypass")
	}
}

func TestFireFlowAmbiguousWriteNoReplay(t *testing.T) {
	writes := 0
	c := fireFlowFixture(t, func(w http.ResponseWriter, r *http.Request) {
		writes++
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	})
	if err := c.ChangeMember(context.Background(), 7, FireFlowMemberRef{ID: 8, Type: "User"}, true); err == nil || writes != 1 {
		t.Fatalf("ambiguous write err=%v writes=%d", err, writes)
	}
}

func TestFireFlowIgnoresAFAInsecure(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted FireFlow endpoint contacted") }))
	defer s.Close()
	c, err := New(Options{FireFlowURL: s.URL, FireFlowSession: "synthetic", ExperimentalFireFlowBindings: true, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.FireFlow.Members(context.Background(), 7); err == nil {
		t.Fatal("AFA insecure disabled FireFlow TLS verification")
	}
}
