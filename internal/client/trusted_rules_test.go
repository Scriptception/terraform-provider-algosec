// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// All responses are synthetic public-contract fixtures, not appliance captures.
func TestTrustedRuleCreateAcknowledgement(t *testing.T) {
	for _, ack := range []string{
		`{"trustedRuleIds":["r"],"failedRuleIds":[],"failureReasons":{}}`,
		`{}`, `{"trustedRuleIds":[]}`, `{"trustedRuleIds":["other"]}`,
		`{"trustedRuleIds":["r","r"]}`, `{"trustedRuleIds":["r"],"failedRuleIds":["r"]}`,
		`{"trustedRuleIds":["r"],"failureReasons":{"r":"secret"}}`,
		`{"trustedRuleIds":["r"],"error":"secret"}`,
	} {
		t.Run(ack, func(t *testing.T) {
			reads, writes := 0, 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/afa/api/v1/trusted-rules/rules" {
					t.Error(r.URL.Path)
				}
				cookie, e := r.Cookie("PHPSESSID")
				if e != nil || cookie.Value != "synthetic" {
					t.Error("cookie")
				}
				if r.Method == "GET" {
					reads++
					if r.URL.Query().Get("deviceNames") != "dev" {
						t.Error("query")
					}
					if reads == 1 {
						fmt.Fprint(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"Device","trustedRules":[]}]`)
					} else {
						fmt.Fprint(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"Device","trustedRules":[{"ruleId":"r","comment":"","expirationDate":""}]}]`)
					}
					return
				}
				writes++
				fmt.Fprint(w, ack)
			}))
			defer s.Close()
			c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
			c.http = s.Client()
			accepted := false
			got, err := c.CreateTrustedRule(context.Background(), "dev", TrustedRule{RuleID: "r"}, func() { accepted = true })
			good := ack == `{"trustedRuleIds":["r"],"failedRuleIds":[],"failureReasons":{}}`
			if good {
				if err != nil || !accepted || got == nil {
					t.Fatalf("positive create: %v", err)
				}
			} else if err == nil || accepted || got != nil || reads != 1 {
				t.Fatalf("unconfirmed adoption: reads=%d err=%v", reads, err)
			}
			if writes != 1 {
				t.Fatal(writes)
			}
		})
	}
}

func TestTrustedRuleDeleteAndReadIntegrity(t *testing.T) {
	ctx := context.Background()
	for _, body := range []string{`[]`, `null`, `{}`, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D"}]`, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":[{"ruleId":"r"}]}]`, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":[],"error":"denied"}]`} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
		c.http = s.Client()
		if _, e := c.TrustedRule(ctx, "dev", "r"); e == nil || e == ErrNotFound {
			t.Errorf("incomplete read accepted: %s", body)
		}
		s.Close()
	}
	deleted := false
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			deleted = true
			fmt.Fprint(w, `{"trustedRuleIds":["r"]}`)
			return
		}
		rules := `[{"ruleId":"r","comment":"owned","expirationDate":""}]`
		if deleted {
			rules = `[]`
		}
		fmt.Fprintf(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":%s}]`, rules)
	}))
	defer s.Close()
	c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
	c.http = s.Client()
	if e := c.DeleteTrustedRule(ctx, "dev", TrustedRule{RuleID: "r", Comment: "owned"}); e != nil || !deleted {
		t.Fatal(e)
	}
}

func TestTrustedRuleDuplicateJSON(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			fmt.Fprint(w, `{"trustedRuleIds":["other"],"trustedRuleIds":["r"]}`)
			return
		}
		fmt.Fprint(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":[]}]`)
	}))
	defer s.Close()
	c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
	c.http = s.Client()
	accepted := false
	c.CreateTrustedRule(context.Background(), "dev", TrustedRule{RuleID: "r"}, func() { accepted = true })
	if accepted {
		t.Fatal("duplicate response keys established ownership")
	}
}

func TestTrustedRuleRecoveryAndSafety(t *testing.T) {
	for _, mode := range []string{"existing", "read_denied", "readback_denied", "mismatch", "transport", "delete_denied", "delete_false_ack", "delete_still_present", "delete_drift", "expired", "disabled", "readonly"} {
		t.Run(mode, func(t *testing.T) {
			reads, writes := 0, 0
			accepted := false
			prior := TrustedRule{RuleID: "r", Comment: "owned"}
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					writes++
					if mode == "transport" {
						conn, _, _ := w.(http.Hijacker).Hijack()
						conn.Close()
						return
					}
					if mode == "delete_denied" {
						w.WriteHeader(403)
						return
					}
					if mode == "delete_false_ack" {
						fmt.Fprint(w, `{"trustedRuleIds":[],"failedRuleIds":["r"],"failureReasons":{"r":"secret"}}`)
						return
					}
					fmt.Fprint(w, `{"trustedRuleIds":["r"]}`)
					return
				}
				reads++
				if mode == "read_denied" || (mode == "readback_denied" && reads > 1) {
					w.WriteHeader(403)
					return
				}
				rules := `[]`
				if mode == "existing" || strings.HasPrefix(mode, "delete_") || reads > 1 {
					rules = `[{"ruleId":"r","comment":"owned","expirationDate":""}]`
				}
				if mode == "mismatch" && reads > 1 || mode == "delete_drift" {
					rules = `[{"ruleId":"r","comment":"external","expirationDate":""}]`
				}
				fmt.Fprintf(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":%s}]`, rules)
			}))
			defer s.Close()
			c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: mode != "disabled", ReadOnly: mode == "readonly"})
			c.http = s.Client()
			var err error
			if strings.HasPrefix(mode, "delete_") {
				err = c.DeleteTrustedRule(context.Background(), "dev", prior)
			} else {
				if mode == "expired" {
					prior.ExpirationDate = "2000-01-01"
				}
				_, err = c.CreateTrustedRule(context.Background(), "dev", prior, func() { accepted = true })
			}
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("expected safe failure: %v", err)
			}
			shouldAccept := mode == "readback_denied" || mode == "mismatch"
			if accepted != shouldAccept {
				t.Fatalf("ownership %t", accepted)
			}
			if writes > 1 {
				t.Fatal("write replay")
			}
			if mode == "transport" && reads != 1 {
				t.Fatal("ambiguous create read-and-adopt")
			}
			if mode == "existing" || mode == "read_denied" || mode == "delete_drift" || mode == "expired" || mode == "disabled" || mode == "readonly" {
				if writes != 0 {
					t.Fatal("unsafe write")
				}
			}
		})
	}
}
func TestTrustedRuleInventoryAndExpiry(t *testing.T) {
	valid := `{"ruleId":"r","comment":"","expirationDate":"2000-01-01"}`
	for _, rules := range []string{`[` + valid + `]`, `[]`, `[` + valid + `,` + valid + `]`, `[{}]`, `[{"ruleId":"r","comment":"","expirationDate":"2026-02-30"}]`} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":%s}]`, rules)
		}))
		c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
		c.http = s.Client()
		got, err := c.TrustedRule(context.Background(), "dev", "r")
		if rules == `[`+valid+`]` {
			if err != nil || got.ExpirationDate != "2000-01-01" {
				t.Fatal("clock inferred absence")
			}
		} else if rules == `[]` {
			if err != ErrNotFound {
				t.Fatal(err)
			}
		} else if err == nil || err == ErrNotFound {
			t.Fatal("malformed inventory proves absence")
		}
		s.Close()
	}
	for _, status := range []int{204, 400, 401, 403, 404, 423, 429, 500, 503} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
		c.http = s.Client()
		if _, e := c.TrustedRule(context.Background(), "dev", "r"); e == nil || e == ErrNotFound {
			t.Fatal(status)
		}
		s.Close()
	}
	for _, date := range []string{"2026-2-01", "2026-02-30", "tomorrow", "2026-01-01T00:00:00Z"} {
		if ValidateTrustedDate(date, false) == nil {
			t.Fatal(date)
		}
	}
}

func TestTrustedRuleConflictingEnvelope(t *testing.T) {
	for _, body := range []string{
		`{"trustedRuleIds":["other"],"TrustedRuleIds":["r"]}`,
		`{"trustedRuleIds":["r"],"description":"denied","fieldErrors":[{"field":"rules","error":"denied"}]}`,
	} {
		accepted := false
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				fmt.Fprint(w, body)
				return
			}
			fmt.Fprint(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":[]}]`)
		}))
		c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
		c.http = s.Client()
		c.CreateTrustedRule(context.Background(), "dev", TrustedRule{RuleID: "r"}, func() { accepted = true })
		if accepted {
			t.Error("conflicting envelope accepted", body)
		}
		s.Close()
	}
}

func TestTrustedRulePartialInventoryMarkers(t *testing.T) {
	for _, extra := range []string{`,"partial":true`, `,"status":false`, `,"nextPage":2`, `,"Error":"denied"`} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `[{"deviceName":"dev","deviceId":"1","deviceDisplayName":"D","trustedRules":[]%s}]`, extra)
		}))
		c, _ := New(Options{URL: s.URL, SessionID: "synthetic", ExperimentalTrustedRules: true})
		c.http = s.Client()
		if _, e := c.TrustedRule(context.Background(), "dev", "r"); e == nil || e == ErrNotFound {
			t.Error("partial inventory proved absence", extra)
		}
		s.Close()
	}
}
