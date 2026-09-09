// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestACEJira(t *testing.T) {
	var saved *ACEJira
	writes := 0
	confirmed := true
	c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prevasio/api/v1/configurations/integrations/jira" {
			t.Error("route")
		}
		switch r.Method {
		case "GET":
			if saved == nil {
				w.Write([]byte(`{"data":{}}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"serverUrl": saved.ServerURL, "userName": saved.UserName, "projectKey": saved.ProjectKey, "defaultIssueType": saved.IssueType, "defaultPriority": saved.Priority, "apiToken": "MASKED-SYNTHETIC"}})
		case "POST":
			writes++
			var v map[string]string
			json.NewDecoder(r.Body).Decode(&v)
			if v["apiToken"] != base64.StdEncoding.EncodeToString([]byte("user@example.invalid:synthetic-raw")) {
				t.Error("wrong token conversion")
			}
			saved = &ACEJira{v["serverUrl"], v["userName"], v["projectKey"], v["defaultIssueType"], v["defaultPriority"]}
			if confirmed {
				w.Write([]byte(`{"data":{"message":"Your Jira project settings were successfully tested and saved."}}`))
			} else {
				w.Write([]byte(`{"data":{"message":"OK"}}`))
			}
		case "DELETE":
			writes++
			saved = nil
			w.Write([]byte(`{"data":{"message":"Jira settings have been deleted."}}`))
		default:
			t.Error("invented method")
		}
	})
	ctx := context.Background()
	v := ACEJira{"https://jira.example.invalid", "user@example.invalid", "TEST", "Task", "High"}
	if e := c.CreateJira(ctx, v, "synthetic-raw"); e != nil {
		t.Fatal(e)
	}
	if e := c.CreateJira(ctx, v, "synthetic-raw"); e == nil || writes != 1 {
		t.Fatal("adopted")
	}
	if got, e := c.Jira(ctx); e != nil || *got != v {
		t.Fatal("read mismatch", e)
	}
	if e := c.DeleteJira(ctx, v); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Jira(ctx); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	confirmed = false
	if e := c.CreateJira(ctx, v, "synthetic-raw"); e == nil {
		t.Fatal("unconfirmed create")
	}
}
func TestACEJiraIncomplete(t *testing.T) {
	for _, b := range []string{`null`, `{}`, `{"data":null}`, `{"data":{"apiToken":"MASKED"}}`, `{"data":{"serverUrl":"https://example.invalid"}}`, `{"data":{},"error":"synthetic"}`} {
		c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(b)) })
		if _, e := c.Jira(context.Background()); e == nil || errors.Is(e, ErrNotFound) {
			t.Fatal("accepted incomplete", b)
		}
	}
}
