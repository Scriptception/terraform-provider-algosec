// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"

	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Synthetic local HTTPS tag lifecycle; no appliance acceptance.
func TestProtocolTagLifecycle(t *testing.T) {
	requireTerraform(t)
	var mu sync.Mutex
	var tag *client.Tag
	creates, deletes := 0, 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/afa/api/v1/tags" && r.URL.Path != "/afa/api/v1/tags/details" && r.URL.Path != "/afa/api/v1/tags/7/name" && r.URL.Path != "/afa/api/v1/tags/7" {
			t.Error("unexpected path", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		switch r.Method {
		case "GET":
			all := []client.Tag{}
			if tag != nil {
				all = append(all, *tag)
			}
			if r.URL.Path == "/afa/api/v1/tags/details" && (r.URL.Query().Get("includeAssociations") != "true" || r.URL.Query().Get("name") != tag.Name) {
				t.Error("unguarded detail read")
			}
			json.NewEncoder(w).Encode(all)
		case "POST":
			if tag != nil {
				w.WriteHeader(409)
				return
			}
			creates++
			tag = &client.Tag{ID: 7, Name: r.URL.Query().Get("name"), Scope: r.URL.Query().Get("scope"), Type: "ALGOSEC", Relations: []client.TagRelation{}}
			json.NewEncoder(w).Encode(tag)
		case "PUT":
			tag.Name = r.URL.Query().Get("name")
		case "DELETE":
			deletes++
			tag = nil
		}
	}))
	defer s.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	cfg := func(name, scope string) string {
		return fmt.Sprintf(`provider "algosec" {
 url = %q
 session_id = "synthetic-session"
 experimental_tags = true
 read_only = false
}
resource "algosec_tag" "test" {
 name = %q
 scope = %q
}
`, s.URL, name, scope)
	}
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, CheckDestroy: func(*terraform.State) error {
		mu.Lock()
		defer mu.Unlock()
		if tag != nil || creates != 2 || deletes != 2 {
			return fmt.Errorf("incomplete tag lifecycle creates=%d deletes=%d", creates, deletes)
		}
		return nil
	}, Steps: []tfresource.TestStep{
		{Config: cfg("Finance", "")},
		{ResourceName: "algosec_tag.test", ImportState: true, ImportStateVerify: true},
		{Config: cfg("Finance renamed", "")},
		{Config: cfg(" Invalid", "new scope"), ExpectError: regexp.MustCompile("canonical|Invalid tag")},
		{PreConfig: func() {
			mu.Lock()
			defer mu.Unlock()
			if tag == nil || deletes != 0 {
				t.Error("invalid replacement deleted tag")
			}
		}, Config: cfg("Finance renamed", "")},
		{PreConfig: func() { mu.Lock(); defer mu.Unlock(); tag.Name = "External rename" }, Config: cfg("External rename", "")},
		{Config: cfg("External rename", "new scope")},
	}})
}
