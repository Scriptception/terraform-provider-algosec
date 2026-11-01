package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// Independent local HTTPS probes; expected safety properties, not appliance responses.
func TestIndependentWrapperBodyMustBeObject(t *testing.T) {
	for _, body := range []string{`null`, `false`, `[]`, `"text"`} {
		t.Run(body, func(t *testing.T) {
			reads, deletes := 0, 0
			c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					reads++
					if deletes > 0 {
						w.WriteHeader(404)
						return
					}
					fmt.Fprint(w, roleFixture)
					return
				}
				deletes++
				fmt.Fprintf(w, `{"body":%s,"statusCode":"100 CONTINUE","statusCodeValue":0}`, body)
			})
			old := AppVizRole{Name: "Test Role", Enabled: true, Users: []string{"alice"}, Permissions: []string{"viewAllApplications"}, Applications: map[string]string{"12": "view"}}
			err := c.DeleteRole(context.Background(), old)
			if err == nil || reads != 1 || deletes != 1 {
				t.Errorf("malformed wrapper accepted: err=%v reads=%d deletes=%d", err, reads, deletes)
			}
		})
	}
}

func TestIndependentURLIPAmbiguousAcknowledgement(t *testing.T) {
	for _, body := range []string{
		`{"categories":{"Example":{"urls":{"www.example.com":[],"www.example.com":["192.0.2.1"]}}}}`,
		`{"categories":{},"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1"]}}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			err := NewURLIPClient(c.c, true).Change(context.Background(), "Example", "www.example.com", "192.0.2.1", true)
			if err == nil {
				t.Error("ambiguous duplicate-key create acknowledgement accepted")
			}
		})
	}
}

func TestIndependentTagInventoryAndDeleteBoundaries(t *testing.T) {
	for _, mode := range []string{"duplicate_second_page", "null_second_page", "wrong_scope", "null_relations", "foreign_relation", "null_relation", "type_device"} {
		t.Run(mode, func(t *testing.T) {
			deletes := 0
			c := tagFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "DELETE" {
					deletes++
					return
				}
				if mode == "duplicate_second_page" || mode == "null_second_page" {
					if r.URL.Query().Get("page") == "0" {
						a := []Tag{}
						for i := int64(1); i <= 100; i++ {
							a = append(a, Tag{ID: i, Name: "Finance", Type: "ALGOSEC"})
						}
						json.NewEncoder(w).Encode(a)
						return
					}
					if mode == "null_second_page" {
						fmt.Fprint(w, `null`)
					} else {
						fmt.Fprint(w, `[{"id":7,"name":"Finance","type":"ALGOSEC"}]`)
					}
					return
				}
				if r.URL.Path != api+"/tags/details" {
					fmt.Fprint(w, `[{"id":7,"name":"Finance","scope":"tenant & 雪","type":"ALGOSEC","relations":[]}]`)
					return
				}
				if r.URL.Query().Get("scope") != "tenant & 雪" || r.URL.Query().Get("includeAssociations") != "true" {
					t.Error("missing full scope/associations")
				}
				switch mode {
				case "wrong_scope":
					fmt.Fprint(w, `[{"id":7,"name":"Finance","scope":"","type":"ALGOSEC","relations":[]}]`)
				case "null_relations":
					fmt.Fprint(w, `[{"id":7,"name":"Finance","scope":"tenant & 雪","type":"ALGOSEC","relations":null}]`)
				case "foreign_relation":
					fmt.Fprint(w, `[{"id":7,"name":"Finance","scope":"tenant & 雪","type":"ALGOSEC","relations":[{"tagId":8,"deviceDataId":2,"hostgroup":"web"}]}]`)
				case "null_relation":
					fmt.Fprint(w, `[{"id":7,"name":"Finance","scope":"tenant & 雪","type":"ALGOSEC","relations":[null]}]`)
				case "type_device":
					fmt.Fprint(w, `[{"id":7,"name":"Finance","scope":"tenant & 雪","type":"DEVICE","relations":[]}]`)
				}
			})
			err := c.Delete(context.Background(), 7)
			if err == nil || deletes != 0 {
				t.Errorf("unsafe deletion: err=%v deletes=%d", err, deletes)
			}
		})
	}
}

func TestCategoryJSONCaseBoundaries(t *testing.T) {
	for _, raw := range []string{
		`{"categories":{},"Categories":{}}`,
		`{"categories":{"Example":{"urls":{},"URLs":{}}}}`,
	} {
		var out Categories
		if json.Unmarshal([]byte(raw), &out) == nil {
			t.Fatal("ambiguous schema aliases accepted")
		}
	}
	raw := `{"categories":{"Example":{"urls":{"www.example.com":["192.0.2.1"],"WWW.example.com":[]}},"example":{"urls":{}}}}`
	var out Categories
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Categories) != 2 || len(out.Categories["Example"].URLs) != 2 {
		t.Fatal("literal case-sensitive identifiers conflated")
	}
}
