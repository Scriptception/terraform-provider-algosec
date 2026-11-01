// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// Synthetic reproduction of independent finding S1 using the public example.
func TestAppVizDeleteOfficialWrapperConfirmsAbsence(t *testing.T) {
	for _, after := range []int{404, 403, 200} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			reads, writes := 0, 0
			c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					reads++
					if writes > 0 && after != 200 {
						w.WriteHeader(after)
						return
					}
					fmt.Fprint(w, roleFixture)
					return
				}
				writes++
				fmt.Fprint(w, `{"body":{},"statusCode":"100 CONTINUE","statusCodeValue":0}`)
			})
			old := AppVizRole{Name: "Test Role", Enabled: true, Users: []string{"alice"}, Permissions: []string{"viewAllApplications"}, Applications: map[string]string{"12": "view"}}
			err := c.DeleteRole(context.Background(), old)
			if (err == nil) != (after == 404) || reads != 2 || writes != 1 {
				t.Fatalf("err=%v reads=%d deletes=%d", err, reads, writes)
			}
		})
	}
}

func TestAppVizDeleteRejectsContradictoryBody(t *testing.T) {
	reads := 0
	c, _ := roleClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			reads++
			if reads > 1 {
				w.WriteHeader(404)
				return
			}
			fmt.Fprint(w, roleFixture)
			return
		}
		fmt.Fprint(w, `{"body":{"success":false},"statusCode":"OK","statusCodeValue":200}`)
	})
	old := AppVizRole{Name: "Test Role", Enabled: true, Users: []string{"alice"}, Permissions: []string{"viewAllApplications"}, Applications: map[string]string{"12": "view"}}
	if err := c.DeleteRole(context.Background(), old); err == nil || reads != 1 {
		t.Fatalf("contradictory delete accepted err=%v reads=%d", err, reads)
	}
}
