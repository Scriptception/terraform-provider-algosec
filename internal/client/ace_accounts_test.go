// SPDX-License-Identifier: MPL-2.0
package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestACEAccountRegistration(t *testing.T) {
	for _, provider := range []string{"aws", "azure", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			var account *ACEAccount
			writes := 0
			key := "opaque-key-not-parsed"
			id := "123456789012"
			if provider == "azure" {
				id = "11111111-2222-3333-4444-555555555555"
			}
			if provider == "gcp" {
				id = "synthetic-project"
			}
			c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case "GET":
					v := []any{}
					if account != nil {
						v = append(v, map[string]any{"accountId": account.AccountID, "accountKey": key, "provider": provider, "name": account.Name, "autoOnboarded": account.AutoOnboarded, "azureTenant": account.AzureTenant, "organizationId": account.OrganizationID})
					}
					json.NewEncoder(w).Encode(v)
				case "POST":
					writes++
					account = &ACEAccount{AccountKey: key, AccountID: id, Provider: provider, Name: "synthetic", AzureTenant: "11111111-2222-3333-4444-555555555555", OrganizationID: "123456"}
					w.WriteHeader(201)
					json.NewEncoder(w).Encode(map[string]string{"accountKey": key})
				case "PATCH":
					var in map[string]string
					json.NewDecoder(r.Body).Decode(&in)
					if len(in) != 1 || in["name"] == "" {
						t.Error("name-only PATCH violated")
					}
					account.Name = in["name"]
					writes++
					w.WriteHeader(204)
				case "DELETE":
					if r.URL.Path != "/api/algosaas/accounts/v1/account/"+provider+"/"+id {
						t.Error("parsed key or wrong base")
					}
					account = nil
					writes++
					w.WriteHeader(204)
				}
			})
			v := ACEAccount{Provider: provider, AccountID: id, Name: "synthetic", AzureTenant: "11111111-2222-3333-4444-555555555555", OrganizationID: "123456"}
			// This test isolates lifecycle from bootstrap format validation, covered separately.
			k, e := c.createAccount(ctxBackground(), v, struct {
				Name string `json:"name"`
			}{v.Name})
			if e != nil || k != key {
				t.Fatal(k, e)
			}
			got, e := c.Account(context.Background(), key)
			if e != nil || got.AccountID != id {
				t.Fatal("identity readback", e)
			}
			if _, e := c.createAccount(ctxBackground(), v, struct{}{}); e == nil || writes != 1 {
				t.Fatal("adopted existing account")
			}
			if e := c.RenameAccount(context.Background(), *got, "renamed"); e != nil {
				t.Fatal(e)
			}
			got.Name = "renamed"
			account.AutoOnboarded = true
			if e := c.DeleteAccount(context.Background(), *got); e == nil || writes != 2 {
				t.Fatal("deleted automatic account")
			}
			account.AutoOnboarded = false
			if e := c.DeleteAccount(context.Background(), *got); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func ctxBackground() context.Context { return context.Background() }
func TestACEAccountReadFailClosed(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `[{}]`, `[{"accountKey":"key","accountId":"123456789012","provider":"aws","name":"synthetic"}]`, `[{"accountKey":"key","accountId":"123456789012","provider":"aws","name":"synthetic","autoOnboarded":null}]`, `[{"accountKey":"key","accountId":"123456789012","provider":"aws","name":"synthetic","autoOnboarded":false},{"accountKey":"key","accountId":"123456789012","provider":"aws","name":"synthetic","autoOnboarded":false}]`} {
		c := aceFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) })
		if _, e := c.Account(context.Background(), "key"); e == nil || errors.Is(e, ErrNotFound) {
			t.Fatal("incomplete account inventory accepted")
		}
	}
}
func TestACEAWSBootstrapRejectInvalidARN(t *testing.T) {
	v := ACEAccount{Provider: "aws", AccountID: "123456789012", Name: "synthetic"}
	if e := ValidateACEAWSBootstrap(v, ACEAWSBootstrap{RoleARN: "arn:aws:iam::123456789012:role/invalid role", ExternalID: "synthetic"}); e == nil {
		t.Fatal("known malformed role ARN accepted")
	}
}
