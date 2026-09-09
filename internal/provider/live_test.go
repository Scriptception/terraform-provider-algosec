// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"fmt"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"os"
	"testing"
	"time"
)

func liveGate(t *testing.T, mutation bool) {
	t.Helper()
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("live appliance tests require TF_ACC=1")
	}
	if mutation && (os.Getenv("ALGOSEC_ACC_MUTATION") != "1" || os.Getenv("ALGOSEC_ACC_DISPOSABLE") != "1") {
		t.Skip("live mutation requires ALGOSEC_ACC_MUTATION=1 and ALGOSEC_ACC_DISPOSABLE=1")
	}
	if os.Getenv("ALGOSEC_URL") == "" {
		t.Fatal("ALGOSEC_URL required")
	}
}

// TestAccDevicesReadOnly performs only inventory GETs (and login if needed).
func TestAccDevicesReadOnly(t *testing.T) {
	liveGate(t, false)
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{{Config: `provider "algosec" { read_only = true }
data "algosec_devices" "live" {}`}}})
}
func TestAccURLCategoryMutation(t *testing.T) {
	liveGate(t, true)
	name := fmt.Sprintf("tf-acc-algosec-%d", time.Now().UnixNano())
	c, err := client.New(client.Options{URL: os.Getenv("ALGOSEC_URL"), SessionID: os.Getenv("ALGOSEC_SESSION_ID"), Username: os.Getenv("ALGOSEC_USERNAME"), Password: os.Getenv("ALGOSEC_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup covers both the original and renamed object if a test step fails.
	t.Cleanup(func() {
		for _, n := range []string{name, name + "-renamed"} {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			_, e := c.Category(ctx, n)
			if e == nil {
				if e = c.DeleteCategory(ctx, n); e != nil {
					t.Error("live cleanup failed:", e)
				}
			}
			cancel()
		}
	})
	cfg := func(n string) string {
		return fmt.Sprintf(`provider "algosec" { read_only = false }
resource "algosec_url_category" "live" {
 name = %q
 urls = { "service.example.invalid" = ["192.0.2.1"] }
}`, n)
	}
	resource.Test(t, resource.TestCase{ProtoV6ProviderFactories: factories, Steps: []resource.TestStep{{Config: cfg(name)}, {ResourceName: "algosec_url_category.live", ImportState: true, ImportStateVerify: true}, {Config: cfg(name + "-renamed")}}})
}
