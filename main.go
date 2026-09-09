// SPDX-License-Identifier: MPL-2.0
package main

import (
	"context"
	"flag"
	"github.com/Scriptception/terraform-provider-algosec/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"log"
)

var version = "dev"
var commit = "none"

func main() {
	debug := flag.Bool("debug", false, "Run with debugger support")
	flag.Parse()
	if err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{Address: "registry.terraform.io/Scriptception/algosec", Debug: *debug}); err != nil {
		log.Fatal(err)
	}
}
