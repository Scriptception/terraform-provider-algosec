// SPDX-License-Identifier: MPL-2.0
package provider

import (
	"context"
	"github.com/Scriptception/terraform-provider-algosec/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type originValidator struct{}

func (originValidator) Description(context.Context) string {
	return "must be an HTTPS origin without credentials, path, query or fragment"
}
func (v originValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (v originValidator) ValidateString(ctx context.Context, r validator.StringRequest, s *validator.StringResponse) {
	if r.ConfigValue.IsNull() || r.ConfigValue.IsUnknown() {
		return
	}
	if err := client.ValidateURL(r.ConfigValue.ValueString()); err != nil {
		s.Diagnostics.AddAttributeError(r.Path, "Invalid URL", err.Error())
	}
}

type identifierValidator struct{}

func (identifierValidator) Description(context.Context) string {
	return "must be nonempty, without control characters or dot segments"
}
func (v identifierValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v identifierValidator) ValidateString(ctx context.Context, r validator.StringRequest, s *validator.StringResponse) {
	if r.ConfigValue.IsNull() || r.ConfigValue.IsUnknown() {
		return
	}
	if _, err := client.Segment(r.ConfigValue.ValueString()); err != nil {
		s.Diagnostics.AddAttributeError(r.Path, "Invalid identifier", err.Error())
	}
}
