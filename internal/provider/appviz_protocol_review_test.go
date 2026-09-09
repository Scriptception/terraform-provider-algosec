package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestReviewPublishedAFAConfigIgnoresDisabledSaaSEnv(t *testing.T) {
	t.Setenv("ALGOSEC_APPVIZ_SAAS_URL", "https://example.invalid")
	t.Setenv("ALGOSEC_APPVIZ_SAAS_TOKEN", "")
	p := New("review")()
	ctx := context.Background()
	var sr provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &sr)
	cfg := tfsdk.Config{Schema: sr.Schema}
	m := providerModel{
		AppVizURL: types.StringNull(), AppVizToken: types.StringNull(), ExperimentalAppVizRoles: types.BoolValue(false),
		URL: types.StringValue("https://afa.example.invalid"), SessionID: types.StringValue("synthetic"),
		Username: types.StringNull(), Password: types.StringNull(),
		ExperimentalTrustedRules: types.BoolNull(), ExperimentalDeviceGroups: types.BoolNull(),
		Insecure: types.BoolNull(), ReadOnly: types.BoolNull(), Timeout: types.Int64Null(),
	}
	value, d := types.ObjectValueFrom(ctx, sr.Schema.Type().(types.ObjectType).AttrTypes, m)
	if d.HasError() {
		t.Fatal(d)
	}
	raw, err := value.ToTerraformValue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Raw = raw
	var resp provider.ConfigureResponse
	p.Configure(ctx, provider.ConfigureRequest{Config: cfg}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("published AFA config blocked by disabled SaaS environment: %v", resp.Diagnostics)
	}
}

func TestReviewAppVizTypeValidation(t *testing.T) {
	requireTerraform(t)
	cases := map[string]string{
		"name_object": `name = {x="y"}`,
		"enabled_list": `name="role"
 enabled=[]`,
		"users_object": `name="role"
 users={x="y"}`,
		"permissions_nested": `name="role"
 permissions=[["admin"]]`,
		"apps_list": `name="role"
 application_permissions=["view"]`,
		"apps_object_value": `name="role"
 application_permissions={"1"={x="view"}}`,
		"apps_null_value": `name="role"
 application_permissions={"1"=null}`,
		"apps_bad_id_unknown_value": `name="role"
 application_permissions={"01"=terraform_data.unknown.output}`,
		"apps_bad_value_unknown_sibling": `name="role"
 application_permissions={"1"="admin", "2"=terraform_data.unknown.output}`,
		"users_null_unknown": `name="role"
 users=[null, terraform_data.unknown.output]`,
		"permissions_blank_unknown": `name="role"
 permissions=["", terraform_data.unknown.output]`,
	}
	for name, attrs := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := fmt.Sprintf(`provider "algosec" {
 appviz_saas_url="https://example.invalid"
 appviz_saas_token="synthetic"
 experimental_appviz_roles=true
 appviz_whole_role_ownership=true
 read_only=false
}
resource "terraform_data" "unknown" { input="view" }
resource "algosec_appviz_role" "test" {
%s
}`, attrs)
			tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{{Config: cfg, PlanOnly: true, ExpectError: regexp.MustCompile("Inappropriate value|Invalid application|Invalid role membership")}}})
		})
	}
}

func TestAppVizWholeRoleConsentRequired(t *testing.T) {
	requireTerraform(t)
	tfresource.UnitTest(t, tfresource.TestCase{ProtoV6ProviderFactories: factories, Steps: []tfresource.TestStep{{Config: `provider "algosec" {
 appviz_saas_url="https://example.invalid"
 appviz_saas_token="synthetic"
 experimental_appviz_roles=true
 read_only=false
}
resource "algosec_appviz_role" "test" {name="Example"}
`, PlanOnly: true, ExpectError: regexp.MustCompile("appviz_whole_role_ownership")}}})
}
