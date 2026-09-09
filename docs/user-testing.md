# Testing the 0.1.3 candidate

Status: prepared for review, unpublished and not live-appliance tested. Scope remains
2 resources and 12 data sources. Start with [read-only quickstart](../examples/quickstart).

## Install a release ZIP without Registry availability

Obtain the maintainer-reviewed ZIP for your OS/architecture and independently
verify its SHA256 against the supplied checksum file. Verify the detached signature
against the maintainer's trusted public key. The release signing-key fingerprint is
`71B43325624199D6C4339C17EE5515CFD4999B22`; the private key is Vault-held. Obtain the
public `.asc` key from the GitHub release and compare its fingerprint before trusting
it. Verify `gpg --verify <SHA256SUMS.sig> <SHA256SUMS>` after importing that public key.
Do not treat an unsigned local candidate as an authenticated release.

Terraform supports a packed filesystem mirror with the original Registry source
address. For example, put the Linux amd64 archive at:

```text
/absolute/private/mirror/registry.terraform.io/scriptception/algosec/terraform-provider-algosec_0.1.3_linux_amd64.zip
```

Create a private `testing.tfrc` with:

```hcl
provider_installation {
  filesystem_mirror {
    path    = "/absolute/private/mirror"
    include = ["registry.terraform.io/scriptception/algosec"]
  }
  direct {
    exclude = ["registry.terraform.io/scriptception/algosec"]
  }
}
```

Set `TF_CLI_CONFIG_FILE` to its absolute path in the testing process. Run `terraform
init`, `terraform validate`, then the authorized read-only `terraform plan` from
the quickstart. The exclusion prevents Registry lookup for this provider, including
before first publication. Other providers may use direct installation. Keep the
resulting dependency lock file with the reviewed configuration; local mirror
checksums are computed locally and are not proof of publisher authentication.
Use a fresh test directory when switching candidate archives; do not overwrite an
already accepted released version.

[HashiCorp mirror configuration](https://developer.hashicorp.com/terraform/cli/config/config-file#explicit-installation-method-configuration)
documents this layout. `make package-smoke` packages the local binary and verifies
real init/validate/schema against an isolated mirror. For a final archive, run:

```sh
python3 scripts/package_smoke.py --archive /path/to/terraform-provider-algosec_0.1.3_linux_amd64.zip
```

This offline check never plans data sources or calls an appliance, and does not
verify a release signature. Repeat with `TERRAFORM=terraform-1.11.0` for the minimum
supported Terraform version.

## Opt-in disposable category mutation

Use a separate configuration and dedicated disposable category, not production.
An administrator must prepare `url_categories.json` in the Panorama plugin override
directory with mode 0644 as described by the
[official prerequisite](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_put.htm).
The provider never prepares the appliance filesystem. Use complete administrator
visibility and exclude concurrent writers.

Copy the [category example](../examples/resources/algosec_url_category/resource.tf),
add the pinned provider requirement from quickstart and set `read_only = false`.
Review `terraform plan`, then explicitly run `terraform apply` only for the disposable
object. Rename should update in place; changing URLs/IPs replaces the entire category
with a delete/create interval. Never use same-name create-before-destroy.

For an existing category you have verified you own, configure its complete URL/IP
map before `terraform import algosec_url_category.example EXACT_CATEGORY_NAME`.
Review a fresh plan; mismatched content may propose destructive replacement. Never
import an object merely because it appeared after an ambiguous create. Inspect the
appliance and verify ownership first. For cleanup, review `terraform plan -destroy`
and run `terraform destroy` only in this dedicated configuration. Destroy deletes
the category, not merely Terraform state. Ambiguous acknowledgements retain owned
state and require inspection before further action.

Experimental groups require A33.20 EA and `experimental_device_groups = true` in
addition to write opt-in. AlgoSec does not recommend the group APIs for production.
Groups own all nonempty membership; rename replaces, additions precede removals,
and deletion leaves devices intact. Import uses exact display name. No live group
acceptance has been run.

## Exact known limitations

- Public documentation contracts only: A32.60 base and separately gated A33.20 EA
  groups, with no appliance compatibility certification.
- Category casing/wrapper examples conflict. Create requires exact acknowledged
  name/URL/IP membership; rename requires old absence/new presence with unchanged membership; delete uses the
  response-table categories map. Malformed nested delete examples fail closed.
  All acknowledged writes still use GET verification; delayed consistency can fail.
- No documented conditional create, ETag or transaction; preflight cannot eliminate
  concurrent-writer races. Partial or permission-filtered inventories cannot prove absence.
- URL/IP changes replace; granular updates are excluded. A33.20 IP deletion exists
  but is not implemented. Trusted traffic may omit zero-hit entries; network-object
  queries use the documented IPv4 default.
- No general devices, users, roles, settings, trusted-rules or operational workflow
  management. See the [complete version-scoped inventory](api-coverage.md).
- Sessions are not refreshed or logged out automatically. Writes are not replayed,
  redirects are refused, and authentication/HTTP errors are not treated as absence.

## Maintainer publication checklist (pending external work)

- Review and commit the candidate; verify VERSION/tag agreement on tested main.
- Configure a protected release environment and Registry-compatible GPG signing key;
  register the public key with the correct Registry namespace. No signing is done yet.
- Complete Registry onboarding for `Scriptception/algosec` and repository association.
- Build final cross-platform release ZIPs, manifest, SHA256SUMS and detached signature;
  verify checksums/signatures and run the archive smoke on the exact release binary.
- Publish the authorized tag/release through the release workflow, verify all assets,
  and confirm Registry indexing. These steps are handled outside this preparation.
- From a clean directory without overrides/mirror, verify Registry `terraform init`
  with `= 0.1.3`; validate, then run authorized appliance tests separately.
- Record actual platform/version/operation results; never promote synthetic tests
  into live compatibility claims.

[HashiCorp publication requirements](https://developer.hashicorp.com/terraform/registry/providers/publishing)
are the external checklist reference. No CI job makes live appliance calls.
