# Terraform Provider for AlgoSec

**v0.3.0 is published:** [Terraform Registry](https://registry.terraform.io/providers/Scriptception/algosec/0.3.0)
and [signed release](https://github.com/Scriptception/terraform-provider-algosec/releases/tag/v0.3.0).
Direct signed installation passed on Terraform 1.11.0 and 1.16.1.
See [release verification](docs/release-0.3.0-verification.md) for migration scope and limits.

> Version `0.3.0` adds separately gated AppViz role,
> A33.30 tag, A33.20 URL/IP membership, A33.30 FireFlow direct bindings and
> rolling ACE configuration: 12 resources, 12 data sources and 53 selected
> operations. Live compatibility remains unverified. The v0.2.0 sections below
> retain historical baseline evidence. See the
> [continuation ledger](docs/durable-expansion-ledger.md).

An independent, unofficial Terraform Plugin Framework provider for **AlgoSec
Firewall Analyzer / ASMS A32.60**, with explicitly experimental A33.20 device
groups and trusted-rule assignments, built from public API documentation. It is not affiliated with or
endorsed by AlgoSec.

Published `0.2.0` includes **3 resources and 12 data sources**, typed
Go clients and schemas, **20 method/route operations**, import/drift handling, generated Registry docs, synthetic
Terraform lifecycle tests. The [signed v0.2.0 release](https://github.com/Scriptception/terraform-provider-algosec/releases/tag/v0.2.0)
and direct Registry installation are verified. **Live-appliance testing remains pending.** Read the
[API coverage and contract limitations](docs/api-coverage.md) before using it.

Maintainers and fresh agent sessions: start with the [maintainer handoff](docs/maintainer-handoff.md).

## Published v0.2.0 scope

| Resources | Ownership and lifecycle |
|---|---|
| `algosec_url_category` | One Panorama URL-category override and its complete URL/IP map. Rename in place; URL/IP changes replace; destroy deletes. |
| `algosec_device_group` | EXPERIMENTAL A33.20 EA: authoritative nonempty membership; add before remove with confirmed readback and recoverable partial state; rename replaces. |
| `algosec_trusted_rule` | Published v0.2.0, experimental A33.20: one trust assignment; explicit import, all input changes replace, exact per-rule acknowledgements and recoverable state. Requires `experimental_trusted_rules=true`. See [contract and limits](docs/trusted-rule-contract.md). |

| Data sources | Purpose |
|---|---|
| `algosec_device_groups`, `algosec_device_group` | EXPERIMENTAL A33.20 EA group inventory and exact display-name lookup. |
| `algosec_devices`, `algosec_device` | Administrator device inventory and exact tree-name lookup, without credentials. |
| `algosec_url_categories`, `algosec_url_category` | Panorama category inventory and exact lookup. |
| `algosec_risk_profiles`, `algosec_risk_profile_files` | Custom risk-profile names and security-zone spreadsheet names. |
| `algosec_security_zones`, `algosec_device_zones` | Spreadsheet zone definitions and analyzed topology zones. |
| `algosec_network_objects` | Paginated device network-object search. |
| `algosec_trusted_traffic` | Informational paginated trusted-traffic inventory; upstream may omit zero-hit entries. |

In published v0.2.0, user/role management, general credentialed device onboarding, trusted-traffic
mutation, risk-profile mutation, rule documentation, analyses, exports, active
changes and other one-shot operations are excluded. The coverage map gives
endpoint-specific reasons; this is not a full ASMS administration provider.

File-device management is excluded: `existingFile` is documented as a
[write input](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-add_edit.htm),
but the [device inventory contract](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/devices-list.htm)
does not establish its readback. Creating first and discovering missing readback
cannot support reliable drift or import. Safe device data sources remain.
A33.20 user/role REST writes exist, but complete authorization readback remains
unproven; see the version-specific [coverage review](docs/api-coverage.md).

## Requirements and authentication

- Terraform **1.11+**, protocol 6; Go **1.26.8+** for source builds.
- An A32.60 appliance for the base APIs, or A33.20 for experimental groups. Drift requires
  an administrator with stable complete inventory visibility.
- Panorama URL categories require the administrator-prepared override file
  described in the [official category API](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_get.htm).
- Group APIs require `experimental_device_groups = true` (default false). AlgoSec
  labels them **Early Availability and does not recommend production use**; see the
  [vendor warning](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/managing-devices-and-groups.htm).

Provide `ALGOSEC_URL` as the HTTPS origin and either `ALGOSEC_SESSION_ID` or both
`ALGOSEC_USERNAME` and `ALGOSEC_PASSWORD` through your credential manager's
process environment. Do not set both authentication modes. Explicit provider
attributes override their corresponding environment variables, including empty
values; unknown configuration produces a diagnostic instead of an env fallback.

```hcl
terraform {
  required_version = ">= 1.11.0"
  required_providers {
    algosec = {
      source  = "Scriptception/algosec"
      version = "= 0.3.0"
    }
  }
}

provider "algosec" {
  read_only = true
}
```

`read_only` defaults to true; set it to false to apply managed resources.
`insecure` defaults to false. Install your appliance CA into the system trust
store where possible. `timeout_seconds` defaults to 30, bounded at 1–300.
The standard Go HTTP proxy environment behavior applies.

Sessions are sent only in cookies. All redirects are refused. Sessions are reused
within a configured client, but are not automatically refreshed on expiry or
logged out; the provider cannot safely log out externally owned sessions.
Username/password authentication establishes a session lazily on the first API
operation. Login and all administration writes are never replayed automatically.

## Local build and use

Install v0.3.0 with the configuration above and `terraform init`.
For offline installation, use the [ZIP mirror instructions](docs/user-testing.md).
For local development, build with a CLI override:

```sh
make build
```

Create a local Terraform CLI config (outside source control), substituting the
absolute path of this checkout:

```hcl
provider_installation {
  dev_overrides {
    "Scriptception/algosec" = "/absolute/path/terraform-provider-algosec/bin"
  }
  direct {}
}
```

Set `TF_CLI_CONFIG_FILE` to that file, then run `terraform validate` and
`terraform plan` in your configuration directory. For a configuration using only
this development provider, skip `terraform init`: init still attempts Registry
version discovery despite dev overrides. Additional providers/modules may need
separate initialization. `make smoke` demonstrates the local compiled-provider
schema, validate and plan workflow without contacting an appliance.

Resource and data-source examples are under [examples](examples); the generated
schema reference starts at [docs/index.md](docs/index.md). Imports use the exact
category name or group display name:

```sh
terraform import algosec_url_category.example tf-example-services
terraform import algosec_device_group.example "Example Group"
```

## State and operational behavior

Existing resources must be imported; create refuses to overwrite a discovered
object. Each category owns all URLs/IPs in that category. Content replacement
causes a delete/create interval; do not enable create-before-destroy for the
same category name. Avoid concurrent external edits or overlapping ownership.
The APIs provide no documented transaction or ETag contract.

Successful writes are read back. Only absence from a successful, well-formed,
complete inventory removes state. Permission errors, HTTP 404, HTTP 204, malformed
or null responses and transport failures during refresh retain existing state with diagnostics. Delayed
consistency produces an error rather than a false success. A successful create
records a recoverable identity before read-back. After ambiguous write failures,
inspect and import the remote object before retrying.

Provider passwords/session IDs are sensitive attributes, but sensitive does not
prevent values entered in configuration from appearing in saved plans. Prefer
environment credentials. No managed resource has credential attributes. Device
credential fields in API responses are discarded before state conversion; no raw
API responses, bodies or headers are logged. Inventory values themselves remain
in Terraform state and should be protected appropriately.

## Verification and live tests

```sh
make fmt-check test vet vuln docs-check smoke actionlint
```

`make test` requires a local Terraform executable and runs unit tests plus real
Terraform CLI/protocol lifecycle tests against **synthetic local HTTPS fixtures**,
with the Go race detector (requires Make and a C compiler). `make test-unit` skips CLI lifecycle tests unless
`TF_ACC_TERRAFORM_PATH` is set. Fixtures are neither live captures nor proof of
appliance behavior. [Verification results](docs/verification.md) record the exact
local gates and limitations.

Live tests are separate and are not run by CI:

```sh
# Read-only inventory; may authenticate, never mutates administration objects.
make testacc-read

# Disposable appliance only. Requires credentials and prepared prerequisites.
ALGOSEC_ACC_MUTATION=1 ALGOSEC_ACC_DISPOSABLE=1 make testacc-mutation
```

Both live targets require `TF_ACC=1` (set by Make). Category mutation tests use
unique `tf-acc-algosec-` names. Group tests are synthetic only.
Do not run mutation tests against production. No live tests were run during this
initial build.

## Releases and license

`VERSION` and `CHANGELOG.md` use SemVer. The maintainer's default release path
builds the tested commit with GoReleaser, signs checksums using the key held in
Vault, verifies the exact archives, then publishes the GitHub release. The private
key is never stored in this repository or copied to GitHub Secrets. The public
signing-key fingerprint for v0.1.4 onward is `BB831B4CD32200DD15EDF4E9AB71E7968334DF52`.

The alternative tag-triggered GitHub signing workflow is disabled unless
`RELEASE_SIGNING_MODE=github-secrets` is explicitly configured together with
approved `GPG_PRIVATE_KEY`/`PASSPHRASE` environment secrets and release protection.
Do not enable it for the Vault-only release path. Registry onboarding and v0.2.0
installation verification are complete. Every future release still requires its
own clean Registry installation check; GitHub publication alone is not proof of
Registry availability.

Licensed under [MPL-2.0](LICENSE). Layout, contributor workflow and release
conventions follow the maintainer's MISP, Airlock and Mimecast providers, also
MPL-2.0. AlgoSec documentation is linked as evidence, not bundled as upstream HTML.

Group create records Terraform ownership only after a successful POST response with a validated positive acknowledgment, before inventory readback. Unconfirmed creates (HTTP or transport errors, malformed or unsuccessful acknowledgments) leave no managed state and do not adopt a visible group. If the POST outcome is ambiguous, inspect the remote group and verify ownership before importing or retrying. An acknowledged create retains recoverable identity if readback fails; successful readback still verifies exact membership. Existing-owned update/delete partial-state recovery is unchanged.

## First user test: published v0.2.0

Start with the [read-only quickstart](https://github.com/Scriptception/terraform-provider-algosec/tree/main/examples/quickstart),
pinned to `= 0.2.0`, with environment-based authentication and TLS verification.
It exposes only counts; full inventory can still enter plan/state and needs protection.
v0.2.0 publication and direct Registry installation are verified. Run
`terraform init`, `terraform validate`, and an authorized `terraform plan`.

[v0.2.0 is published in the Terraform Registry](https://registry.terraform.io/providers/Scriptception/algosec/0.2.0).
Direct-only installation with isolated HOME/config/data and no mirrors or plugin
cache, Registry signature verification, validate and schema
loading passed on Terraform 1.11.0 and 1.16.1. The shared signing key is
`BB831B4CD32200DD15EDF4E9AB71E7968334DF52`. All 12 GitHub release assets were
downloaded and hash-verified. Eight platform archives were built; execution was
Linux amd64 only. No live-appliance acceptance has been performed.
See [user testing](https://github.com/Scriptception/terraform-provider-algosec/blob/main/docs/user-testing.md)
for CA trust, category prerequisites, disposable mutations, import/destroy and limitations.
Immutable v0.2.0 source: commit `e017b2f0613e28b62fc5cfd16418e7609f1812f5`,
tree `053820d4644d5c5b4fa522df54d8ca063eca44cb`. Subsequent documentation HEAD
is not the release source. See [release-source CI](https://github.com/Scriptception/terraform-provider-algosec/actions/runs/34315231830).
