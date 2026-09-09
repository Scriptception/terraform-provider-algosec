# Maintainer handoff

## Active unreleased expansion branch

For `feat/durable-api-expansion`, start with the
[durable expansion ledger](durable-expansion-ledger.md) and
[AppViz SaaS role contract](appviz-role-contract.md). Development VERSION is
`0.3.0-dev`; published 0.2.0 pins and historical evidence below remain unchanged.
This candidate has twelve resources, twelve data sources and fifty-three selected
operations. No publication or live acceptance is authorized by this handoff.


## Start here in a fresh session

1. Read [AGENTS.md](../AGENTS.md), this handoff, [API coverage](api-coverage.md),
   and the current section of [verification](verification.md).
2. Inspect `git status --short --branch`, the current commit, open pull requests,
   and current CI before making changes. Preserve unrelated work; do not replay
   old release scripts or infer that a previously green tree is still current.
3. Choose the next task explicitly. A new session is not authorization to publish
   a release, change signing credentials, or contact an appliance.

## Current published baseline: v0.2.0

Historical release `VERSION` and retained installation pins select published `0.2.0`;
the current repository `VERSION` is the unpublished `0.3.0-dev` candidate:
[Terraform Registry](https://registry.terraform.io/providers/Scriptception/algosec/0.2.0)
and [signed GitHub release](https://github.com/Scriptception/terraform-provider-algosec/releases/tag/v0.2.0).
Immutable tag `v0.2.0` is commit `e017b2f0613e28b62fc5cfd16418e7609f1812f5`,
tree `053820d4644d5c5b4fa522df54d8ca063eca44cb`.
[Exact-source CI](https://github.com/Scriptception/terraform-provider-algosec/actions/runs/34315231830)
passed. Subsequent documentation HEAD is not the release source.

All 12 assets were downloaded and hash-verified; eight platform archives were
built, with execution tested on Linux amd64 only. Direct-only isolated
HOME/config/data installation, without mirrors or plugin cache, passed init,
signature verification, validate and schema loading on Terraform 1.11.0 and 1.16.1:
3 resources and 12 data sources, implementing 20 operations. Shared signing-key
fingerprint: `BB831B4CD32200DD15EDF4E9AB71E7968334DF52`.
See [verification](verification.md) for evidence. No live appliance acceptance
is claimed; experimental opt-ins remain required.

## Historical published baseline: v0.1.4

- [Terraform Registry v0.1.4](https://registry.terraform.io/providers/Scriptception/algosec/0.1.4)
  and [GitHub release](https://github.com/Scriptception/terraform-provider-algosec/releases/tag/v0.1.4).
- Immutable release source: `172f6e77cb0476a981b3cbb08ace3d2975ecbd3b`.
  Main contains later documentation improvements; it is not the release source.
- [Release-source CI](https://github.com/Scriptception/terraform-provider-algosec/actions/runs/34309853152)
  passed. Direct-only Registry init, signature verification, validate and schema
  loading passed on Terraform 1.11.0 and 1.16.1, without mirrors or plugin caches.
- Shared Terraform signing-key fingerprint:
  `BB831B4CD32200DD15EDF4E9AB71E7968334DF52` (Registry key `11617`).
  Reuse this key across the maintainer's Terraform providers. Do not create a new
  per-provider key or copy private material into GitHub Secrets.
- v0.1.3 was signed with an earlier key and is historical. Do not move its tag,
  replace its assets, or confuse its old onboarding failure with current status.
- Eight platform archives were cross-built and verified; execution tests were
  Linux amd64 only. All 12 uploaded release assets were downloaded/hash-compared.

## Implemented scope and boundaries

Published `v0.2.0` adds `algosec_trusted_rule` (A33.20) behind
`experimental_trusted_rules=true`, separate from vendor EA groups. See the
[contract and limitations](trusted-rule-contract.md) and
[historical implementation verification](public-expansion-verification.md). Historical
v0.1.4 has 2 resources, 12 data sources and 17 operations.

The published v0.2.0 provider exposes **3 resources and 12 data sources**, implementing **20
method/route operations**. The inventory covers **204 documentation pages**:
85 A32.60 and 119 A33.20. Page counts are not API-operation coverage percentages.

Base APIs target A32.60. Device groups target A33.20 Early Availability, are
experimental and require explicit opt-in. No live AlgoSec appliance compatibility
has been established. Do not turn synthetic fixture tests into a live acceptance
claim. Managed file devices, users/roles and broader operational workflows remain
excluded where a complete durable lifecycle contract has not been demonstrated.

Create ownership must come from an operation-specific positive acknowledgement,
not a same-name GET after rejected or unconfirmed creation. Keep the category and
group regression suites when extending the provider. Preserve already-owned
partial state on ambiguous update/readback errors; do not adopt another actor's
object to make recovery appear successful.

## Next useful work

See the [public-provider expansion roadmap](coverage-roadmap.md) for prioritized contract research and resource milestones.

1. **Read-only live acceptance:** obtain an authorized appliance/version and
   approved credential source. Use the [quickstart](../examples/quickstart/README.md)
   with verified TLS, complete administrator inventory visibility and protected
   working state. `terraform plan` reads the appliance; it is not an offline test.
2. Record actual API compatibility and sanitized observations, especially response
   envelopes, category acknowledgements, inventory visibility and consistency.
   Keep tenant data, credentials, raw captures, plans and state out of Git.
3. Before any live mutation, review the existing test helper's name-based cleanup:
   it must not delete a concurrent actor's object after an unconfirmed create.
   Add an ownership regression before relying on cleanup. This is a static review
   concern, not a reproduced appliance finding. Only after separate approval, test
   a disposable Panorama category with the required override file. Existing live
   automation covers device inventory and category create/import/rename/destroy,
   not all data sources, replacement, drift or recovery. A33.20 group validation
   needs a separate live matrix; current group tests are synthetic only. See the
   [unfinished checklist](user-testing.md#unfinished-live-acceptance-checklist).
4. Review dependency update PRs normally. No dependency updates or scope expansion
   are implicitly accepted by this handoff.
5. For new resources, prove create/read/update/delete/import contracts first and
   add failing ownership and recovery regressions before implementation changes.

## Development and release commands

Normal environment: Go and Terraform on PATH, plus a C compiler for the race
suite. Tool versions are declared in `go.mod`, `Makefile` and the CI workflow.

```sh
make fmt-check test vet vuln docs-check smoke actionlint
make generate                    # after schema/example/template edits
make coverage-check
make release-check               # includes package smoke and GoReleaser check
```

`make test` includes real Terraform protocol tests against synthetic local HTTPS
fixtures. `make testacc-read` is an explicit live operation; mutation additionally
requires the documented opt-in variables. See [user testing](user-testing.md).

### Future authorized releases

1. Bump `VERSION`, changelog and active example pins; regenerate docs. Preserve
   historical evidence rather than globally replacing old version strings.
2. Run release gates and exact-source CI. Freeze the source commit, then create a
   new tag; never overwrite a released version.
3. Verify the existing shared private/public key pair, derive its full fingerprint,
   match it to the Registry public key and test signing before building a release.
   Keep secret retrieval/signing in the approved credential boundary.
4. Build the clean tag using `goreleaser release --clean --skip=publish,sign`.
   Sign checksums in an ephemeral keyring and verify with an independent
   public-only keyring. Include the protocol manifest in the checksums.
5. Create a draft release with an explicit asset list. Download every uploaded
   asset, compare hashes/counts, and test the exact host ZIP before publishing.
6. Verify Registry indexing and then direct-only init in a fresh HOME/config/data
   directory with no mirror, development override or plugin cache. Require the
   expected signing key, checksum, schema and validation results.
7. Update current docs after verified publication without altering the immutable
   release tag or assets.

The maintainer's default signing path is Vault-backed. The hosted GitHub signing
job is opt-in (`RELEASE_SIGNING_MODE=github-secrets`) and is not the default release
mechanism. HCP Terraform token authentication is distinct from public Registry
onboarding. Existing onboarding already works: do not repeat the old browser/token
setup loop. An empty classic GitHub hooks list is not sufficient evidence that
Registry integration is absent; v0.1.4 indexed automatically after publication.

Host-specific tool paths, Vault record names and version-pinned helper scripts
belong in the local `terraform-provider-algosec` skill, not this portable runbook.
