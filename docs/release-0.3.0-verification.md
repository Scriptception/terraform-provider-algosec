# v0.3.0 publication verification

Published on 2026-09-09 to the [Terraform Registry](https://registry.terraform.io/providers/Scriptception/algosec/0.3.0)
and [GitHub Releases](https://github.com/Scriptception/terraform-provider-algosec/releases/tag/v0.3.0).

Immutable release source: `6d770baea9f4ff668d7164064286809e590ab165`, tree
`75c3a82962f526bf82e9cfa3d1ef5651b6f8f29f`, merged through [PR #6](https://github.com/Scriptception/terraform-provider-algosec/pull/6).
[Exact-source CI](https://github.com/Scriptception/terraform-provider-algosec/actions/runs/34330092847)
passed both Terraform versions and vulnerability checks. Later documentation commits
do not change the release source or assets.

## Verified distribution and compatibility

- Twelve release assets were uploaded, downloaded, and hash-compared. Eight platform
  archives were built; execution was verified on Linux amd64 only.
- Nine files (eight ZIPs and the protocol manifest) are checksummed. The checksum
  signature verified independently using the existing shared public key:
  `BB831B4CD32200DD15EDF4E9AB71E7968334DF52`.
- Registry package metadata matched the uploaded Linux archive hash. Direct-only
  installation in fresh HOME/config/data directories, without mirrors or plugin
  caches, passed signature verification, validation and schema loading on
  Terraform 1.11.0 and 1.16.1: 12 resources and 12 data sources.
- Local release-check passed format, race/protocol tests, vet, reachable-vulnerability
  checks, generated docs, inventory/coverage, package installation, offline plan,
  actionlint, module verification and release configuration validation.
- The [published-state migration harness](published-upgrade.md) passed on both
  Terraform versions against the combined candidate source. Actual v0.2.0-created
  state retained IDs and owned values with zero mutations during upgrade/refresh;
  controlled drift and final owned cleanup preserved unrelated sentinels.
- Documented ephemeral Jira/AWS bootstrap examples validated and serialized saved
  plans on Terraform 1.16.1, with bootstrap values absent from plan JSON.

## Scope and limits

The release implements 53 selected method/route operations. Additional API families
remain future work; this is not full AlgoSec administration coverage. All new
experimental opt-ins and ownership limitations remain in effect. Write-only inputs
require Terraform 1.11+; documented ephemeral saved-plan examples require 1.16.1+.
Synthetic HTTPS fixtures and migration tests are not live appliance acceptance.
No live appliance testing was performed for this release.
