# Final contract revision verification (0.1.2)

Target: ASMS / Firewall Analyzer A32.60 public REST contracts plus separately
gated experimental A33.20 Early Availability device groups. Final schema: two
resources (`url_category`, `device_group`) and twelve data sources. All API fixtures are
**synthetic**; no appliance acceptance or Registry installation has been claimed.

The implementation was built in an initially empty, uncommitted repository.
Reference checkouts were read-only. Source research, tool downloads, checksums and
command logs are in `/home/hermes/algosec-provider-work/` on the build host.

## Tool provenance

- Go 1.26.8 linux/amd64: official go.dev download checksum verified.
- Terraform 1.16.1 and 1.11.0 linux/amd64: official releases.hashicorp.com SHA256SUMS
  verified before extraction.
- GoReleaser 2.18.1: official GitHub release SHA256 checksums verified.
- govulncheck 1.8.0 and Go module dependencies: downloaded through Go's checksum
  database; dependencies pinned in go.mod/go.sum and tools/go.mod/tools/go.sum.
- Final race runs use the existing Zig 0.16.0 compiler (`zig cc`), CGO_ENABLED=1.
  No GCC packaging or system package installation was performed in this revision.
- actionlint 1.7.12 is pinned in Makefile and executed through the Go checksum database.
- Terraform 1.11.0 was already available; this revision independently compared its
  binary with the official ZIP after verifying the published SHA256SUMS.

## Local checks

Verified on 2026-09-09 with Go 1.26.8. Unit and protocol tests include schema retrieval, create/update/import/refresh/delete, external
removal and drift, read-only refusal, missing/null/unknown configuration, URL/IP
validation, escaped identifiers, authentication, TLS verification, redirect
refusal, bounded bodies, pagination errors, context cancellation and diagnostic
redaction. Device response credentials are explicitly discarded.

### Executed gates

- `go test ./...`: passed; live tests skipped.
- `TF_ACC=0 TF_ACC_TERRAFORM_PATH=.../tools/terraform go test -race -count=1 -timeout=10m ./...`
  with `CGO_ENABLED=1` and the existing Zig compiler: passed on Terraform 1.16.1
  (final provider package 80.077s). Includes synthetic group CLI/protocol lifecycle,
  rename replacement, disabled gates, partial-state recovery and category tests.
- Same uncached full suite without race on `.../tools/terraform-1.11.0`: passed
  (final provider package 35.243s).
- `make fmt-check vet`: passed. `go mod verify` in root and tools: both passed.
- `make vuln`: root and tfplugindocs tool dependency scans reported no vulnerabilities.
- `make generate` and `make docs-check`: generated docs/examples reproduce exactly.
- Compiled `scripts/smoke.py` with Terraform 1.16.1 and 1.11.0: schema is exactly
  2 resources / 12 data sources, validate passes, plan has exactly two creates.
  No refresh or apply occurs.
- `make actionlint`: passed with pinned actionlint v1.7.12, validating both workflows.
  Release workflow already had the pinned GoReleaser v2.18.1 check/install step
  before `make release-check`; retained that ordering.
- `goreleaser check`: passed. `goreleaser release --snapshot --skip=sign --clean --parallelism=2`:
  builds all eight OS/architecture ZIPs (Darwin, FreeBSD, Linux, Windows; amd64/arm64),
  plus checksums and manifest metadata, without signing or publishing.
  All eight archive checksums and the manifest checksum were independently verified.
  The extracted Linux amd64 snapshot binary also passed schema/validate/plan smoke
  on both Terraform versions.
  Since this repository has no commits or tags, the snapshot version is honestly
  `0.0.0-SNAPSHOT-none`, not a tagged 0.1.1 release.
- The ownership correction changes the group create client and its callback timing test, and adds focused provider regressions. Other imported extension code, parent module files and category resource implementation were not replaced.

Final command logs are outside the deliverable in
`/home/hermes/algosec-provider-work/final-*.log`; checksum evidence is in
`final-terraform-1.11-checksum.txt`. These are local results, not GitHub Actions
execution or appliance acceptance.

## Known limits

The official docs contain inconsistent path capitalization, wrappers and some
missing response examples. The precise choices and exclusions are recorded in
[API coverage](api-coverage.md). Synthetic tests verify the implementation against
those selected contracts, not the correctness of upstream documentation.

Live mutation tests require TF_ACC=1, ALGOSEC_ACC_MUTATION=1 and
ALGOSEC_ACC_DISPOSABLE=1. Only category live mutation tests remain; device-group
tests are synthetic only. Read-only live tests cannot mutate administration objects. Neither was
run. No Vault access, live-appliance contact, external mutation, commit, tag, push,
repository creation or publication occurred.

Release CI and GPG signing configuration are present. Actual GitHub workflow
execution, signing credentials, signed release publication and Registry onboarding
remain unverified. Local snapshots skip signing and publishing.

## New-group ownership correction

Group create records Terraform ownership only after a successful POST response with a validated positive acknowledgment, before inventory readback. Unconfirmed creates (HTTP or transport errors, malformed or unsuccessful acknowledgments) leave no managed state and do not adopt a visible group. If the POST outcome is ambiguous, inspect the remote group and verify ownership before importing or retrying. An acknowledged create retains recoverable identity if readback fails; successful readback still verifies exact membership. Existing-owned update/delete partial-state recovery is unchanged.

The supplied regression was copied into main and failed before the fix with
`definitively rejected create retained ownership of another actor's group`.
Current correction evidence and exact command outputs are recorded in
`/home/hermes/algosec-provider-work/ownership-fix-report.md`; earlier final logs above describe the preceding revision.

Post-fix gates passed on 2026-09-09: focused RED/GREEN; complete race/coverage
unit and synthetic Terraform protocol suite on 1.16.1; uncached complete suite
on 1.11.0; vet; fmt-check; generated docs consistency; actionlint; root/tools
module verification; GoReleaser configuration check. Root vulnerability scan
found none; the tools scan found no reachable vulnerabilities (one required-module
vulnerability with no affected imported package or call path). Compiled smoke
verified exactly 2 resources, 12 data sources and 2 planned creates on both CLIs.
Unsigned snapshots were rebuilt with the existing snapshot command.
All eight rebuilt ZIP checksums and the manifest checksum passed verification;
the extracted Linux amd64 artifact contains the correction diagnostic and passed
compiled smoke on both Terraform versions.
