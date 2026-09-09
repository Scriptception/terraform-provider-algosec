# 0.1.3 candidate verification

Prepared on 2026-09-09 from clean main
`c659b5eb24f5ab5aeb662c50c7c1eb5299de509d`. Changes remain uncommitted for maintainer
review. Scope is unchanged: 2 resources / 12 data sources, 17 client method/route
operations including login. All API fixtures are synthetic. This document records
this preparation's executed checks, not previous revisions' release claims.

## Evidence and TDD

The independent publication audit and captured official A32.60 create, rename and
delete pages were read. Their URLs and selected contract choices are in
[API coverage](api-coverage.md) and [implemented operation mapping](api-inventory.json).
No captured HTML or raw appliance data is bundled.

- Copied the audit's `audit_category_ownership_test.go` into the maintained suite.
  Before the fix, `go test ./internal/provider -run
  TestAuditCategoryUnconfirmedCreateMustNotAdopt -count=1` failed all four original
  safety cases: `{}`, `false`, message-only failure and empty categories map.
  Each acquired state and performed a second GET, with no diagnostics.
- Expanded the same assertions with arrays/null, malformed JSON, false status,
  wrong name/URL membership and null URL maps. These now require diagnostics,
  exactly one preflight GET and no newly acquired state.
- Client regression tests cover wrong IP/URL membership, invalid IPs and positive
  acknowledgement with reordered IP sets. Provider tests cover positively
  acknowledged create with failed GET, ambiguous rename/delete retaining prior
  state, and acknowledged delete requiring subsequent GET.
- An additional rename wrong-membership regression failed before tightening rename
  acknowledgement, then passed. Rename now requires exact prior membership under
  the new name and absence of the old name before advancing identity.
- Focused final GREEN command:
  `go test ./internal/client ./internal/provider -run
  'TestAuditCategory|TestCreateCategoryExactAcknowledgementMembership|TestMutationResponseErrors'
  -count=1 -v` passed.

Raw logs remain outside the repository in the maintainer's supplied work directory:
`category-release-red.log`, `category-rename-red.log`, and
`category-release-green.log`. The original adversarial assertions were retained.
The existing synthetic server already returned the selected documented categories
maps for all three operations; comments now explain the delete response-table
choice. No alternate write route, response retry or guessed payload was introduced.

## Tools and executed gates

Observed local tools: Go **1.26.8 linux/amd64**, Terraform **1.16.1** and **1.11.0**.
Race tests used `CGO_ENABLED=1` with the supplied Zig 0.16.0 `zig cc` compiler.
Tools were provided locally; their download provenance was not reverified during
this preparation. Module authenticity was checked using `go mod verify` in both
root and tools modules (both passed).

| Command | Result and scope |
|---|---|
| `make fmt-check test vet docs-check smoke package-smoke coverage-check actionlint` | Passed on Terraform 1.16.1; final code revision. |
| `make test smoke package-smoke TERRAFORM=terraform-1.11.0` | Passed on final code: race/protocol, compiled plan smoke and packed-ZIP init/validate/schema. |
| `make vuln` | Passed: root reports no vulnerabilities; tfplugindocs reports no affected symbols/imported packages, with one vulnerability in a required module not called by the tool. |
| `go mod verify` and `go -C tools mod verify` | Both passed; no module files changed. |
| `goreleaser check` | Passed; configuration validation only. |
| `make fmt generate` | Passed; templates/examples regenerated. Final `docs-check` confirmed exact parity. |
| `python3 scripts/coverage_check.py` | Passed: 85 A32.60 + 119 A33.20 pages, classification totals, evidence URLs/versions, source route/method expressions, and 2/12 surface mapping. No network calls. |
| `git diff --check` | Passed. |

`make test` runs race/coverage unit tests and actual Terraform protocol lifecycles
against local synthetic HTTPS servers with `TF_ACC=0`. Live acceptance is skipped.
The final 1.16.1 provider suite completed in 24.798 seconds, with provider coverage
82.4% and client coverage 80.2%. These are software-contract tests, not proof of
appliance compatibility.

`make smoke` built the provider and verified schema, validate, and an offline plan
with exactly two resource creates using a development override. `make package-smoke`
packaged that actual local binary into a candidate ZIP and verified real Terraform
init, the pinned read-only quickstart's validate, and schema loading via an isolated
packed filesystem mirror. It performed no plan/data-source reads or appliance calls.
The local ZIP is a smoke fixture, not a final version-stamped GoReleaser release or
an authenticated signed artifact. The script also accepts `--archive` for parent
verification of the exact final host ZIP.

Gate logs: `release-final-gates.log`, `release-final-minimum.log`,
`release-modules.log`, `release-tool-modules.log`, `release-goreleaser.log`.
The vulnerability result is in `release-gates.log`. That initial combined run
stopped at docs parity because inventory edits overlapped its snapshot; the settled
documentation passed the subsequent final run. Initial failures are not hidden.
These logs are local execution evidence, not GitHub Actions execution results.

## Signing setup after code review

The maintainer created an RSA-3072 signing key through the approved Vault wrapper
and verified the stored record by reading it back. Fingerprint:
`71B43325624199D6C4339C17EE5515CFD4999B22`. Private key generation used an ephemeral
tmpfs keyring; the persistent private key and passphrase remain in Vault. The
hosted signing workflow now requires explicit `RELEASE_SIGNING_MODE=github-secrets`
opt-in; the default release is built and signed by the Vault-backed maintainer
process, not by copying Vault secrets into GitHub. The pending list below records
what the earlier code-preparation run did not do; final release evidence belongs
to the corresponding GitHub release.

## Pending external and live verification

- No GPG key is available yet. No signing, key access, signed checksum verification,
  release tag, push, Registry onboarding, publication or Registry installation was
  performed. Parent handles external systems.
- No final cross-platform archive build was performed in this preparation. Parent
  must build/review/sign final archives and execute `scripts/package_smoke.py
  --archive ...` on the actual host release ZIP, plus validate other target platforms.
- No credentials were read and no appliance was contacted. A32.60 base compatibility,
  Panorama override prerequisites, acknowledgement shapes, delayed consistency and
  A33.20 EA group behavior still require authorized appliance evidence.
- Category delete's nested vendor example conflicts with its response table. The
  selected single categories map fails closed on that malformed example; owned
  state is retained. Preflight/acknowledgement cannot eliminate concurrent-writer
  races without a documented conditional-create/transaction contract.
- Read-only quickstart plan contacts the appliance and still exposes inventory to
  plan/state despite count-only outputs. Protect state and use environment auth/TLS.
  See [user testing and publication checklist](user-testing.md).
