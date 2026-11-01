# First managed-resource expansion verification (historical)

This records the reviewed `0.2.0-dev` implementation and expiry-fix evidence before
release metadata preparation. Version strings and quickstart-pin observations
below are historical; they do not describe current 0.2.0 metadata or establish
0.2.0 publication, Registry verification or live acceptance.

2026-09-09, branch `feat/public-coverage-expansion`, unreleased `0.2.0-dev`.
Published v0.1.4 is unchanged. One writer preserved the existing roadmap/handoff
work. No commits, tags, external mutations, credentials, Vault, appliance calls,
dependency upgrades or system package changes were made.

Implemented `algosec_trusted_rule` and typed GET/POST/DELETE operations. See
[the official contract dossier](trusted-rule-contract.md) for route/auth choices,
ownership, replacement, import, absence, expiry and concurrency limits. Inventory
is now 3 resources, 12 data sources, 20 operations; 85 + 119 documentation pages.
This is one managed-resource milestone, not comprehensive product coverage.

## Test-first evidence

Logs are outside Git in the authorized mission evidence directory.

| Slice | Actual RED | GREEN |
|---|---|---|
| 01 client create | Missing option, type and CreateTrustedRule method | Exact per-rule acknowledgement; unconfirmed creates never read/adopt |
| 02 delete/read integrity | Missing DeleteTrustedRule method | Delete preflight, acknowledgement, absence readback; incomplete reads refused |
| 03 Terraform protocol | Unsupported experimental_trusted_rules provider argument | Create/import, replacement and clearing, external drift/deletion, destroy |
| 04 duplicate JSON | Conflicting duplicate keys established ownership | Duplicate keys rejected |
| 06 conflicting envelopes | Case-variant keys and fieldErrors established ownership | Conflicts and unknown acknowledgement fields rejected |
| 07 partial inventory | Partial/status/nextPage/Error fields proved absence | Undocumented device/rule fields fail closed |

Commands for slices used `go test ./internal/client -run TestTrustedRule -v`
and `TF_ACC=0 TF_ACC_TERRAFORM_PATH=$(command -v terraform) go test
./internal/provider -run TestProtocolTrustedRule -v`, narrowing `-run` to the
named regression for each later RED. Evidence files preserve the actual failures,
not reconstructed results. Additional recovery tests cover expired dates,
403/404/5xx, transport ambiguity/no replay, existing assignment refusal, readback
mismatch and retained Framework create/read/delete/update-error state. Protocol
safety tests exercise disabled/null gates, read-only defaults/null, invalid
identifiers and dates, and expired-create refusal before any fixture request.

## Verification environment and commands

Supplied local Go 1.26.8, Terraform 1.16.1 and 1.11.0, GNU Make 4.4.1 and Zig
0.16.0 were used. PATH puts the mission's `tools/go/bin` and `tools` first;
`CGO_ENABLED=1`, `CC` selects the supplied Zig executable with `cc`.
All Terraform lifecycle traffic goes to synthetic local HTTPS fixtures.

```sh
make fmt generate
python3 scripts/coverage_check.py --write
make fmt-check test vet vuln docs-check smoke coverage-check actionlint package-smoke
TF_ACC=0 TF_ACC_TERRAFORM_PATH=/path/to/provided/terraform-1.11.0 \
  go test -race -count=1 ./internal/provider \
  -run 'TestProtocolTrustedRule|TestProtocolCategoryLifecycle|TestProtocolDeviceGroupLifecycle' -v
git diff --check
```

Initial full testing found the expected surface-count regression (2 versus 3
resources) in `TestProtocolSchema`; that assertion was updated without changing
category/group lifecycle behavior. All requested gates passed: fmt-check, race tests, vet, vuln, docs-check,
smoke, coverage-check, actionlint and package-smoke. Client statement coverage
was 81.9%; provider coverage was 83.0%. Minimum Terraform 1.11.0 passed the
trusted-rule lifecycle/safety and existing category/group lifecycle tests.
The vulnerability gate reported zero affecting vulnerabilities; its tools scan
also noted one module-level vulnerability outside called/imported packages.
Exact output is retained outside Git; no dependency upgrade was made.
Detailed command outcomes are recorded in the mission report outside Git. Source tests are synthetic, not appliance
acceptance. Package smoke installs the local candidate through a filesystem ZIP
mirror, with no signature or Registry-publication claim. Published quickstart
pins remain at v0.1.4; only the temporary package-smoke copy selects the candidate.

Remaining acceptance: separately authorized live A33.20 auth/base-path validation,
complete visibility, optional metadata defaults, expiration cleanup/timezone,
concurrent-writer behavior and disposable lifecycle recovery. The mission's parent
must independently review the frozen scope before final acceptance.


## Independently reproduced expiry replacement fix

A separate review reproduced a destructive invalid replacement: changing an
indefinite assignment to `2000-01-01` passed planning, deleted the assignment,
then failed create-time validation. The original verification above did not
cover this ordering defect.

The parent regression was adapted into maintained tests and run against the
current working source before the fix. It failed with
`invalidDeletes=1 exists=false`. Additional test-first coverage reproduced
deletion on metadata replacement of an imported expired assignment.
Resource `ModifyPlan` now rejects known invalid expiry for creation or changed
managed inputs before deletion, retaining create-time revalidation. It leaves
unchanged expired imports, refresh/no-op and destroy valid. Framework tests
verify unknown expiry is preserved and known invalid expiry is rejected with
unknown identity. Unknown dates and dates expiring between plan and apply remain
apply-time limitations, as described in the contract.

Evidence is retained outside Git under the mission's `fix-expiry/` directory:
`red.log`, `red-additional.log`, `green.log`,
`terraform-1.11.0.log`, and `full-verification.log`.
These are synthetic fixture results, not live appliance acceptance.
The fix passed focused GREEN, the full requested Make gates (fmt-check, test,
vet, vuln, docs-check, smoke, coverage-check, actionlint, package-smoke), and
targeted Terraform 1.11.0 trusted-rule protocol/Framework tests with the race
detector. Full-suite statement coverage was 81.9% client and 83.1% provider.
The tools vulnerability scan again reported zero affecting vulnerabilities and
one module-level finding outside called/imported packages. Docs were regenerated;
the candidate remains `0.2.0-dev` and published v0.1.4 is unchanged.
