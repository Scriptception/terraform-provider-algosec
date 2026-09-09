# Durable expansion batch 1 verification

2026-09-09, `feat/durable-api-expansion`, based on
`c0ffbdb5bbda0b762acf37ebaf0cae66c481c924`; unreleased `0.3.0-dev`.
One writer. No appliance, real credentials, Vault, tags, signing, remote changes
or publication. Published 0.2.0 installation pins and historical evidence remain
unchanged. Parent independent frozen-source review is still required.

## Delivered and verified scope

New resource: **`algosec_appviz_role`**, AppViz SaaS vendor Early Availability,
separate bearer authentication and opt-in. See the [contract](appviz-role-contract.md).
It implements exact role GET, create, user/global permission delta update and
delete; import uses the case-sensitive name. Application permission/name/enabled
changes replace with known-input validation before destruction. Positive create
responses establish ownership; errors preserve confirmed recovery state.

The compiled Terraform schema independently reports exactly:

- `algosec_appviz_role`
- `algosec_device_group`
- `algosec_trusted_rule`
- `algosec_url_category`

**4 resources, 12 data sources, 24 selected method/routes.** Cross-product
inventory validation reports **934 discovery records**, including 772 REST and
162 unresolved SOAP service/binding records. Twenty-four records map to current
implementation. The inventory has 457 explicitly unassessed records; this batch
is not comprehensive provider completion. See the [continuation ledger](durable-expansion-ledger.md).

## Actual failing regressions and fixes

External evidence directory:
`/home/hermes/algosec-expansion-evidence/implementation/`.

| Evidence | Actual failure before implementation/fix | Final behavior |
|---|---|---|
| `01-client-red.log` | Missing AppVizClient/NewAppVizClient/AppVizRole | Typed role client, no failed-create read/adoption |
| `02-protocol-red.log` | Unsupported SaaS provider arguments | Protocol create/import/update/external deletion/destroy |
| `03-baseline-red.log` | Cleanup issued one unowned DELETE; category/group invalid replacements deleted owned objects | State-led test cleanup; known category IP and null member validation before deletion |
| `04-trailing-json-red.log` | Concatenated JSON accepted as role state | Invalid/trailing JSON rejected before decoding |
| `08-inventory-red.log` | Missing operation inventory validator | Duplicate keys, missing evidence/mapping and unresolved SOAP namespace regressions pass |

The independent baseline review's no-delete assertions are preserved in
`baseline_review_test.go` and `baseline_cleanup_test.go`. The latter executes
the live helper only in a scrubbed child process pointed at its own synthetic
localhost TLS server; no appliance endpoint or real credential can be inherited.

Additional tests exercise duplicate/conflicting permission data, partial/malformed
responses, denied/not-found reads, create identity retention on readback failure,
update/delete recovery, external drift refusal, TLS verification, redirects,
transport ambiguity without retry, read-only/experimental gates, application
permission replacement/import and invalid inputs with unknown siblings. Fixtures
are synthetic and the new SaaS protocol tests trust the fixture CA rather than
disabling TLS. No resource state includes the bearer token.

## Executed gates

Supplied tools: Go **1.26.8**, Terraform **1.16.1** and **1.11.0**, with
`CGO_ENABLED=1` and supplied Zig 0.16.0 `zig cc`. No system packages installed.

`final-generate.log`: `make fmt generate` passed after schema/example/template edits.

`final-gates.log`: the following complete command exited zero:

```sh
make fmt-check test vet vuln docs-check smoke coverage-check actionlint package-smoke release-check
```

This covers race/protocol tests against synthetic HTTPS, vet, root/tool vulnerability
scans, generated docs parity, compiled offline plan/schema smoke, cross-product
inventory tests/mappings, actionlint, local candidate ZIP mirror init/validate/schema,
module verification and `goreleaser check`. It does not publish, sign, build a
release tag, or establish Registry/appliance acceptance. Terraform smoke reports
four creates and four resource schemas; package smoke preserves the published
quickstart pin and substitutes the candidate only in its temporary copy.

Final full-suite statement coverage: **79.7% client, 82.4% provider**. Root
vulnerability scan found none. The tools scan reports zero affecting vulnerabilities
and one module-level finding outside imported/called code; no dependency upgrade
was made.

`terraform-1.11.log`: targeted race/protocol tests passed on **Terraform 1.11.0**:
AppViz lifecycle and Framework recovery, all three new baseline regressions, and
existing category/group/trusted-rule lifecycles. Exit zero, 39.715 seconds.

Earlier failures are retained: `07-full-test.log` found the expected resource-count
assertion update and a null-set diagnostic-regex mismatch; neither involved weakened
ownership assertions. `full-gates.log` passed test/vet/vulnerability checks then
failed docs parity because docs edits overlapped its snapshot. The frozen final
run passed. Final documentation evidence additions are checked again separately
with `docs-check coverage-check` before the local commit.

## Remaining work

Legacy AppViz service/network/flow contract gaps are explicitly documented;
SaaS service/network gaps are not filled with invented mappings. A33.30 tags,
FireFlow direct membership/permission bindings, other AppViz metadata, ACE and
ObjectFlow candidates remain listed with next actions. Parent graph discovery has
1021 pages and still needs graph-only operation reconciliation. No unassessed
candidate is silently marked blocked or complete. Parent reviews this coherent
first batch before further implementation or remote action.
