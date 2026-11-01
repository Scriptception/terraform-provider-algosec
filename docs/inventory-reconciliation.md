# Reconciled discovery and current implementation

The cross-product inventory preserves 975 independent candidate IDs and 1,048
source observations: 747 REST records with selected research routes, 66 unresolved
REST records, and 162 SOAP catalog names with zero certified operation QNames.
Discovery records are not a coverage percentage or executable API certification.

Original record fields, labels, versions, auth provenance and classifications are
historical evidence. `integration` records the independent reconciliation;
`current_implementation` separately maps the current selected operations to exact
candidate IDs, source functions, tests and Terraform surfaces. Original broad
blockers do not override the additive second-review nominations. Current final
independent source review and all live acceptance remain pending.

The 71 public SaaS operation identities are separate from 210 cached nodes. Seven
internal exported operations remain exclusions. Shared service operations are
counted once with product associations. Fifteen missed REST routes and 39 AppViz
supplemental observations are reconciled with their source pointers, not blindly
appended or normalized. No compatibility transfers across versions or auth services.

Frozen sanitized inputs under `scripts/inventory/inputs` contain metadata only,
with hash manifests and official-source provenance. `scripts/inventory/transform.py`
and `verify_inventory.py` reproduce and verify the historical audit. The current
validator additionally checks every implementation mapping against
`docs/api-inventory.json` and actual source/test files. It detects dropped source
observations, changed identities, missing mappings, invented functions and version
transfers. `make coverage-check` runs both suites and compares the generated
baseline page tables. Discovery, selected operations, resources and data sources
are reported separately.
