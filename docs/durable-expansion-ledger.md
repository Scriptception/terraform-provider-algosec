# Durable expansion ledger and continuation

Active branch: `feat/durable-api-expansion`, based on clean
`c0ffbdb5bbda0b762acf37ebaf0cae66c481c924`. Sole implementation writer.
Development candidate: **0.3.0-dev**, unpublished. Published 0.2.0 pins and release
history remain unchanged. No appliance calls, credentials, Vault, remote changes,
tags, signing, publication or policy changes occurred. Public documentation and
local synthetic HTTPS are the only API evidence used.

## First coherent batch

- Implemented **`algosec_appviz_role`**: separately gated AppViz SaaS EA role,
  typed bearer client, complete readable authorization/membership sets, import,
  delta updates, guarded replacement, positive create ownership, fail-closed
  absence and recoverable state. [Exact contract and limitations](appviz-role-contract.md).
- Independently reproduced and fixed three baseline regressions: unowned category
  name cleanup, known-invalid category IP bypass with unknown siblings, and null
  group membership replacement. Supplied no-delete assertions are preserved.
- Added runnable cross-product inventory validation and integrity regressions.
  [Selected implementation mapping](api-inventory.json) has **24 operations**;
  provider registration/schema has **4 resources and 12 data sources**.
- Full managed set: `algosec_url_category`, `algosec_device_group`,
  `algosec_trusted_rule`, `algosec_appviz_role`. No new data sources are counted as
  managed lifecycle expansion. All compatibility remains synthetic/unverified live.

## Discovery versus implementation

[Cross-product inventory](cross-product-operations.json): **934 records**, comprising
**772 REST operation records and 162 unresolved SOAP service/binding records**.
Per product: AFA 525, legacy AppViz 141, FireFlow 114, AppViz SaaS 71, ACE 65,
ObjectFlow 18. SOAP local names without certified operation QName remain unresolved;
even documented QNames without a service/binding are not executable SOAP contracts.
All records carry source URLs, retrieval, auth/version boundary and disposition.
Selected canonical routes exist only for implemented mappings. Raw route labels,
contradictory examples and documented server/base context are separate fields.
Relative labels are keyed with documented catalog/server path context to avoid
collapsing unrelated `/new`, `/{id}` or `/login` operations. No route normalization
silently repairs vendor spelling, case, embedded newlines or slashes.

The ledger maps 24 implementation records; other-version equivalents remain
unverified. Imported parent/researcher catalogs are discovery evidence, not an
independent lifecycle approval. The original 204-page AFA baseline is retained
separately. Graph discovery reached 1021 official pages in the parent's corpus,
but this batch does not claim all graph-linked operations are reconciled into the
934-record inventory. AppViz SaaS service-level auth and model nodes are separate
from its 71 operation nodes. No overall coverage percentage is claimed.

Public version discovery reached **A33.30 Horizon Foundation**, under
`https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/`.
This differs from A32.60/A33.20 `/en/asms/.../asms-help/` and from the unversioned
SaaS stream. The writer independently fetched priority contracts in all three
legacy versions, and directly retrieved SaaS public schemas and role metadata.

## Candidate dispositions and exact reopening conditions

| Candidate | Current state | Evidence/gap or next action |
|---|---|---|
| AppViz SaaS role | Implemented experimental | [Contract](appviz-role-contract.md); live acceptance and unreadable metadata limitations retained. |
| Legacy AppViz owned service objects | Evidence-blocked A32.60/A33.20/A33.30 | [Read schema](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/networkservice.htm) returns strings; [create](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/post-new_2.htm) writes protocol/port objects. Need reversible content grammar, current-revision lookup and non-device provenance; replacement does not fix these gaps. |
| Legacy AppViz network Host/Range/Group/Abstract | Evidence-blocked A32.60/A33.20/A33.30 | [Create](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/post-new_1.htm) newObject.id/endpointGroupId lacks mapping to [read](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/networkobject.htm) revisionID/objectID; latest revision/provenance and Group/Range equivalence unresolved. Need positive identity mapping before state, not same-name adoption. |
| AppViz SaaS owned services/network objects | Evidence-blocked selected snapshot | Public service schemas still read service item names without port/protocol grammar; network create newObject is untyped. Need current identity/read representation mapping; do not copy legacy auth or models into SaaS. Public schema snapshots retained externally. |
| Legacy ordinary/shared/subscribed application flows | Evidence-blocked selected lifecycle | [Create](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/post-id-flows-new.htm), [edit](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/post-id-flows.htm), [delete](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/delete-id-flows-flow_id.htm): need draft acquisition/ownership, revision transitions and import identity; edit singular/plural route and typed fields conflict. Never apply/discard another actor's draft. |
| Legacy application container | Evidence-blocked destroy | [Decommission](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/post-id-decommission.htm) literal `decommisson` and change-response semantics do not prove terminal destroy/recreation. Need exact route, terminal state and ownership. |
| AppViz SaaS application/flow and legacy child metadata (contacts/labels/custom fields) | Unassessed | Richer SaaS schemas recovered; inspect each specific draft/child lifecycle. Existing legacy container blockers are not proof that every child binding is blocked. |
| AFA whole users/roles | Evidence-blocked current public read mapping | Fresh A33.30 [roles GET](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/retrieving_roles.htm) still has malformed fields/query session; [write](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/roles_create_post.htm) enableGlobalTrustTraffic is not proved equivalent to EnableGlobalCustomization. Need complete readable permissions, safe auth and secret-free user password inputs. |
| AFA devices: direct brands, managers/children, cloud connectors, file devices | Evidence-blocked complete refresh | Fresh [detail](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/device-details.htm) has no complete configuration response schema; [write](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/device-add_edit1.htm) templates/testMode are not live readback. Reopen per brand with authoritative managed nonsecret fields, positive identity and child/delete ownership. |
| AFA A33.30 ALGOSEC tags | Implementation candidate; next batch | [Create](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tags-create-post.htm), [list](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tags-all-tags-get.htm): parent dossier proposes explicit object-create/array-read/empty-ack choices, numeric-ID import and association-loaded delete guard. Review pagination exhaustion, contradictions and risk references before code. Do not blanket block due missing appliance. |
| AFA tag-hostgroup assignment | Unassessed mapping | Need stable deviceDataId/canonized hostgroup versus write deviceTreeName mapping and includeAssociations=true; no whole relation ownership. |
| FireFlow A33.30 direct role permission/member bindings | Implementation candidates; next batch | Independently re-fetched [permission GET](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/mf-roles-id-permissions-get.htm) and [POST](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/mf-roles-id-permissions-post.htm), plus members GET/POST. Separate FireFlow_Session auth, singleton delta, explicit Success ack and direct/inherited reads support bounded binding work. Parent dossiers available; implement with ownership regressions. |
| FireFlow whole roles/users and SOAP custom-field assignments | Evidence-blocked full lifecycle | No whole-role DELETE; user mutation not established. Mixed REST/SOAP custom fields require certified identity/auth/namespace/binding and safe value ownership. Do not invent role delete or infer SOAP binding. |
| FireFlow tickets, sub-ticket configurations and object change requests | Workflow boundary | Ticket configuration is reversible but scoped to a change request, not global durable configuration. Submission/status is not authoritative deployed network/service CRUD. Keep workflows out of managed resources. |
| AFA map ignored-interface, URT, tunnels, risk/config/zone and remaining durable families | Unassessed | Parent map/URT evidence and broader graph must be reconciled; require read/identity/auth/reset semantics per candidate. Preserve generic secret-bearing config exclusions until narrowed. |
| ACE Jira integration, threat entries, cloud onboarding, risk profiles, CD mitigation | Unassessed | Official public SaaS exports exist; inspect parent findings and each operation's read/auth/delete/secret gaps. Missing legacy appliance Swagger is not a blocker for those public exports. |
| ObjectFlow owned network objects and custom-field definitions | Unassessed | Official public SaaS CRUD-shaped contracts exist; device selection may open FireFlow requests. Resolve owned-object versus deployed-device semantics, complete fields, identity and deletion before implementation. |

## Verification evidence

External directory: `/home/hermes/algosec-expansion-evidence/implementation`.
Actual RED logs: `01-client-red.log` (missing typed API), `02-protocol-red.log`
(missing provider surface), `03-baseline-red.log` (all three destructive baseline
regressions reproduced), `04-trailing-json-red.log` (extra JSON accepted),
`08-inventory-red.log` (missing validator).
GREEN: `01-client-green.log`, `02-protocol-green.log`, `03-04-green.log`,
`05-client-safety.log`, `06-framework.log`, `08-inventory-green.log`.

The first full test run found the expected schema-count update and an existing
null-set diagnostic regex mismatch; both were corrected without weakening safety
assertions. A later combined gate run passed race tests/vet/vulnerability checks
but stopped at docs parity because documentation edits overlapped its snapshot.
Final settled-tree gates all passed, including release-check and targeted Terraform
1.11.0 tests; see [batch verification](durable-expansion-verification.md).
These are local synthetic tests, never appliance acceptance.

## Runnable continuation after parent frozen-source review

1. Read `AGENTS.md`, this ledger, `docs/appviz-role-contract.md`, and `git status`.
   Preserve the branch and unrelated work. Parent owns remote push/PR/merge.
2. Parent independently reviews the frozen first batch, then supplies fixes or
   next-batch direction. Broad expansion is **not complete**: unassessed/candidate
   rows above are real remaining work, not evidence-blocked by fiat.
3. Next implementation priorities: A33.30 FireFlow singleton role permission/member
   bindings, AFA tags, then remaining AppViz SaaS/ACE/ObjectFlow candidates. Read
   external `afa/{tag-implementation-contract,current-actionable-addendum}.md`,
   `appviz/`, `fireflow-boundaries/`, and any `map-urt/` dossier. Treat them as
   evidence; independently verify official contracts before coding.
4. Reconcile the parent's `catalog-discovery/canonical-page-index.json` (1021 pages)
   with `docs/cross-product-operations.json`; add graph-only operations with literal
   routes, evidence and disposition. Import no raw HTML, credentials or source dumps.
5. Capture actual RED tests externally before fixes, implement typed lifecycle,
   retain confirmed state, never adopt on failed create, validate replacement
   before deletion. Preserve all category/group/trusted/AppViz regressions.
6. Use the supplied tools, no system installs:

   ```sh
   export PATH=/home/hermes/algosec-provider-work/tools/go/bin:/home/hermes/algosec-provider-work/tools:$PATH
   export CGO_ENABLED=1
   export CC='/home/hermes/algosec-provider-work/tools/zig-x86_64-linux-0.16.0/zig cc'
   make fmt generate
   python3 scripts/coverage_check.py --write
   make fmt-check test vet vuln docs-check smoke coverage-check actionlint package-smoke
   make release-check
   ```

   `make test` uses TF_ACC=0. The cleanup regression invokes the live helper only
   in an environment-scrubbed child against its local synthetic trusted TLS server.
   Do not invoke live targets or any appliance. Keep repeatable external logs.
7. Generate docs only after schema/examples edits settle, then freeze documentation
   during docs-check. Update only the unreleased candidate version for capability
   changes. Stage explicit reviewed paths; make a local coherent commit only once
   gates pass, report exact commit/tree, and leave remote publication to parent.
