# Durable expansion ledger and continuation

Publication update: the implemented subset is released as v0.3.0; see
[verified release evidence](release-0.3.0-verification.md). Unreleased descriptions
below preserve earlier development checkpoints. Unassessed families remain future
work and are not claimed as implemented or evidence-blocked by publication.

Active branch: `feat/durable-api-expansion`, based on clean
`c0ffbdb5bbda0b762acf37ebaf0cae66c481c924`. Sole implementation writer.
Development candidate: **0.3.0-dev**, unpublished. Published 0.2.0 pins and release
history remain unchanged. No appliance calls, credentials, Vault, remote changes,
tags, signing, publication or policy changes occurred. Public documentation and
local synthetic HTTPS are the only API evidence used.

## Current FireFlow direct-binding and review-fix sub-batch

Batch 2 independent review reproduced malformed AppViz wrapper bodies, ambiguous
URL/IP JSON and a consistently wrong route mapping. Retained regressions now reject
these inputs before confirmation/adoption/absence; category and URL identifiers
remain case-sensitive. Source mapping checks bind the selected function request.

Current surface: **12 resources, 12 data sources, 53 selected operations**.
`algosec_fireflow_role_member` owns one direct User/Role tuple;
`algosec_fireflow_role_permission` owns one direct System/CustomField/RequestTemplate
permission tuple. [Contract](fireflow-binding-contract.md): separate verified-TLS
FireFlow_Session client, exact Success acknowledgements, preserved inherited and
unrelated grants, canonical import, replacement validation and recovery. Parent-role
inverse routes are represented by role membership, not counted twice.

[Full sub-batch gates](durable-expansion-batch3-verification.md) passed on
Terraform 1.16.1 and 1.11.0. Final parent frozen review remains pending; no live
acceptance or final closure is claimed. Narrowed AppViz/ACE subsets remain active implementation work.

## Current ACE configuration sub-batch

The isolated ACE implementation is now integrated with planning-time serialized
payload limits, forced-replacement credential guards, Unicode alias rejection and
separate disabled-client configuration. It adds four experimental resources and
18 selected rolling-SaaS operations. The secure ephemeral saved-plan examples
require Terraform 1.16.1 or later; literal write-only protocol tests still cover
the provider's 1.11 compatibility boundary. Independent frozen ACE review remains
pending, and full cloud credential drift is intentionally outside this scope.

## Historical tag/URL and review-fix sub-batch

Sub-batch surface: **6 resources, 12 data sources, 31 selected method/route operations**.
Added `algosec_tag` and `algosec_url_ip_membership`; see their
[tag](tag-contract.md) and [URL/IP](url-ip-contract.md) contracts. Tag-hostgroup
assignment has the narrow identity mapping blocker described there.

Independent first-batch security/protocol reports were read. Actual RED tests
reproduced S1 (published DELETE wrapper), P1 (known oversized replacement deletes
the old role), and P2 (disabled ambient SaaS configuration breaks AFA). Fixes and
regressions are retained. Whole-role destructive ownership now requires explicit
provider acknowledgement; permission implication and known-payload checks run
before replacement. Existing baseline safety fixes remain intact.

This is an intermediate coherent sub-batch. Final frozen-source independent review
requested changes; the current sub-batch fixes are recorded below. Narrowed
AppViz/ACE durable subsets remain work.
No completion or live acceptance is implied by current implementation counts.
[Executed sub-batch gates](durable-expansion-batch2-verification.md) passed on
Terraform 1.16.1 and 1.11.0; final independent review remains pending.

## Historical first coherent batch

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

[Cross-product inventory](cross-product-operations.json): **975 candidate records**,
with **747 selected REST, 66 unresolved REST, 162 unresolved SOAP catalog names**
and **1,048 source observations**. Zero SOAP operation QNames are certified.
Original IDs, literal labels, source pointers and version/auth provenance remain
unchanged. The additive `current_implementation` overlay maps 53 selected
operations; historical audit classifications are not current support claims.
See [reconciliation](inventory-reconciliation.md). The provisional first-batch
934-record inventory is retained only as frozen input metadata.

The original 204-page AFA baseline is retained separately. Graph discovery reached
1,021 official pages; neither page nor operation-record counts are a managed
resource coverage percentage. The 71 public SaaS operation identities remain
separate from 210 cached nodes and seven internal export exclusions. Shared
operations are deduplicated without transferring compatibility across versions.

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
| AFA A33.30 ALGOSEC tags | Implemented experimental | [Selected contract](tag-contract.md); short-page pagination, ID refresh/import and association-loaded delete guard. |
| AFA A33.20 URL/IP singleton | Implemented experimental | [Selected contract](url-ip-contract.md); exact delta acknowledgement; no overlapping whole-category ownership. |
| AFA tag-hostgroup assignment | Evidence-blocked identity mapping | [Narrow blocker](tag-contract.md#hostgroup-association-boundary): establish allowed-device ID to deviceDataId and canonical hostgroup read before creating an absent tuple. |
| FireFlow A33.30 direct role permission/member bindings | Implemented experimental | [Contract](fireflow-binding-contract.md); separate cookie client, singleton deltas, exact Success and direct/inherited reads. Full privileged visibility and exclusive tuple writers required. |
| FireFlow whole roles/users and SOAP custom-field assignments | Evidence-blocked full lifecycle | No whole-role DELETE; user mutation not established. Mixed REST/SOAP custom fields require certified identity/auth/namespace/binding and safe value ownership. Do not invent role delete or infer SOAP binding. |
| FireFlow tickets, sub-ticket configurations and object change requests | Workflow boundary | Ticket configuration is reversible but scoped to a change request, not global durable configuration. Submission/status is not authoritative deployed network/service CRUD. Keep workflows out of managed resources. |
| AFA map ignored-interface, URT, tunnels, risk/config/zone and remaining durable families | Unassessed | Parent map/URT evidence and broader graph must be reconciled; require read/identity/auth/reset semantics per candidate. Preserve generic secret-bearing config exclusions until narrowed. |
| ACE Jira integration, threat entries, cloud onboarding, risk profiles, CD mitigation | Unassessed | Official public SaaS exports exist; inspect parent findings and each operation's read/auth/delete/secret gaps. Missing legacy appliance Swagger is not a blocker for those public exports. |
| ObjectFlow owned network objects and custom-field definitions | Unassessed | Official public SaaS CRUD-shaped contracts exist; device selection may open FireFlow requests. Resolve owned-object versus deployed-device semantics, complete fields, identity and deletion before implementation. |

## Verification evidence

External logs are retained in the operator-provided implementation evidence directory.
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
2. Parent independently reviews each exact frozen sub-batch, then supplies findings. Broad expansion is **not complete**: unassessed/candidate
   rows above are real remaining work, not evidence-blocked by fiat.
3. Next implementation priorities: AppViz role/action, application-revision and service custom-field
   bindings; ACE notification emails, Jira, threat entries and manual cloud-account
   registration subsets. Read
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
   # Source the operator-provided tool environment; keep host paths external.
   export CGO_ENABLED=1
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
