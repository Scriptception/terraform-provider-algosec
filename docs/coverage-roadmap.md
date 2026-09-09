# Public-provider expansion roadmap

Planning evidence reviewed 2026-09-09. The first single-assignment trusted-rule
batch is now published in `v0.2.0` under separate user
authorization; see [contract decisions](trusted-rule-contract.md) and
[verification](public-expansion-verification.md). Remaining milestones below are
research priorities. v0.2.0 publication and direct Registry installation are
[verified](verification.md); live appliance acceptance remains outstanding.
The original baseline and planning findings are historical.

Planning review: This is a **not-exhaustive, representative
contract review**, not an implementation or appliance-compatibility claim. The
goal is useful managed administration across public AlgoSec product versions,
not coverage tailored to one maintainer's appliance. Existing A32.60 restrictions
remain the implemented baseline; this roadmap proposes how to expand them.

## Product naming and scope

**Horizon Security Analyzer is included as AFA (AlgoSec Firewall Analyzer)** in
this roadmap. The [current public product page](https://www.algosec.com/products/firewall-analyzer)
uses Horizon Security Analyzer while retaining the Firewall Analyzer URL and
terminology. Preserve established API paths and Terraform identifiers; branding
alone does not justify renaming resources or breaking state.

The public-provider goal is broad API coverage, not only the priority candidates
below. Revisit remaining AFA configuration, risk definitions, zone assignments,
category membership and other durable families in the operation ledger. The
[Horizon product lineup](https://www.algosec.com/products) also lists ACE and
ObjectFlow: their API boundaries, authentication and potential provider scope need
separate discovery. They were not inventoried by this bounded ASMS review, and
must not silently disappear from a claim of all-AlgoSec coverage.

## Baseline and research boundary

The historical published v0.1.4 planning baseline had 2 resources, 12 data sources
and 17 implemented method/route operations. Published v0.2.0 now has 3 resources,
12 data sources and 20 operations; see [coverage](api-coverage.md) and
[handoff](maintainer-handoff.md). The
204 inventoried AFA documentation pages (85 A32.60, 119 A33.20) do not enumerate
all AlgoSec APIs. Device groups remain experimental A33.20 Early Availability;
no live appliance compatibility has been established.

Repository structure supports incremental delivery: `internal/client` contains
typed HTTP contracts; `internal/provider` contains Framework schemas and
lifecycle/ownership tests; `internal/testserver` supplies synthetic HTTPS
fixtures; `examples` and `templates` feed generated resource/data-source docs.
`docs/api-inventory.json` and `scripts/coverage_check.py` currently track the AFA
baseline only. The initial roadmap changed none of those contracts or registrations; the first
implementation now adds one resource and three operations (3/12/20 total).

Official versioned public HTML was fetched with Python `requests` and parsed
with stdlib `HTMLParser`; the first urllib request returned 403, while requests
successfully fetched the introduction and selected catalog/detail pages. No
appliance, credentials or appliance-local Swagger was accessed. Research dumps
are not committed. Entry points verified in this review:

- [A33.20 API introduction][intro]: links AFA REST/SOAP, FireFlow REST/SOAP and
  AppViz REST, and describes appliance-local Swagger and deprecation policy.
- [A33.20 AFA REST catalog][afa]: administration, device brands, users/roles,
  trusted rules, analysis and reporting.
- [A33.20 FireFlow REST catalog][ff] and [SOAP catalog][ff-soap]: change-request
  workflows and SOAP custom-field operations, not proof of direct object CRUD.
- [A33.20 AppViz REST catalog][av]: separate `/BusinessFlow/rest/v1` service;
  applications, network objects and services. Its URLs retain BusinessFlow names.
- A32.60 comparison samples: [device writes][old-devices], [SOAP users/roles][old-auth],
  [applications catalog][old-apps] and [FireFlow REST catalog][old-ff]. Catalog
  overlap alone does not prove matching schemas or lifecycle behavior.

## What comprehensive coverage means

Maintain a future operation ledger keyed by **product + public ASMS version +
HTTP method + route template**, including the documented base path. For SOAP,
use product/version + service/binding + operation QName; counting every SOAP
method as one HTTP POST would conceal actual coverage. Preserve literal route
labels and contradictory examples separately from any reviewed canonical route.
Deduplicate repeated links, anchors, aliases and examples. Track brand variants,
authentication, parameters, payloads, response envelopes, errors and lifecycle
semantics as contract dimensions even when they share a route.

Every discovered operation needs an evidence URL/retrieval date, availability
status, classification, implementation mapping, synthetic-test status and
version-specific live evidence. Classifications are: managed resource lifecycle;
resource helper; import/adoption support; read-only data source; one-shot action
or workflow; unsupported contract pending research; intentionally excluded with
reason. POST searches are reads. A ticket-creation POST is not object CRUD.

Report separately per product/version:

1. Discovery completeness against named catalogs and, when authorized and
   available, versioned specifications; undiscovered families remain unknown.
2. Implemented unique method/routes divided by all enumerated method/routes,
   with auth/helpers shown separately. Do not sum a cross-version numerator
   against a single-version denominator or count one GET twice for two surfaces.
3. Delivered managed lifecycles divided by identified durable-object candidates,
   with blocked candidates visible. Supporting data sources do not improve this
   managed-resource measure.
4. Contract-tested versus live-accepted versions and device types, independently.

“Comprehensive” requires a reconciled ledger across AFA, FireFlow and AppViz for
an explicitly named version set, a disposition for every enumerated operation,
and accepted implementations for every claimed managed lifecycle. It does not
mean forcing all workflows into resources. This review has no exhaustive
cross-product denominator and therefore makes no overall percentage claim.
Missing documentation is a research gap with a reopening condition, not evidence
that the API can never be supported.

## Public version support policy (proposed)

Use a product/feature/version matrix rather than one universal ASMS minimum.
Retain A32.60 as the documented baseline and evaluate A33.20 additions separately.
Neither is asserted to be the newest generally available release. Add other
public versions through the same contract comparison and acceptance process;
do not silently follow `/latest/` or infer backward support from a newer page.

For each feature distinguish researched, synthetic-contract-tested, experimental,
live-accepted and deprecated. Record actual appliance version/build, product,
brand where relevant, permissions and provider/Terraform versions for acceptance.
An untested version is unverified, not automatically incompatible. Keep EA
features explicitly opt-in until vendor status and acceptance justify promotion.
Use explicit capability/version selection where necessary; reject unsupported
combinations before writes. Never probe alternate mutation routes or replay
writes to discover compatibility.

The [vendor introduction][intro] describes a 12-month deprecation period and
notifications through Swagger and release documentation. Track those notices
per operation; do not treat that policy as proof every response shape is stable.
Preserve existing identities and state, use state migration for schema changes,
and announce removals with an appropriate provider-version migration path.
Promotion requires public contract evidence plus the live matrix below, not just
newer documentation. This policy is a proposal, not a new support guarantee.

## Prioritized managed-resource work

### P0 / milestone 1: trusted-rule assignments

**Published in v0.2.0, experimental:** one
`algosec_trusted_rule` resource owning one trust assignment identified by device
tree name and existing rule ID. It manages trust metadata, not the firewall rule
itself. Avoid a device-wide authoritative set that could delete other owners'
assignments. Identity encoding must be unambiguous and round-trip through import.

A33.20 documents GET, POST and DELETE at the literal resource label
`/api/v1/trusted-rules/rules`: [list][tr-get], [save][tr-post], [delete][tr-delete].
GET takes device names and returns per-device rules with rule ID, comment and
expiration date. POST takes one actual device and a list of IDs with optional
comment/future expiration; groups and ALL_FIREWALLS are disallowed. POST and
DELETE return per-rule success/failure lists and reasons, so HTTP 200 alone
cannot prove success. DELETE's `trustedRuleIds` means successfully deleted IDs.

The candidate has unusually useful readback and explicit acknowledgements, but
required the following contract decisions. Their selected implementation and
remaining live uncertainties are recorded in [the contract dossier](trusted-rule-contract.md):

- Reconcile AFA base-path/session rules with examples omitting `/afa` and using
  Bearer authentication. Select one verified contract, never fallback writes.
- Establish whether saving an existing ID updates, rejects or otherwise changes
  the assignment; determine omitted/empty comment and expiration semantics.
  There is no demonstrated PUT. If update is unavailable, replacement is only
  acceptable after confirming delete/recreate safety and documenting its gap.
- Prove list completeness and behavior for an untrusted, expired or removed
  underlying rule. Legacy trusted-traffic hit filtering is not a substitute.
- Establish duplicate-create behavior and ownership under concurrency. Preflight
  rejects existing assignments and directs explicit import; a same-ID GET after
  an ambiguous POST cannot establish ownership. If POST is an unconditional
  upsert, record that concurrency limitation and gate safe create semantics.

Batch contents after those gates: three typed client methods, one resource,
explicit import, synthetic contract and Terraform lifecycle tests, tenant-neutral
example and generated docs. No extra data source is needed to claim this batch.
Retain positively acknowledged identity across failed readback; retain owned
state on ambiguous update/delete. Test failures inside successful HTTP responses.
Acceptance requires stable refresh/import, metadata change or verified replacement,
external drift/deletion, expiration behavior, partial failure and no adoption after
unconfirmed create, followed by a disposable A33.20 live run before promotion.

### P1 / milestone 2: roles, then users

Authorization is high-value durable administration. A33.20 has REST
[role create][role-create], [edit][role-edit], [delete][role-delete] on
`/api/v1/roles`, and [user create][user-create], [edit][user-edit],
[delete][user-delete] on `/api/v1/users`. These are not universally SOAP-only;
[A32.60 SOAP operations][old-auth] remain a separately evaluated fallback family,
not a reason to invent a REST backport.

Start with a role resource, then a user resource referencing roles. Define
ownership of authorization lists explicitly; avoid simultaneous ownership by
whole-user schemas and independent role-binding resources. Prefer stable
name-based adoption only after uniqueness/domain scope and rename behavior are
proved. Existing objects require explicit import, not implicit create-as-update.

Blockers are material: [user GET][user-get] has an incomplete collection example;
[role GET][role-get] is `/afa/api/v1/users/Roles`, not GET `/roles`, and its example
is malformed. Read fields do not establish all writable permissions; do not map
`EnableGlobalCustomization` to `enableGlobalTrustTraffic` by guesswork. Role GET
also documents a session in the query string: obtain a supported safe-auth
contract consistent with repository policy before implementation. Establish
complete envelopes, permission visibility, defaults, omitted-field update
behavior and per-object acknowledgement semantics. A reduced schema is viable
only if it can preserve every unmanaged permission during writes.

User creation requires temporary user and administrator passwords; authentication
type does not demonstrate a password exemption. User edit directs password
changes to a separate endpoint. Treat passwords as write-only inputs with an
explicit nonsecret rotation trigger where required; never read them back or
persist hashes as a substitute. Sensitive marking alone does not keep secrets
out of state. Adoption must work without the original password and without an
unrequested reset. Confirm Terraform/Framework write-only support requirements
before selecting a minimum version. Roles avoid the user-password problem but
still need safe session authentication.

Exit criteria: exact authorization readback, import with no privilege change,
role/user drift tests, duplicate/partial acknowledgements, permission-denied
refresh retaining state, secret-absence assertions, and approved disposable
role/user create/update/import/delete acceptance. Do not test deletion or privilege
changes on the executing administrator. Unresolved read fields block the affected
resource; they do not permanently exclude users/roles from the roadmap.

### P1 / milestone 3: AppViz-owned objects, applications and flows

Build separate typed AppViz authentication/client support first. The [catalog][av]
documents `JSESSIONID`; some operation examples use Bearer auth. Resolve the
selected version's authentication before writes. Never reuse AFA cookies by
assumption. AppViz model changes do not inherently prove firewall deployment.

| Candidate and priority within this milestone | Verified contract | Lifecycle decision and remaining gate |
|---|---|---|
| Non-device service objects, then non-device network hosts/ranges/groups | [Service catalog][services] and [network catalog][objects] expose create, GET, edit and delete. [Service create][svc-new] returns an object; [edit][svc-edit] uses content deltas. [Network create][obj-new] returns `newObject`; [edit][obj-edit] can return a change request. | Strong durable candidates restricted initially to AppViz-owned objects. Prove stable identity versus revision IDs, latest-revision lookup, field readback, origin and dependent-object behavior. [Service deletion][svc-delete] cannot permanently remove device service objects; [network deletion][obj-delete] depends on product configuration and can be undone by device synchronization. Do not claim management of those device-backed objects. |
| Application metadata/container | [Create][app-new] returns an Application; [revision GET][app-get] and [latest application GET][app-latest] distinguish revision ID from application ID. | Valuable candidate, but the catalog does not establish generic application DELETE or arbitrary metadata update. [Decommission][app-decommission] returns a change response and has a misspelled literal resource label. Resolve terminal state, asynchronous effects, rename and safe destroy before a full resource. Never silently equate decommission with deletion. |
| Application flow inside an explicitly selected application | [Create flows][flow-new], [GET flow][flow-get], [edit flows][flow-edit] and [delete flow][flow-delete] form a real lifecycle candidate. | Prioritize ordinary application flows before shared/subscribed flows. Establish application ID + flow ID identity across revisions and exact import lookup. Resolve edit example's singular `/application` versus declared `/applications`, malformed payload and custom-field spelling. Prove draft acquisition, locking, merge/conflict behavior and completion semantics. |

[Apply draft][app-apply] can open a change request and may include all changed
flows if none are selected. Apply, discard, resolve, connectivity checks and
application decommission are workflow operations, not automatic refresh steps.
Choose and document a draft-only ownership model or an explicitly authorized
publication lifecycle; never apply another actor's draft changes. Importing a
revision does not establish ownership of its whole application. Flow deletion
means removal from the selected revision, not proof of live firewall removal.

Exit criteria: one non-device object lifecycle accepted before broad object types;
then application/flow identity round-trips, current-revision drift, concurrent
edits, referenced-object constraints, uneditable statuses, partial errors and
read-after-write. Full application management waits for the destroy contract.
A flow resource may target an existing application without owning it only after
draft/parent ownership is safe. Do not pad this milestone with application report
data sources while leaving all managed candidates unresolved.

### P2 / milestone 4: device onboarding by type

[A33.20 add/edit][devices] documents POST/PUT `/api/v1/devices/`;
[detail][device-get] and [delete][device-delete] use device identity. This is a
brand-dependent family, not a safe generic JSON resource. [Brand templates][brands]
are request-building helpers, not current device configuration readback. The
public detail page does not provide a complete response schema.

| Onboarding type | Representative evidence and scope | Required proof before delivery |
|---|---|---|
| Direct devices | Add/edit tables include standalone firewall/router brands; templates list `fortigate`, `ios`, `junos`, `paloalto` and others. | Select one brand first; map every managed nonsecret field to GET, positive create identity, immutable/editable fields and deletion. Credentials are write-only; imports cannot recover them. |
| Management devices and children | Add/edit describes FortiManager, Check Point and other managers; deprecated `addChildren` coexists with `addAllAvailableChildren` and selected-child parameters. | Separate manager ownership from child selection; prove discovery identifiers, default all-child behavior, partial onboarding and delete cascades. Prevent unintended child adoption/removal. Do not generalize one manager's fields to another. |
| Cloud accounts/connectors | Add/edit has AWS and Azure credential/region/subscription tables. | Start with one cloud type after readback and credential rotation are established. Determine discovered-child ownership, sync effects and account deletion behavior; cloud onboarding is not ownership of cloud infrastructure. |
| File devices | [A32.60 write table][old-devices] requires `existingFile`, `FW_TYPE`, `name`, with optional source-related fields. | Prove file-source readback, identity, external-file ownership and deletion effects. Inventory `FW_FILE` alone cannot refresh desired source configuration. A write test/preview is not a read contract. Reopen when versioned documentation resolves this gap. |

Proposed order is one direct brand with proven readback, then one manager/child
model, then one cloud connector; move file devices earlier only if their readback
gap closes. Preserve verified TLS, bounded calls, no redirects and no write
retries. Never echo credential-bearing `testMode` results into state or logs.
Exit criteria apply **per brand/version**, including import without secrets,
nonsecret drift, secret rotation, partial children, external deletion and safe
cleanup. One passing brand is not “all device onboarding.”

### P2 / milestone 5: FireFlow object management and workflow boundary

[Create object change request][ff-object-new] is POST
`/FireFlow/api/request/object`. It supports network/service objects, group
membership changes and content replacement across devices/containers. It returns
a request ID, and explicitly warns creation may be incomplete even with that ID.
[GET object change request][ff-object-get] reads
`/FireFlow/api/change-requests/object/{changeRequestId}` and only returns requests
created through the API, not UI-created requests. This precludes universal ticket
import through that read route and does not read current firewall object state.

Deliver workflow integration only after proving submission acknowledgement,
status/terminal-state readback, multi-device partial outcomes and safe retry or
operator recovery. Ticket submission, approvals, work-order calculation and
ActiveChange are one-shot workflows. Their existence is not a managed
`network_object` or `service_object` lifecycle. Existing AFA network-object
search is analyzed inventory, not automatically authoritative deployment readback.

Keep direct FireFlow-backed durable object resources as an open research item:
require authoritative object identity/readback, implementation completion,
update/delete effects and ownership across containers/devices. A compensating
change request is not a demonstrated Terraform destroy. SOAP [custom-field
operations][ff-soap] likewise need field readback and ownership before resource
classification. No unsupported direct CRUD route is invented. Exit criteria are
an explicit workflow contract and, separately, a complete durable-object contract
if one can be established; shipping ticket lookup alone does not satisfy managed
object coverage.

## Contributor and live acceptance strategy

Each coding milestone starts with a contract dossier: versioned URLs, literal and
selected routes, auth, typed payload/read fields, identity/import, acknowledgement,
absence, update/reset, concurrency, secrets and delete effects. Record unresolved
contradictions as blockers. Seek corrected public docs or a vendor contract first;
a sanitized, explicitly authorized version/build-specific observation may narrow
a gap but is not evidence for every public version. Re-review deferred families
when relevant docs or version contracts change.

Use synthetic, clearly labelled fixtures for positive and negative envelopes,
per-item failures inside HTTP 200, pagination, malformed/incomplete reads,
401/403/404 distinctions, ambiguous transport outcomes and delayed consistency.
Terraform protocol tests must cover create/refresh/no-op plan/update or replacement,
import, external drift/deletion, destroy and recoverable partial state. Preserve
existing ownership regressions. Never remove state on permission errors or adopt
a same-name object after an unconfirmed create. Test secret absence in serialized
state and captured diagnostics/logs without real credentials.

For future code changes, run the repository-required
`make fmt-check test vet vuln docs-check smoke`, generate docs from schemas/examples,
and update capability inventory, VERSION and CHANGELOG under separate authorized
scope. The subsequent implementation mission explicitly authorized this first resource
batch and local verification; it did not authorize publication or live changes.

Live testing is a separate gate: `TF_ACC=1` for read-only tests; mutation also
requires `ALGOSEC_ACC_MUTATION=1` and `ALGOSEC_ACC_DISPOSABLE=1`, explicit approval,
and disposable targets. Read-only tests must not submit previews, tickets or
other writes. Use approved secret management and verified TLS. Establish complete
visibility and ownership-safe cleanup first; never delete a coincident same-name
object after an uncertain create. Record sanitized results per product/version,
brand and feature; keep captures, state, plans and credentials out of Git. Broader
public support needs contributor-operated matrices, not one maintainer's version.

## Immediate handoff

The first trusted-rule batch is implemented and locally exercised. Review the
[verification record](public-expansion-verification.md) and contract dossier;
perform the parent frozen-scope review before accepting the mission. No appliance
or publication work is authorized. Next managed-resource research remains roles
and AppViz non-device service objects, with their blockers retained above. The
current inventory is 3 resources, 12 data sources and 20 operations; this does not
establish comprehensive AlgoSec coverage.

[intro]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/api_introduction.htm
[afa]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/afa-rest-web-services.htm
[ff]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/fireflow-rest-web-services.htm
[ff-soap]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/fireflow-soap-web-services.htm
[av]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/businessflow-rest-web-services.htm
[old-devices]: https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-add_edit.htm
[old-auth]: https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/managing-users-and-roles.htm
[old-apps]: https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/applications.htm
[old-ff]: https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/fireflow-rest-web-services.htm
[tr-get]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/trusted-rules-get.htm
[tr-post]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/trusted-rules-add-post.htm
[tr-delete]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/trusted-rules-delete.htm
[role-create]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/roles_create_post.htm
[role-edit]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/roles_edit_put.htm
[role-delete]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/roles_delete_delete.htm
[user-create]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/users_createnew_post.htm
[user-edit]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/users_editdetails_put.htm
[user-delete]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/users_delete_delete.htm
[user-get]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/retrieving_users.htm
[role-get]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/retrieving_roles.htm
[services]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/network_services.htm
[objects]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/network_objects.htm
[svc-new]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-new_2.htm
[svc-edit]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-id_1.htm
[svc-delete]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/delete-id_1.htm
[obj-new]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-new_1.htm
[obj-edit]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-id.htm
[obj-delete]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/delete-id.htm
[app-new]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-new.htm
[app-get]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/get-id.htm
[app-latest]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/get-id-application_id.htm
[app-decommission]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-id-decommission.htm
[app-apply]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-id-apply.htm
[flow-new]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-id-flows-new.htm
[flow-get]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/get-id-flows-flowid.htm
[flow-edit]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/post-id-flows.htm
[flow-delete]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/delete-id-flows-flow_id.htm
[devices]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/device-add_edit1.htm
[device-get]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/device-details.htm
[device-delete]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/device-delete.htm
[brands]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/device-examples-by-brand.htm
[ff-object-new]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/creating-a-multiple-device.htm
[ff-object-get]: https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/objectcr-get.htm
