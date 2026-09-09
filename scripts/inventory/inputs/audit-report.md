# Independent cross-product inventory reconciliation

## Verdict

**Candidate inventory, not a complete executable API catalog or a new support declaration.** No provider-checkout edits, appliance calls, credential retrieval, or mutations were performed by this audit. Public documentation metadata was fetched anonymously. The active native writer and its new SaaS role/baseline fixes remain pending a frozen-source comparison.

- **975 deduplicated records** from 1048 input observations, including 15 independently recovered missing routes.
- REST: **747 selected method/route records**, **66 unresolved route observations**. These include explicit extraction/reference gaps; none is a universal executable-contract certification.
- SOAP: **162 versioned catalog-name records; zero certified WSDL operation QNames**. Namespaces are documented; unknown service/port/binding/QName/SOAPAction remain null.
- **72 duplicate groups / 73 excess observations merged**, preserving contributing artifact indices and source URLs. 32 same-page multi-record groups remain explicitly enumerated for review; many are legitimate multi-operation pages, not duplicate bugs.
- All **20 published operations, 3 resources and 12 data sources** map to the original provider inventory. No newer-version support is inferred from historical operation mappings.

## Product/version record totals

Counts below include unresolved observations and SOAP catalog names, **not** a denominator for coverage percentages. Shared services are counted once, with association tags.

| Service/product | Version | Records |
|---|---|---:|
| ACE | rolling-saas | 64 |
| AFA / Horizon Security Analyzer | a32.60 | 144 |
| AFA / Horizon Security Analyzer | a33.20 | 179 |
| AFA / Horizon Security Analyzer | a33.30 | 206 |
| AppViz | a32.60 | 56 |
| AppViz | a33.20 | 56 |
| AppViz | a33.30 | 56 |
| AppViz | rolling-saas | 70 |
| FireFlow | a32.60 | 31 |
| FireFlow | a33.20 | 34 |
| FireFlow | a33.30 | 49 |
| ObjectFlow | rolling-saas | 17 |
| Shared ASMS | a32.60 | 4 |
| Shared ASMS | a33.20 | 4 |
| Shared ASMS | a33.30 | 4 |
| Shared SaaS authentication | rolling-saas | 1 |

## AppViz supplement closure and shared operations

- Original applications/network/services ledger: 141 observations (47/version). The prior role GET/POST addendum adds 6 observations.
- The completed supplement adds 39 observations (13/version); 6 overlap with the prior role addendum. The union is **180 AppViz-catalog-associated observations**: **168 customer-hosted BusinessFlow observations (56/version)** plus **12 shared-service observations (4/version)**. Do not concatenate the original, prior addendum and merged file without deduplication.
- The four shared methods per version are POST vulnerability KB import, POST vulnerability host import, DELETE imported vulnerability data, and POST risk calculation. These belong to their documented service bases, not BusinessFlow. The global candidate stores product associations rather than duplicate AppViz/AFA operations.
- SaaS tenant-login documentation is shared by ACE, ObjectFlow and AppViz. The common access-key-base POST login is one shared SaaS record with three product associations. SaaS authorization stays bearer/tenant/regional; customer-hosted AppViz Basic/JSESSIONID and FireFlow/AFA sessions are separate.
- Permission references: 19 rows, 18 exact-case action names, one duplicate refreshVulnerability. Preserve **EditApplicationInformation**. Only refreshVulnerability → viewVulnerability is an established implication here. Permissions are configuration even when action names describe workflows.

## Independently verified SaaS public provenance

Anonymous official project metadata: [cHJqOjE1ODIzNg](https://api-docs.algosec.com/api/v1/projects/cHJqOjE1ODIzNg). It identifies public project 158236, default branch **master**, branch **YnI6MzA4NTc4MQ**, **is_default=true**, **is_published=true**, commit `d22eb6e6bd9e465aaf746886a5432f35777f4bc4`. Retrieval: `2026-09-09T06:04:21.731793+00:00`.

- This is independently fetched metadata, not reliance on the task’s original “published” wording. Publication applies to the identified current branch, not automatically to every cached object.
- The 210-node cache is **71 operation nodes + 112 component-schema nodes + 27 other nodes**. “210 APIs/operations” is incorrect.
- Current official TOC has **71 operations, 111 models, 9 articles, 7 services**, plus 9 headings. All 198 typed public TOC nodes were fetched successfully; their branch-node IDs and URIs match 198 cached nodes and identify the same default master branch.
- All **71 public operation node IDs, URIs and method/path pairs** independently matched current official node metadata. Cached snapshot **content equality** to the current branch was not established: snapshot IDs and SHA-256 values are retained, and no on-prem compatibility is inferred.
- The remaining **12 cached nodes** were not corroborated as current public TOC entries (assets/config, a model, Task service/schema and troubleshooting article). Their public-default-branch status remains unestablished. See saas-provenance.json for the exact list.
- Project metadata reports 221 total branch nodes /79 operations/9 API documents, while the visible public TOC has 71 operations/7 services. Do not use internal/hidden/reference metadata totals as a public operation denominator.
- Cached eight service documents contain **78 method/path rows: 71 public-node matches, 7 x-internal exclusions**. All seven are enumerated in inventory-candidate.json and excluded from public candidates, including application hard-delete and the internal Task operation. A recoverable export is not permission to implement an internal API.
- Cache SHA-256: `5784d752a26bfedc6d17309f2310226b2c9e254e96170d5079101b8916c968e9`. The portable provenance file contains IDs, URLs, dates, hashes and selected branch metadata only, not raw schema/response/example dumps.

## Missing coverage and extraction defects

The canonical graph contains **1021 successfully fetched API-guide pages**, with no missing in-scope graph links. This audit links operation observations to **664** pages; **357** have no operation-row evidence link. Most are reference/catalog/DTO pages, but that does not prove every one is non-operational. Every unrepresented page is enumerated in audit-details.json; no percentage is claimed.

**Recovered missing REST rows:**

- a32.60 POST `/api/v1/rule/advancedsearch/basic/{treeName}` — [source](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/advancedsearch_basic.htm).
- a32.60 POST `/api/v1/devices/managedDevices/cma` — [source](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/management-device-retrieve.htm).
- a32.60 POST `/api/v1/devices/managedDevices/fortimanager` — [source](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/management-device-retrieve.htm).
- a32.60 POST `/api/v1/devices/managedDevices/genericDevices` — [source](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/management-device-retrieve.htm).
- a32.60 POST `/api/v1/devices/managedDevices/pv1` — [source](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/management-device-retrieve.htm).
- a32.60 POST `/api/v1/devices/managedDevices/pv1/cma` — [source](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/management-device-retrieve.htm).
- a33.20 POST `/api/v1/devices/managedDevices/cma` — [source](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/management-device-retrieve.htm).
- a33.20 POST `/api/v1/devices/managedDevices/fortimanager` — [source](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/management-device-retrieve.htm).
- a33.20 POST `/api/v1/devices/managedDevices/genericDevices` — [source](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/management-device-retrieve.htm).
- a33.20 POST `/api/v1/devices/managedDevices/pv1` — [source](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/management-device-retrieve.htm).
- a33.20 POST `/api/v1/devices/managedDevices/pv1/cma` — [source](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/management-device-retrieve.htm).
- a33.30 POST `/api/v1/devices/managedDevices/cma` — [source](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/management-device-retrieve.htm).
- a33.30 POST `/api/v1/devices/managedDevices/fortimanager` — [source](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/management-device-retrieve.htm).
- a33.30 POST `/api/v1/devices/managedDevices/pv1` — [source](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/management-device-retrieve.htm).
- a33.30 POST `/api/v1/devices/managedDevices/pv1/cma` — [source](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/management-device-retrieve.htm).

The two historical managed-device pages had their Brand/URL tables collapsed into bogus single labels; A33.30 only enumerated genericDevices and omitted four other routes. The five distinct credentialed-discovery routes per version are now represented; the collapsed input blobs are retained by hashes rather than exported as raw tables. The basic rule search was missed because it is reached beyond the direct REST catalog.

**Remaining detail-page linkage gaps (not newly invented SOAP operations):**
- [a33.20 Importing Risks](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/importing-risks.htm): corresponding import SOAP catalog-name rows already exist, but their detail-page evidence is not linked. Request table and example spelling differ; resolve names against real WSDL before executable binding.
- [a33.30 Importing Risks](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/importing-risks.htm): corresponding import SOAP catalog-name rows already exist, but their detail-page evidence is not linked. Request table and example spelling differ; resolve names against real WSDL before executable binding.

**Unresolved/contradictory row classes are enumerated, not silently repaired:**

- AFA leading-colon extraction contamination, U+200B, embedded spaces, `*/`, missing leading slashes, duplicate slash, collapsed table labels, and ambiguous mergeRouters base composition.
- Bare issues-center count paths have no selected service base in the candidate. Map confirm/delete labels remain incomplete. Query Troubleshooting’s truncated `queryTroubleshootin` token stays literal.
- Customer-hosted AppViz decommission spelling and flow singular/plural/body contradictions retain null selected routes. Stronger SaaS evidence is separate, not an on-prem repair.
- Five ObjectFlow rows have an empty server entry alongside regional importer bases: candidate route selection remains unresolved rather than silently discarding contradictory metadata.
- 24 FireFlow researcher rows asserted namespace-qualified catalog operation names and service “FireFlow.” The source establishes a generic SOAP namespace/header and literal request names, not the WSDL service or operation QName. All those assertions are separately recorded and canonical unknown fields are null.
- Same-page GET analysis-status aliases, notification query/acknowledge/activate, multiple import routes, topology actions and enable-device variants are legitimate candidates for separate operations. The multi-record ledger is a review queue, not a claim that all are duplicates.

## Lifecycle/discovery decisions and reopening gates

The candidate contains detailed family decisions with official source URLs. Priority is reviewed **A33.30 + AppViz SaaS**, with A32.60/A33.20 retained as historical evidence.

| Family | Candidate or gap | Reopen / acceptance requirement |
|---|---|---|
| SaaS role/action configuration | Experimental managed candidate; native code pending | Exact-role ack and read, complete typed selected fields, delta isolation, implication policy. GET omits description/LDAP provenance: visible membership guards do not make arbitrary import/replacement safe. Prefer exclusively owned new roles or explicit destructive whole-role ownership policy. |
| AppViz role/application bindings | Experimental delta candidate | Exact role and selected application revision identity; preserve unrelated grants; documented full-array or explicit-pair absence interpretation; no mixed ownership. |
| AppViz network/service/application/flow lifecycles | Improved SaaS schemas do not complete all lifecycles | Positive create identity, current revision mapping, service tuple/name drift equivalence, async draft/commit isolation; public decommission is not hard-delete. |
| AFA users/roles and device onboarding | Managed candidates blocked per contract | Complete authorization/read envelopes, safe secrets, positive identity and per-brand refresh; no metadata-only permission overwrite. |
| A33.30 tags and hostgroup associations | Conditional experimental managed candidates | Typed identity/ack, includeAssociations read guard, canonical device/hostgroup mapping, pagination and no overlapping ownership. |
| A33.20+ URL-IP membership | Experimental reduced managed candidate | Full category ack/read and exact IP add/remove; cannot overlap full-category ownership. Ambiguous URL-add wrapper is separate. |
| FireFlow MF permissions/members | Experimental delta candidates | Direct-versus-inherited reads, singleton add/remove, exact Success ack, session boundary. Full role lifecycle still has no delete. |
| Map/URT/tunnels/ignored interfaces | Durable candidates, not dismissed as reports | Typed membership/config read, operation-specific async/auth, create identity and delete/reset. URT POST route conflict and missing reset persist. Device URT GET is a distinct typed discovery candidate. |
| SOAP scheduler/custom fields | Durable configuration candidates with gaps | Schedule read/list or complete custom-field read; cardinality side effects; actual WSDL binding/QName. Not equivalent to one-shot analysis. |
| ACE / ObjectFlow | Separate SaaS boundary | Typed selected schemas, secret handling, async and ownership/lifecycle semantics. Internal administration/hard-delete exports remain excluded. |

HTTP verb is not classification: POST searches and notification queries are discovery; imports, analysis and change-request transitions are operational; authentication is helper; permission grants are persistent configuration.

## Published baseline and pending writer

**Resources:** `resource.algosec_device_group`, `resource.algosec_trusted_rule`, `resource.algosec_url_category`.

**Data sources:** `data.algosec_device`, `data.algosec_device_group`, `data.algosec_device_groups`, `data.algosec_device_zones`, `data.algosec_devices`, `data.algosec_network_objects`, `data.algosec_risk_profile_files`, `data.algosec_risk_profiles`, `data.algosec_security_zones`, `data.algosec_trusted_traffic`, `data.algosec_url_categories`, `data.algosec_url_category`.

All 20 baseline entries retain client function, actual provider route, exact documentation source/version, response contract choice, Terraform surface and candidate IDs. Mapping uses official page + version + method, so the provider’s chosen Panorama casing/trailing slash is not used to overwrite vendor literals. No new checkout files were read as completed support; active native changes require frozen-source review.

## Portable artifacts and verification

- `inventory-candidate.json`: sanitized cross-product candidate and published baseline mapping; family blockers/reopen conditions.
- `audit-details.json`: exact duplicate groups, unrepresented pages, recovered missing routes, multi-record groups, inconsistent rows and SOAP corrections.
- `saas-provenance.json`: independently fetched metadata/provenance plus all cached node snapshot IDs/hashes and public identity checks.
- `url-resolution.json`: 44 anonymous HTTP-200 source alias checks; A33.30 ASMS aliases resolve to actual Horizon canonical URLs, preventing false missing coverage.
- `recovered-operation-rows.json`: 15 explicitly recovered method/route observations with sources.
- `verification.json`: executed assertions and output SHA-256 values.
- `reconcile.py`, `report.py`: reproducible generation scripts accepting explicit external paths; no checkout writes.

Verification checks unique IDs and exact source observation accounting, source URLs on every operation, 20/3/12 baseline mapping, no host home paths, no raw schema/example/response payload keys, and no claimed new implementation support. No live compatibility or synthetic implementation-test result is inferred from inventory checks.
