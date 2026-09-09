# API coverage: ASMS A32.60 base and experimental A33.20 groups

This initial provider targets the **public A32.60 REST documentation**, retrieved
2026-09-09. It is not a claim of compatibility with every ASMS version or live
appliance verification. The public catalog links were fetched directly with
Python requests and parsed with HTMLParser. Detailed source excerpts and research
notes are kept outside the deliverable in `algosec-provider-work/research`.

Sources: [AFA REST catalog](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/afa-rest-web-services.htm),
[ASMS introduction](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/api_introduction.htm).
The appliance-local Swagger is not publicly downloadable without an appliance;
no appliance was contacted. This inventory covers the linked public AFA REST
catalog, not undiscovered endpoints, FireFlow or AppViz APIs.

## Initial surface and contract choices

Two resources: `algosec_url_category`, `algosec_device_group` (experimental A33.20 EA).
Twelve data sources: `algosec_url_categories`, `algosec_url_category`,
`algosec_devices`, `algosec_device`, `algosec_risk_profiles`,
`algosec_risk_profile_files`, `algosec_security_zones`, `algosec_device_zones`,
`algosec_network_objects`, `algosec_trusted_traffic`,
`algosec_device_group`, `algosec_device_groups` (both experimental).

These form a narrow administrative core with supporting discovery. Many more
read/report APIs exist. Broad device onboarding, users, roles, risk
mutation and policy workflows are not supported.

- REST paths beginning `/api/v1` are resolved beneath `/afa`, following the
  catalog's base-URL rule and working request examples. The catalog's `https::`
  typo is not reproduced. Credentials are carried in the PHPSESSID cookie,
  never in query strings. Login uses `/fa/server/connection/login`.
- URL-category docs contain capitalization and wrapper inconsistencies. The
  provider uses `/afa/api/v1/plugins/panorama/URLCategory/` as shown in the
  explicit cURL examples and the canonical `{categories:{name:{urls:{...}}}}`
  GET/create example. It **does not** try alternate mutation routes or replay
  payload variants. Unexpected read shapes fail closed. Rename sends a JSON
  string as explicitly defined in the request-body table and uses the example's
  trailing slash. These are documented-contract choices, not live confirmation.
- Only `panorama` is documented. An administrator must prepare the override file
  `/home/afa/.fa/plugins/panorama/url_categories.json` from the product-supplied
  file with permissions 0644, following the linked AlgoSec instructions. This
  provider does not access the appliance filesystem or create that prerequisite.
- Each category owns its complete URL/IP map. Name changes rename in place;
  URL/IP changes replace (delete then create). Do not use create-before-destroy
  for same-name replacement. Granular add-URL examples conflict, and add-IP has
  no removal counterpart. Existing categories must be imported. No overlapping
  ownership is supported; there is no API ETag/transaction contract, so concurrent
  external modification remains a risk even with preflight checks.
- File-device management is excluded. The [write contract](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-add_edit.htm)
  documents `existingFile`, but the [inventory example](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/devices-list.htm)
  only establishes `nodeType`, name and display name for FW_FILE, not file-source
  readback. The [detail page](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-details.htm)
  provides no resolving response schema. A post-create diagnostic cannot repair
  this contract gap. Only safe read-only device inventory is retained.
- Only successful, well-formed complete category/device inventories prove absence.
  HTTP 204/400/401/403/404/5xx, malformed JSON and null inventories never remove state.
  This requires stable **administrator visibility**, not a permission-filtered
  account. Revoking visibility could otherwise be indistinguishable from deletion.
- Network-object search uses the documented default IPv4 filter and explicitly
  includes devices beyond the FireFlow-supported subset. IPv6 selection is not
  exposed in this initial schema.
- Data-source pagination has a 1000-page bound and detects duplicate identifiers,
  changing totals and incomplete pages. Trusted traffic is informational: upstream
  warns that zero-hit entries may be omitted. It is not used for resource drift.
- Writes are not retried. Read-back is immediate: delayed consistency returns an
  error with recoverable state, rather than claiming success or blindly replaying.
  After ambiguous transport failures, inspect/import the remote object before retry.

## Endpoint/page inventory

The machine-readable companion is [api-inventory.json](api-inventory.json).
Paths in this table preserve the public documentation spelling, including typos;
implementation path choices are explained above. Pages with multiple operations
are kept together; this is not a fabricated OpenAPI specification.

| Official page | Method and documented path | Coverage and reason |
|---|---|---|
| [Rules Advanced Search - full](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/advancedsearch_full.htm) | `POST /api/v1/rule/advancedsearch/full/{treeName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieve parent device](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/afa-ret-parent-obj.htm) | `GET ` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [AFA search rule fields](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/afa-search-rule-fields.htm) | ` ` | **Reference** — Shared response types/search field definitions, not a standalone operation. |
| [Import vulnerability data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/api-import-vuln.htm) | `POST, POST, DELETE ` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Assign zone types to interfaces](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/assigning-zone-types-to-interfaces.htm) | `POST /api/v1/interfaces` | **Excluded/deferred** — Excluded mutation: resource path says /api/v1/interfaces but example uses /fa/server/interfaces/update; display-name identity and clear/reset lifecycle unresolved. |
| [Bulk update keys of AWS cloud accounts](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/awskeys-bulkchange.htm) | `PUT /api/v1/firewallData/bulkUpdateCloudAccounts` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Run a Risk Check](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/calculate-risk-check_post%20.htm) | `POST /api/v1/riskcheck/calculate` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Export covered rules to a CSV](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/coveredrules_exportcsv.htm) | `GET /api/v1/rules/covered/csv/{reportId}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [EntitiesResponse type](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/data-types_1.htm) | ` ` | **Reference** — Shared response types/search field definitions, not a standalone operation. |
| [Add/Edit a device](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-add_edit.htm) | `POST, PUT /api/v1/devices/` | **Excluded/deferred** — Excluded: no documented existingFile readback for reliable file-device drift/import; other brands need separate typed contracts.
| [Delete a device](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-delete.htm) | `DELETE /api/v1/devices/{device-name}` | **Excluded/deferred** — Excluded: no managed device lifecycle is shipped; device deletion is not exposed.
| [Get details for a specified device](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-details.htm) | `GET /api/v1/devices/{deviceName}` | **Excluded/deferred** — Deferred: no example response shape; exact lookup uses documented full device inventory instead. |
| [View device parameter templates](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-examples-by-brand.htm) | `GET /api/v1/devices/examples/<brandName>` | **Excluded/deferred** — Onboarding utility. Templates may contain secret slots and do not represent managed state. |
| [Export list of device changes to XLS file](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device-exportxls.htm) | `GET /api/v1/device/exportChanges/xls` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of parents for specified list of child devices](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/device_getparents.htm) | `POST /api/v1/device/getParents` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Get a list of devices](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/devices-list.htm) | `GET /api/v1/devices/` | **Implemented** — algosec_devices and algosec_device read-only administrator inventory. Password fields discarded.
| [Get zones data from a device](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/devicezones_data.htm) | `GET /api/v1/deviceZones` | **Implemented** — algosec_device_zones; rejects additionalInformation partial failures. |
| [Enable processes after relocation](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/enable-processes.htm) | `PUT, PUT /api/v1/device/relocation/enableDevices, /api/v1/device/relocation/enableDevicesOnRemoteAgent` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieve a risk profile list](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/getting_risk_profiles_list.htm) | `GET /api/v1/security_zones/get_profiles_list` | **Implemented** — algosec_risk_profile_files; accepts documented bare array or successful status/data envelope. |
| [Retrieve security zones](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/getting_security_zones.htm) | `GET /afa/api/v1/security_zones/<risk_profile_excel_filename>/get_zones` | **Implemented** — algosec_security_zones; accepts documented bare array or successful status/data envelope. |
| [Identify missing routers](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/identifying-missing-routers.htm) | `POST, GET, GET, POST, GET /ms-mapDiagnostics/v1/api/mapCompleteness/execute*/, ms-mapDiagnostics/v1/api/mapCompleteness/missingStubRouters, ms-mapDiagnostics/v1/api/mapCompleteness/lastExecution*/, ms-mapDiagnostics/v1/api/mapCompleteness/abort*/, ms-mapDiagnostics/v1/api/mapCompleteness/defaultValues*/` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Import risk profile from spreadsheet](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/import-risk-csv.htm) | `POST /api/v1/riskcheck/import/{profile}` | **Excluded/deferred** — Deferred durable profile import: file workflow lacks documented matching delete lifecycle; no profile resource is claimed. |
| [Log in to ASMS](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/logging-in.htm) | `POST /fa/server/connection/login` | **Implemented** — Authentication helper; JSON username/password, boolean status and SessionID; PHPSESSID cookie only. |
| [Log out of ASMS](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/logging-out.htm) | `POST /fa/server/connection/logout` | **Excluded/deferred** — Not called: provider does not own externally supplied sessions; Framework has no reliable per-instance shutdown callback. Login sessions expire per appliance policy. |
| [Get device info about  managed devices](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/management-device-retrieve.htm) | `POST Brand` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Manage AFA notifications](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/managing-issues.htm) | `POST, POST, POST /ms-watchdog/v1/api/issues-center/issues, /ms-watchdog/v1/api/issues-center/issues/acknowledge, /ms-watchdog/v1/api/issues-center/issues/activate` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Merge routers](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/merging-routers.htm) | ` ` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get  NAT rules information](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/nat-rules_get.htm) | `GET /afa/api/v1/rule/natRulesInfo/â` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Get network objects by Device](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/network-object_bydevice_get.htm) | `GET /api/v1/networkObject/search/{deviceTreeName}/objects` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Get a list of network objects](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/networkobject_search_get.htm) | `GET /api/v1/networkObject/search/findByOriginalNameContaining` | **Implemented** — algosec_network_objects; typed allowlist, bounded complete pagination, no raw JSON state. |
| [Get a list of permissive rules](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest-tightenpermissiverules-get.htm) | `GET /api/v1/rules/tightenPermissive/{entityTreeName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of consolidated rules](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_consolidatedrules.htm) | `GET /api/v1/rules/consolidated/{deviceTreeName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of covered rules](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_coveredrules.htm) | `GET /api/v1/rules/covered/{entityTreeName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of disabled rules](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_disabledrules.htm) | `GET /afa/api/v1/rule/policy-optimization/{deviceTreeName}/disabledrules` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of redundant special case rules](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_redundantspecialcaserules.htm) | `GET /api/v1/rules/specialCase/{deviceTreeName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of rules without logging](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_ruleswithoutlogging.htm) | `GET /api/v1/rule/policy-optimization/{deviceTreeName}/withoutlogging` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of unattached objects](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_unnattachedrules.htm) | `GET /api/v1/objects/unattached/{entityTreeName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of unused rules](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_unusedrules.htm) | `GET /api/v1/rules/unused/{entityTreeName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get a list of rules with empty comments](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/policyrest_withoutcomment.htm) | `GET /afa/api/v1/rule/policy-optimization/{deviceTreeName}/withoutcomment` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieve network objects in device](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/post_byoriginalorcanonizednamesanddevicesmapping.htm) | `POST /api/v1/networkObject/search/findByOriginalOrCanonizedNamesAndDevicesMapping` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Retrieve Network Objects Containing All FQDNs](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/post_containingfqdn.htm) | `POST /api/v1/networkObject/search/containingAllFqdns` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Retrieve matching network objects by original or canonized name](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/post_findbyoriginalorcanonizedname.htm) | `POST /api/v1/networkObject/search/findByOriginalOrCanonizedName` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Retrieve a mapping between FQDNs and network objects](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/post_searchfqdn.htm) | `POST /api/v1/networkObject/search/byFqdns` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Relocate devices between nodes](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/relocate-devices-between-nodes.htm) | `POST /api/v1/device/relocation` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Cancel device relocation](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/relocate-devices-cancel.htm) | `DELETE /api/v1/device/relocation` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Check device relocation progress](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/relocate-devices-check-progress.htm) | `GET /api/v1/device/relocation` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get all reports](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/reports_getall.htm) | `GET /api/v1/report/findAllReports` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieve last completed report of specified devices](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/reports_getlastcompleted.htm) | `POST /api/v1/report/findLastCompletedReport` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieve an analysis status](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving-an-analysis-status.htm) | `GET /api/v1/analysis/status` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieve interfaces](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving-interfaces.htm) | `GET /api/v1/interfaces` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Retrieve network objects and IPs](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving-network-objects.htm) | `GET /fa/server/network_objects/read` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Get risky rules](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving-risky-rules.htm) | `GET /api/v1/risks/riskyRules` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieves all the rules in a device's or group's policy](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving-rules.htm) | `GET /api/v1/rules` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Retrieve service objects](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving-service-objects.htm) | `GET /api/v1/network_services` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Retrieve a baseline compliance report](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving_a_base_compliance_report.htm) | `GET ` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Retrieve role data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving_roles.htm) | `GET /afa/api/v1/users/Roles` | **Excluded/deferred** — Deferred: collection envelope, field spelling and session-in-query authentication are incomplete/inconsistent; no REST mutation. |
| [Retrieve user data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/retrieving_users.htm) | `GET /afa/api/v1/users` | **Excluded/deferred** — Deferred: single-object example for plural user inventory leaves collection envelope unspecified; REST mutations absent. |
| [Download Risk Profile File](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/riskprofile-get_downloadriskprofile.htm) | `GET /api/v1/risks/profiles/{profileName}/download` | **Excluded/deferred** — Operational file download; no durable Terraform object. |
| [Get Custom Risk Profile Data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/riskprofile-get_riskprofiledata.htm) | `GET /api/v1/risks/profiles/{profileName}` | **Excluded/deferred** — Deferred typed detail expansion: nested rule variants, string/boolean mismatch and optional per-rule structures; profile names are implemented. |
| [Get a list of user defined risk profiles](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/riskprofile_get_list.htm) | `GET /api/v1/risks/profiles` | **Implemented** — algosec_risk_profiles; string array. |
| [Get  devices routing information](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/routing-info_get.htm) | `GET /afa/api/v1/interfaces/routingInformation/â` | **Deferred read-only** — Additional analyzed topology/object/report query outside the initial administrative inventory; no mutation is implemented or implied. |
| [Add to or edit a rule's documentation](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/rule_editdocumentation.htm) | `POST /api/v1/rule/createDocumentation` | **Excluded/deferred** — Deferred: rule-id vs rule_id spelling conflicts and clearing/deletion behavior is not explicitly defined. |
| [Get a rule's documentation data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/rule_getdocumentationdata.htm) | `GET /api/v1/rule/ruleDocumentation` | **Excluded/deferred** — Deferred: rule-id/page vs ruleId/pageNumber conflicts; documentation mutation lacks clear/delete semantics. |
| [Rules hit count](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/rules-hit-count.htm) | `POST /api/v1/rules/hit-count` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Running the Query Troubleshooting Tool](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/running-the-query-troubleshooting.htm) | `POST, POST /ms-watchdog/v1/api/issues-center/issues/acknowledge` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Start an analysis](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/starting-an-analysis.htm) | `POST /api/v1/analysis/start` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Traffic Simulation Query](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/traffic-simulation-query.htm) | `POST /api/v1/query/` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Add a new trusted traffic request](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/trusted-traffic_addnew.htm) | `POST /api/v1/trustedTraffic` | **Excluded/deferred** — Excluded mutation: no create response identifier contract, service/request type table conflicts with examples, and read may omit zero-hit rows. |
| [Delete trusted traffic data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/trusted-traffic_deletedata.htm) | `DELETE /api/v1/ trustedTraffic/{trustedTrafficId}` | **Excluded/deferred** — Excluded mutation: standalone deletion of trusted traffic is not a desired-state resource lifecycle. |
| [Edit trusted traffic data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/trusted-traffic_editdata.htm) | `PUT /api/v1/trustedTraffic/{trustedTrafficId}` | **Excluded/deferred** — Excluded mutation: no reliable complete drift source; same object/request typing conflicts as create. |
| [Export trusted traffic to a CSV or JSON file](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/trusted-traffic_exportdata.htm) | `GET /api/v1//trustedTraffic/firewalls/{firewallName}` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Get trusted traffic data](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/trusted-traffic_getdata.htm) | `GET /api/v1/trustedTraffic/firewalls/{firewallName}` | **Implemented** — algosec_trusted_traffic data source only; paginated advertised inventory. Zero-hit omission makes it unsuitable as a resource drift source. |
| [Import trusted traffic rule from XLS](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/trusted-traffic_importfile.htm) | `POST /api/v1/trustedTraffic/uploadTrustedTrafficFile` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Trust an existing rule](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/trusted-traffic_trustrule.htm) | `POST /api/v1/trustedTraffic/trustRiskyRule` | **Operational** — Analysis, reporting, optimization, bulk credential rotation or workflow action; intentionally not modeled as a durable administration resource. |
| [Update Risk Definitions](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/update-risk-definition_post.htm) | `POST /api/v1/risks/profiles` | **Excluded/deferred** — Deferred: updates existing definitions, but create/delete/reset lifecycle is not documented; would require explicit adopt/forget semantics. |
| [Delete URL categories](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_delete.htm) | `DELETE /api/v1/plugins/{brand}/URLCategory/` | **Implemented** — algosec_url_category deletion; JSON array of names; complete-list read-back. |
| [Remove URL(s) from a specified URL Category](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_delete_url.htm) | `DELETE /api/v1/plugins/{brand}/URLcategory/{category}/URL` | **Excluded/deferred** — Deferred granular mutation: API exists but a complete URL membership/update resource also needs the ambiguous add contract. Full category content changes replace. |
| [Get the list of all URL Categories](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_get.htm) | `GET /api/v1/plugins/{brand}/URLCategory/` | **Implemented** — algosec_url_categories, algosec_url_category data sources; complete list is the resource read/drift/import helper. |
| [Get the URL(s) of a specified URL Category](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_get_category.htm) | `GET /api/v1/plugins/{brand}/urlcategory/{category}` | **Excluded/deferred** — Not used: lowercase urlcategory path and unrelated multi-category response example; exact lookup uses complete list. |
| [Get the IPs of a specified URL](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_get_url_url_ip.htm) | `GET /api/v1/plugins/{brand}/URLcategory/{category}/URL/{url}/IP` | **Excluded/deferred** — Not needed: documented cURL array shape available through full category inventory; granular path capitalization differs. |
| [Create/add  URL Categories](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_put.htm) | `PUT /api/v1/plugins/{brand}/URLcategory/` | **Implemented** — algosec_url_category create, canonical cURL payload {categories:{name:{urls:{URL:[IP]}}}}. Refuses preexisting category. |
| [Rename a specified URL Category](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_put_category.htm) | `PUT /api/v1/plugins/{brand}/URLcategory/{category}` | **Implemented** — algosec_url_category name update; JSON string body per parameter definition; verifies old absence and new contents. |
| [Add IPs to URL](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_put_ip.htm) | `PUT /api/v1/plugins/{brand}/URLcategory/{category}/URL/{url}/IP` | **Excluded/deferred** — Excluded resource: additive IP mutation has no documented individual IP deletion; cannot implement a complete membership lifecycle. |
| [Add URLs to a specified URL Category](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_put_url.htm) | `PUT /api/v1/plugins/{brand}/URLcategory/{category}/URL` | **Excluded/deferred** — Excluded mutation: body example has one urls wrapper, cURL has two; cannot establish safe merge/overwrite semantics. |
| [Edit the URL of a specified URL Category](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/url-categories_put_url_url.htm) | `PUT /api/v1/plugins/{brand}/URLcategory/{category}/URL/{url}` | **Excluded/deferred** — Deferred: URL rename alone is insufficient for a safe complete URL resource lifecycle. |

## SOAP administration review

[SOAP catalog](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/afa-soap-web-services.htm)
was also inspected to avoid overlooking durable administration:

- [Devices/groups](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/managing-devices-and-groups.htm):
  create group and add member exist, but no documented group deletion/member removal
  in this catalog establishes a complete lifecycle. REST is recommended for devices.
- [Users/roles](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/managing-users-and-roles.htm):
  mutations exist, but REST inventory envelope/field inconsistencies and SOAP
  success-message strings are insufficient for safe implementation without further
  contract evidence. No SOAP paths, namespaces or status formats are invented.
- [Set configuration](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/setting-configuration-parameters.htm)
  and [get configuration](https://techdocs.algosec.com/en/asms/a32.60/asms-help/content/api-guide/getting-a-configuration.htm):
  generic secret-bearing settings with no unset/reset contract; excluded.

All committed fixtures are synthetic. No live appliance, credential manager,
external mutation, acceptance environment, or Registry publication was used.

## A33.20 experimental groups and later authorization APIs

This version-specific review incorporates the independent report
[`independent-api-research.md`](/home/hermes/algosec-provider-work/independent-api-research.md)
(2026-09-09; research remains outside this repository). Its primary sources are
linked below; A33.20 contracts do not establish A32.60 availability.

`algosec_device_group` and both group data sources require
`experimental_device_groups=true`, default false. AlgoSec marks these APIs
**Early Availability and does not recommend production use**:
[vendor warning](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/managing-devices-and-groups.htm).
No live compatibility is claimed. Paths use `/afa/api/v1`, following the base rule
in the AFA REST catalog linked above; isolated examples omit `/afa` inconsistently.

| Operation | Official contract |
|---|---|
| Inventory | [GET /groups](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/groups_list_dev_get.htm) |
| Create | [POST /groups?displayName=...](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/groups_create_post.htm), nonempty array of device display names |
| Add members | [POST /groups/{displayName}/addDevices](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/groups-add-device-post.htm) |
| Remove members | [DELETE /groups/{displayName}/removeDevices](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/groups-devices-delete.htm), cannot empty group |
| Delete | [DELETE /groups/{displayName}](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/groups-existing-delete.htm), leaves devices intact |

Rename requires replacement. Membership is authoritative and nonempty; additions
precede removals, with complete inventory readback and exact verification at each
step. Partial failure retains confirmed observations. Only validated complete
administrator inventory proves absence. Concurrent changes and filtered inventory
remain limitations. See the [resource contract](resources/device_group.md).

A33.20 documents [user REST creation](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/users_createnew_post.htm)
and [role REST creation](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/roles_create_post.htm),
plus update/delete; these are not universally SOAP-only. Managed users and roles
remain excluded because [user reads](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/retrieving_users.htm)
and [role reads](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/retrieving_roles.htm)
do not establish complete authorization fields or reliable collection envelopes.
The role read is `/users/Roles`, not an invented GET `/roles`; malformed examples
and `EnableGlobalCustomization` do not establish `enableGlobalTrustTraffic` drift.

Group create records Terraform ownership only after a successful POST response with a validated positive acknowledgment, before inventory readback. Unconfirmed creates (HTTP or transport errors, malformed or unsuccessful acknowledgments) leave no managed state and do not adopt a visible group. If the POST outcome is ambiguous, inspect the remote group and verify ownership before importing or retrying. An acknowledged create retains recoverable identity if readback fails; successful readback still verifies exact membership. Existing-owned update/delete partial-state recovery is unchanged.
