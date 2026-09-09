# Experimental ACE SaaS durable configuration

This isolated `0.3.0-dev` candidate adds four resources and eighteen operations
against the rolling public ACE SaaS contracts retrieved 2026-09-09. This is
**not a Horizon/ASMS version**, appliance test, release, or whole-product coverage
claim. The portable [operation delta](ace-operation-additions.json) requires
parent integration into the final inventory; the existing 934 discovery records
and published installation pins remain unchanged.

## Authentication and evidence

Set `ace_url` to the tenant's regional HTTPS **origin**, for example
`https://us.app.algosec.com`. Official regions are `us`, `eu`, `anz`, `me`, `uae`,
`ind`, and `sgp`. CAA configuration and threat routes use `/prevasio`; unified
account administration uses `/api/algosaas`. These exact service bases are not
interchangeable with AppViz, AFA, or historical CNS administration.

Supply an externally obtained bearer access token using environment-only
`ALGOSEC_ACE_ACCESS_TOKEN` (origin: `ALGOSEC_ACE_URL`). Optional sensitive
`ace_access_token` configuration can persist in Terraform plans; environment-only
credentials avoid that configuration persistence. ACE never obtains, refreshes,
logs, or saves tokens in resource state. Expiry fails the operation. No credentials
or tenant APIs were used during development.

Set `experimental_ace_public_contracts=true` and, for mutations, `read_only=false`.
ACE always verifies TLS, even if the unrelated AFA `insecure` option is enabled.
Requests have bounded time/body limits, refuse redirects, and never replay writes.
HTTP errors exclude URLs, headers, payloads and raw response text. Invalid JSON,
duplicate keys, null/missing managed fields, unknown error envelopes, and
401/403/404 do not prove absence. Reads require complete stable tenant visibility.

The eighteen selected operation nodes, plus twenty related ACE nodes, were
independently re-fetched from official documentation metadata and exactly matched
the supplied bundled contracts. The three matching public service exports also
matched byte-for-byte. Source URLs, regional bases, contract versions and client
functions are recorded per operation in the delta. Research dumps stay outside
this repository. The Jira [integration guide](https://techdocs.algosec.com/en/ace/content/cloud-apps/prev-integrations-jira.htm)
independently confirms base64 conversion of `email:raw-token`.

## CD notification email set

`algosec_ace_cd_notification_emails` owns the complete nonempty email set for one
`cloud_provider` (`aws|azure|gcp`). Identity/import is that provider name. GET
requires a complete typed `data.threatManagement` and
`data.violationNotifications.emails` response, while only emails enter state.
Spelling is preserved; duplicate/null/invalid addresses fail closed.

Create requires an empty existing email list. Nonempty sets must be imported;
empty sets cannot be imported. PATCH sends only
`{"violationNotifications":{"emails":[...]}}`. It never writes threatManagement,
protection switches or severity. The exact documented update acknowledgement is
required before create acquires ownership, then GET verifies the set. Update
preflights the last refreshed set. Destroy PATCHes an explicit empty array, the
vendor-documented reset, and verifies it. A complete empty set is authoritative
child-assignment absence; it does not mean the parent integration is absent.

## Jira integration

`algosec_ace_jira_integration` is a tenant singleton, imported as `jira`. GET's
literal `data:{}` is absence; missing/null data is not. All five nonsecret fields
are read from GET. The masked `apiToken` is never written to state or reused.
For new submissions, issue type and priority must be explicitly nonempty,
avoiding the public schema's ambiguous `"''"` defaults. Existing integrations
with readable empty defaults can be refreshed/imported and destroyed.

`api_token_wo` takes the **raw** Atlassian API token. The provider internally
base64-encodes `user_name:api_token_wo`, as documented by AlgoSec. Write-only fields
require Terraform 1.11 or later and may use ephemeral variables. The recommended
ephemeral saved-plan examples require Terraform 1.16.1 or later because Terraform
1.11.0 cannot serialize those marked values into a saved plan. Their attribute
values are absent from plan and state. Terraform can still include a literal
secret written directly into HCL in the saved configuration expression; write-only
attributes cannot redact that configuration source. Token changes alone cannot produce observable drift: change
`replacement_version` to deliberately replace with a new token.

POST requires the exact tested-and-saved message; conflict or generic success
never adopts an existing singleton. DELETE requires its exact message and GET
absence. There is no PATCH. All nonsecret configuration changes replace using
delete then create. **Do not use create_before_destroy.** Replacement requires
resolved credentials before planning destruction, with known-invalid fields
rejected even alongside unknown siblings. Import, refresh, unchanged plans and
destroy do not require the write-only token. Unknown values and credentials can
still change between plan and apply; failed creation after deletion requires
operator recovery, not reconstruction of the old secret.

The integration guide describes deletion as losing alert-to-ticket associations,
without deleting Jira tickets. Treat API deletion/replacement as disruptive and
do not assume association retention. This side effect has not been live-tested.

## Custom threat-list entry

`algosec_ace_threat_list_entry` owns exact `threat_type`, `list_type`, `destination`
and readable description/severity. Threat types are `ip-addresses`, `domains`,
`open-ports`, `countries`, `cve`, `malware-names`; lists are only `block-list` and
`allow-list`. Block entries require `low|medium|high|critical`; allow entries omit
severity entirely. Description is explicit and may be empty. All changes replace;
there is no invented PATCH. Replacement temporarily removes the old entry.

GET reads every page, checking `page.current`, `page.limit`, `page.total` (pages)
and `page.totalItems`. It rejects duplicate destinations across any pages,
changing/inconsistent totals, incomplete pages and missing metadata. Bounds are
1000 pages and 1000 items per page. Only a complete valid inventory proves absence.
Both zero- and one-page empty representations are accepted when totalItems is zero.

Create preflights absence and requires the operation-specific message containing
the exact destination/list/threat. DELETE always carries the exact nonempty
`destination` query parameter; omitting it can delete the whole list and is never
allowed. Deletion preflights current metadata and verifies absence after the
exact acknowledgement. Whole-list ownership is intentionally unavailable.

Import is `v1.<base64url(threat_type)>.<base64url(list_type)>.<base64url(destination)>`,
with canonical unpadded UTF-8 tokens. No lowercasing, CIDR normalization, country
alias conversion or fuzzy match is invented. The server validates destination
semantics. Exact spelling and exclusive writers are experimental prerequisites;
duplicate insertion and normalized-alias behavior require live/vendor confirmation
before stronger guarantees can be offered.

## Manual cloud registration and name

`algosec_ace_cloud_account_registration` supports AWS, Azure and GCP using distinct
typed DTOs behind one typed schema. It owns registration existence, name, provider,
account ID, manual provenance, and the readable Azure tenant/GCP organization
identity. `account_id` is an expected identity for preflight/readback, not an extra
AWS POST field. POST must return HTTP 201 with nonempty `accountKey`. GET must
match that exact key and return the expected accountId/provider and
`autoOnboarded=false`. The account ID is never inferred by splitting the key.
Import uses the exact opaque accountKey and refuses automatic registrations.

`unified_onboarding=true` explicitly asserts tenant eligibility; the public
contract does not expose a migration-state probe. Historical CNS administration
is not used as a fallback. PATCH sends **name only**, including Azure where the
same endpoint also accepts credentials. DELETE removes registration; it does not
create/delete external IAM roles, applications, service accounts or keys.

Bootstrap fields ending `_wo` are individually typed **submission-only** inputs.
They are not managed access configuration, ignored desired configuration, or an
access-drift guarantee. All are discarded after use and omitted on name updates.
Change `replacement_version` when deliberately resubmitting bootstrap data; changing
bootstrap values alone does not rotate credentials. Replacement requires the
matching complete, resolved bootstrap inputs before old-registration destruction.
Import, refresh, no-op, name update and destroy work without them.

- AWS requires matching `role_arn_wo`, `external_id_wo`, and explicit nonsecret
  `support_changes_wo` / `flow_logs_wo` booleans. Initial ARN support is the public
  `arn:aws:iam` form, not inferred alternate AWS partitions.
- Azure requires `azure_tenant`, subscription `account_id`, and explicit
  `application_id_wo`, `application_secret_wo`, `support_changes_wo`. Requiring
  application credentials resolves the prose-required/schema-optional ambiguity
  conservatively; no omitted-credential mode is claimed.
- GCP requires `organization_id` as specified by the schema, project `account_id`,
  and every typed service-account field: credential type, private key ID/PKCS8 key,
  client email/ID and four HTTPS URI/certificate fields. Keys are supplied externally;
  tests generate disposable synthetic keys locally. Raw JSON blobs are not accepted.

GET omits AWS roleArn/externalId, Azure application credentials, and GCP
service-account credentials. Concrete counterexample: externally replacing an AWS
role with another role in the same account can leave name/accountKey/accountId and
permissions unchanged. This resource correctly makes no promise to detect that
change. Full access-configuration ownership remains blocked until an authoritative
current nonsecret configuration read and an explicit secret submission/version
contract cover those fields. The reduced registration/name lifecycle remains usable.

## Ownership, recovery and reopening conditions

Acknowledged identity is saved **before** post-create readback. Failed/unconfirmed
creates never use GET to adopt a concurrent object and never trigger cleanup.
Owned update/delete/read failures retain recoverable state. Preflight comparisons
cannot prevent races after the read: these public APIs provide no transaction,
ETag, conditional-create or ownership lease. Use one state owner and no concurrent
external writer for each managed identity. Read-after-write is immediate, with
honest recoverable errors for delayed consistency rather than retries.

Other ACE families remain explicitly bounded:

| Family | Disposition and reopening evidence |
|---|---|
| Full CD protection configuration | Email child reset is implemented; whole protection ownership needs a defined neutral reset, not invented disabling of security. |
| CNS risk-profile ownership | Evidence blocked: multipart CSV import has no canonical typed row/export contract; list shape is incomplete; DELETE lacks successful response contract. Need typed equivalence, duplicate/overwrite behavior, authoritative absence and positive delete. |
| Default risk-profile assignment | Evidence blocked: need readable current assignment and documented neutral reset; never restore an untracked snapshot/default name. |
| Risk/trigger suppression | Evidence blocked: free-form status/bulk applyToAll does not establish per-assignment identity, complete status enum, reset and re-detection semantics. |
| Automatic onboarding | Operational orchestration, not manually owned accounts. Reopen only for durable object-specific read and inverse. |
| Credential issuance/rotation, diagnostics, scans, searches, CI downloads | Operational or read-only helpers; no workflow/action wrappers presented as resources. Reopen only on a durable public contract. |
| Legacy CNS Admin | No public usable export: original public export 404; bundled export marks internally excluded. Need a supported vendor public contract and migration guidance; no bypass or guessed routes. |
| UI-only controls without public API | No public contract; require exact published method/path/auth/DTO/read/inverse before implementation. |

Excluded-family evidence: [risk-profile import](https://api-docs.algosec.com/docs/ace/864e6c0a0660d-import-risk-profile),
[list](https://api-docs.algosec.com/docs/ace/367222a3ac7ef-get-a-list-of-risk-profiles),
[delete](https://api-docs.algosec.com/docs/ace/0615b2ac0ac23-delete-risk-profile),
[default assignment](https://api-docs.algosec.com/docs/ace/36419b434c44b-set-default-risk-profile),
[trigger status](https://api-docs.algosec.com/docs/ace/eb757e207179e-edit-risk-trigger-status),
[risk status](https://api-docs.algosec.com/docs/ace/62umds2jdukb8-edit-risks-status).

Validation uses synthetic local HTTPS and real Terraform protocol tests only.
Live acceptance must separately verify tenant visibility, normalization, consistency,
regional compatibility, manual provenance and deletion effects on disposable scope.
No live calls, Vault, credentials, system installs, tags, signing or publication
were authorized or performed.
