# AppViz SaaS role contract — unreleased 0.3.0-dev

`algosec_appviz_role` implements the public SaaS Permissions API Controller,
retrieved 2026-09-09. Vendor **Early Availability**, explicitly enabled with
`experimental_appviz_roles=true`. This is neither the legacy BusinessFlow
A32.60/A33.20/A33.30 contract nor an AFA role. No live acceptance is claimed.

## Official evidence and chosen wire contract

- [Create role](https://api-docs.algosec.com/docs/appvizsaas-api-docs/nfm3d9hk4k4i2):
  POST `/BusinessFlow/rest/v1/settings/permissions/role/new`.
- [Read role](https://api-docs.algosec.com/docs/appvizsaas-api-docs/7r93tg1xsbeqf):
  GET `/BusinessFlow/rest/v1/settings/permissions/role?name=...`.
- [Update permissions/users](https://api-docs.algosec.com/docs/appvizsaas-api-docs/4wo7alllbgaph):
  POST the same role route with case-sensitive name query.
- [Delete role](https://api-docs.algosec.com/docs/appvizsaas-api-docs/mkgujbmi04j1h):
  DELETE the same role route with name query.

The official documentation site's public schema nodes were retrieved directly,
including the referenced permission models, then the four operation nodes were
independently fetched again through their public metadata URLs. Raw schemas and
examples remain outside Git. Their regional server base is
`https://<region>.app.algosec.com/BusinessFlow/rest`; operation paths start `/v1`.
The API document is an unversioned SaaS stream: the inventory snapshot date is
not a claim that an ASMS release implements it.

Authentication is the documented Bearer scheme. Configure `appviz_saas_url`
and preferably `ALGOSEC_APPVIZ_SAAS_TOKEN`. Tokens are never acquired, refreshed,
logged, or placed in resource state by this client. Environment configuration
avoids putting tokens in HCL or saved configuration/plan inputs. The client
always verifies TLS, refuses redirects and automatic write replay, bounds each
request to 1–300 seconds and 8 MiB, and never includes response bodies, URLs or
authentication headers in diagnostics. AFA credentials/cookies are separate;
SaaS-only configuration is supported and rejects AFA operations without AFA setup.
The existing `insecure` flag applies only to AFA; it cannot disable SaaS TLS.

## Managed fields and ownership

Create sends the exact name, enabled flag, complete user-name list, allowed global
permission-name list and application permissions. Read returns `name`, `enabled`,
`roleUsers`, `authorizedViewsAndActions` (name/allowed pairs) and
`authorizedApplications` (applicationID/name/permission triples). All selected
fields and arrays must be present and non-null. Duplicate or contradictory
identifiers, unknown fields, malformed JSON and invalid permission values fail
closed. Global entries with `allowed=false` are not members of the allowed set.
Application IDs are canonical positive integer **revision IDs**, represented as
string keys in configuration and create, and integers in read, as the schema
specifies. Permission values are `view` or `edit`.

The resource owns the entire role, including all readable authorization and user
membership sets. Existing roles require explicit import by exact case-sensitive
name. Description and LDAP linkage are not exposed as arguments because the
public GET omits them. Delta updates omit those fields. Importing a role still
means authorizing destruction of that role; inspect its non-readable metadata
before importing. Use dedicated roles with no independent writers or overlapping
permission/membership resources.

Create preflights GET. Only its documented 404 proves absence; 401/403 and all
other statuses retain state/fail creation. POST must return a complete role for
the requested name before any state is acquired. An unconfirmed POST never
triggers same-name lookup/adoption. A complete positive create response establishes
recoverable state before readback. Readback mismatch or error produces a diagnostic
and retains confirmed identity/state rather than claiming success.

User and allowed-global-permission updates use explicit `add`/`remove` deltas,
after verifying current readable state still matches the refreshed state.
Application permission changes, enabled changes and name changes replace. This
avoids guessing ordering for removal/addition of an existing application permission
or inventing an enabled setter. Known invalid names, null membership elements and
invalid application IDs/values are rejected before replacement deletion, including
known invalid elements alongside unknown siblings. Inputs unresolved until apply
remain an apply-time limitation. Replacement temporarily removes the role and
must not use same-name `create_before_destroy`.

Delete preflights the complete role and refuses unexpected drift. The published
DELETE schema is a generic `body/statusCode/statusCodeValue` wrapper; its example
contains placeholder `100 CONTINUE` and zero. The implementation requires a
well-formed wrapper with nonempty statusCode and statusCodeValue 200, then requires
GET's documented role-not-found 404. It does not treat the placeholder example or
HTTP success alone as deletion proof. Malformed acknowledgements, dependency
errors and successful responses followed by a surviving role retain state.

The docs do not establish conditional create, ETags or atomic compare-and-delete.
A writer racing between preflight and mutation can still change/adopt the same
name. An enabled/application replacement can also lose unreadable metadata of an
imported role. These are explicit scope limits, not transactional ownership claims.
Permissions and names depend on tenant availability; server rejection is surfaced
without replay. There is no pagination in the exact role GET contract.

## Verification and reopening

Synthetic trusted-CA HTTPS tests cover protocol create/import/update/empty sets,
external deletion/destroy; failed-create nonadoption, retained confirmed state,
changed-role deletion refusal, malformed/partial/error responses, redirect and
transport ambiguity, verified TLS, safety gates and invalid replacement inputs.
Existing category/group/trusted-rule regressions remain required.

Before promotion, independently validate the chosen wrapper, complete permission
visibility, default permissions, duplicate-name create behavior, application
revision IDs, delta updates, dependency deletion, and SaaS version compatibility
in separately authorized disposable live acceptance. No such calls are authorized
or claimed in this batch.
