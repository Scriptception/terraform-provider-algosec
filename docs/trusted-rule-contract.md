# A33.20 trusted-rule assignment contract

Release candidate 0.2.0, researched 2026-09-09. Publication and Registry
verification are pending; live acceptance has not been performed. This adds one managed
resource, `algosec_trusted_rule`, and three operations. Published v0.1.4 remains
unchanged. Horizon Security Analyzer/AFA is included through the existing AFA
API identifiers. No appliance compatibility or vendor Early Availability status
is inferred for this feature.

## Official evidence and selected contract

- [A33.20 AFA REST catalog](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/afa-rest-web-services.htm)
  declares `/afa/api/v1` with a PHPSESSID cookie, distinct from `/fa/server`.
- [GET trusted rules](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/trusted-rules-get.htm)
  documents `/api/v1/trusted-rules/rules`, mandatory `deviceNames`, and device
  entries containing `deviceName`, `deviceDisplayName`, `deviceId`, `trustedRules`.
  Rules have `ruleId`, `comment`, and `expirationDate` (YYYY-MM-DD).
- [POST trusted rules](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/trusted-rules-add-post.htm)
  saves rules for one actual device: `deviceName`, `rules:[{id,comment?,expirationDate?}]`.
  Future expiration is required when supplied. Groups/ALL_FIREWALLS are disallowed.
- [DELETE trusted rules](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/trusted-rules-delete.htm)
  removes trust assignments using `deviceName`, `ruleIds`. It does not delete
  firewall rules. `trustedRuleIds` acknowledges successfully **deleted** IDs.

All three selected routes are `/afa/api/v1/trusted-rules/rules` using the existing
cookie client. GET/POST examples omit `/afa` and show Bearer tokens; DELETE's
example omits authentication entirely. We give the explicit catalog base/session
rule precedence over these examples. This is a documented-contract interpretation,
not proof of appliance behavior. There are no Bearer fallback, alternate routes,
write retries, credentials in URLs, or new TLS exceptions. The separate provider
flag `experimental_trusted_rules=true` acknowledges this uncertainty; it does not
inherit the vendor EA warning attached specifically to device groups.

## Ownership and lifecycle

The resource owns one device/rule trust assignment. It requires complete and
stable administrator visibility. GET requests one device; only exactly one entry
matching that device, with nonempty device identity/display name and a non-null
rules array, may prove rule absence. Omitted devices, null lists, duplicate IDs,
missing managed metadata, malformed dates, error envelopes and non-success HTTP
responses fail closed. This deliberately refuses an empty top-level response,
including a removed underlying device: resolve that situation explicitly rather
than treating unknown visibility as deletion. No legacy trusted-traffic hit
filtering is used. Server-filtered lists cannot be detected from their contents;
complete administrator visibility is an operational prerequisite.

Preflight refuses existing assignments and directs import. POST must acknowledge
exactly the requested rule ID in `trustedRuleIds`, without failures, conflicting
IDs or malformed fields. Its device scope comes from the single-device request;
the documented response does not echo device identity. Acknowledgement records
recoverable identity before GET; readback must match metadata. Unconfirmed POSTs
never trigger read-and-adopt. After ambiguous transport failure, inspect the
assignment and verify ownership before importing or retrying.

The docs do not establish conditional-create or existing-ID update semantics.
A writer racing between preflight and POST can still overwrite/adopt the same
assignment if the API saves existing IDs. There is no unique creator token,
transaction, ETag or ownership lease. Do not share the same assignment with other
writers. We do not claim atomic ownership or an impossible conditional-create API.

All input changes require delete-then-create replacement, avoiding invented
metadata update/reset semantics. Replacement temporarily removes trust;
`create_before_destroy` must not be used for same-identity metadata changes.
Delete preflights exact current metadata, requires the operation-specific positive
acknowledgement, then verifies absence. Errors retain prior state for recovery;
no writes are retried. A same-identity delete race also remains possible.

Comment and expiration default to empty strings, and empty values are omitted
from POST. Explicit null metadata returned by GET is represented as empty;
omitted metadata is refused as incomplete. A nonempty returned default differing
from the plan produces an error with confirmed state rather than false success.
Dates are calendar-validated. Plans for creation or any input replacement reject
known nonempty dates that are not strictly after the current UTC date, before
Terraform can delete the old assignment. Unchanged expired metadata remains valid
for refresh, import, no-op plans and destroy. Unknown expiry values remain unknown
and are validated when resolved; a known invalid expiry is rejected even if another
replacement input is unknown. Create revalidates as defense in depth. This cannot
guarantee replacement safety for an expiry unresolved during planning or a date
that expires between plan and apply.
Refresh preserves a returned expired assignment, never inferring deletion from
the clock. When the complete server list removes it, Terraform detects drift;
recreation with the old expired date is refused until configuration is changed.
The server's timezone and expiry cleanup timing remain live-acceptance questions.

## Identity and limits

Import uses `v1.<base64url(device_name)>.<base64url(rule_id)>`, unpadded canonical
UTF-8 tokens. Parsing preserves case, whitespace and special characters; invalid
UTF-8, padding, noncanonical tokens and control characters are refused. Device
names containing commas are unsupported because the documented GET array uses
comma separation. Rule IDs containing commas are safe in JSON. Groups cannot be
selected intentionally; the API's actual-device requirement remains authoritative.

All tests are synthetic HTTPS fixtures. Tests exercise Terraform protocol
create/import/replacement/clearing/drift/destroy, ownership and state recovery,
per-item failure responses, malformed and duplicate data, HTTP errors, transport
ambiguity and expiry. No appliance, credentials, Vault, external mutation or
publication was involved. Promotion requires separately authorized A33.20 live
acceptance of the selected auth/base route, metadata defaults, complete visibility,
expiration behavior, and disposable create/import/replace/delete recovery.
