# Changelog

## 0.3.0

- Close reviewed Jira mixed-unknown payload, FireFlow Unicode acknowledgement and ACE method-binding validation gaps.
- Add a supplied-artifact migration regression from v0.2.0; see docs/published-upgrade.md for its bounded synthetic scope.

- Reject malformed AppViz DELETE body shapes and ambiguous category JSON without
  conflating case-sensitive identifiers; bind inventory routes to selected requests.
- Add separately gated A33.30 FireFlow direct User/Role membership and direct
  System/CustomField/RequestTemplate permission bindings with verified TLS,
  externally supplied session cookies and preserved inherited/unrelated grants.
- Add four separately gated rolling ACE SaaS configuration resources for CD
  notification email sets, Jira integration, custom threat entries and reduced
  manual cloud-registration/name lifecycles. Planning rejects oversized encoded
  writes and unresolved replacement bootstrap credentials; live compatibility is
  unverified.


- Add experimental A33.30 EA ALGOSEC tags and A33.20 singleton URL/IP membership.
- Fix independently reproduced AppViz oversized replacement, disabled ambient
  SaaS configuration, and documented DELETE-wrapper completion regressions.
- Require explicit whole-role destructive ownership acknowledgement, including
  imports; validate vulnerability permission prerequisites before replacement.
- Reconcile 975 discovery identities and 1,048 source observations with exact
  current implementation mappings. All additions remain experimental and unverified live.


- Add experimental `algosec_appviz_role` for the public AppViz SaaS Early Availability role contract, with separate bearer authentication, complete readable permission/membership ownership, explicit import, fail-closed reads and recovery. No legacy AppViz or live compatibility claim.
- Add four typed SaaS operations: role GET/create/update/delete (historical first sub-batch: 4 resources, 12 data sources, 24 selected operations). Preserve published 0.2.0 installation pins.
- Reject known-invalid category IPs alongside unknown values, and null group members, before replacement destroys owned objects.
- Remove name-only live-test cleanup that could delete another actor's category after an unconfirmed create; Terraform state drives cleanup.
- Add a cross-product public-operation inventory and runnable continuation ledger; remaining candidates are tracked separately from implemented lifecycles.

## 0.2.0

- Reject known expired trusted-rule creation/replacement dates during planning, before deletion; preserve unchanged expired assignments and destroy.
- Add experimental A33.20 `algosec_trusted_rule` single-assignment management with explicit import, metadata replacement, positive per-rule acknowledgements, strict readback and recoverable state. Separate opt-in from EA device groups; no live appliance acceptance.
- Add three typed operations, synthetic client/Framework/protocol tests and version-scoped coverage mappings (3 resources, 12 data sources, 20 operations). Published v0.1.4 remains unchanged.

## 0.1.4

- Release-signing alignment: use the maintainer's shared Terraform GPG key already registered for Scriptception. No provider code, API, schema, or dependency changes.
- Update example version pins. Keep the v0.1.3 tag and published assets unchanged; Registry ingestion and clean direct signature-verified installation passed on Terraform 1.11.0 and 1.16.1.

## 0.1.3

- Fix category create ownership: require the documented exact name/URL/IP acknowledgement before recording state; retain confirmed identity on failed readback.
- Validate rename/delete post-operation categories maps and retain owned state on ambiguous replies; keep GET verification and document conflicting vendor examples.
- Inventory all 85 A32.60 and 119 A33.20 catalog pages, separate literal labels from selected routes, map 17 implemented operations to Terraform surfaces, and add offline consistency gates.
- Add pinned read-only quickstart, filesystem-mirror ZIP installation smoke and practical first-user testing/publication checklist. No scope expansion.
- Published a signed GitHub release with eight platform archives; verified all uploaded assets and exact Linux archive installation. Registry onboarding/direct installation and live-appliance acceptance remain pending.


## 0.1.2

Unpublished ownership safety correction.

- Record new device-group ownership only after a validated positive create acknowledgment. Unconfirmed creates leave no managed state; ambiguous outcomes require inspection and ownership verification before import/retry. Acknowledged creates retain identity on readback failure. Existing-owned update/delete recovery is unchanged.

## 0.1.1

Unpublished final contract revision; supersedes the unshipped 0.1.0 surface.

- Remove file-device resource, writes and fixtures: existingFile readback is undocumented.
- Add explicitly gated experimental A33.20 EA device-group resource and two data
  sources (final surface: 2 resources / 12 data sources). Vendor advises against
  production use. Rename replaces; nonempty membership adds before removing,
  verifies inventory each step and preserves recoverable partial state.
- Reject whitespace-prefixed application failures and malformed/missing JSON
  acknowledgments, including mutation responses. Preserve category exact readback
  and content replacement, and parent authentication-cancellation/security fixes.
- Check pinned GoReleaser before release gates; add pinned actionlint validation.
- Preserve parent dependency versions; regenerate documentation and verify both
  supported Terraform test versions locally without live calls or publishing.

## 0.1.0

Initial unpublished implementation targeting the public ASMS A32.60 REST contracts.

- Native Terraform Plugin Framework protocol 6 provider with environment-based
  session or username/password authentication, verified HTTPS by default and a
  read-only default.
- Panorama URL-category and file-backed device resources with import, read-back,
  drift handling, conservative replacement and verified deletion.
- Ten typed inventory data sources for devices, categories, risk profile catalogs,
  security/topology zones, network objects and trusted traffic.
- Bounded typed HTTP client, redacted diagnostics, no redirects or automatic write
  retries, and explicit exclusion of incomplete/operational API contracts.
- Generated Registry docs, endpoint inventory, examples, unit and synthetic
  Terraform lifecycle tests, separately gated live tests, CI and signed-release
  configuration.

No live-appliance acceptance or Registry publication is claimed. See the coverage
map and verification report for prerequisites and contract limitations.
