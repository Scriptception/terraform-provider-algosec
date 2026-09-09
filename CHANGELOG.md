# Changelog

## 0.1.4

- Release-signing alignment: use the maintainer's shared Terraform GPG key already registered for Scriptception. No provider code, API, schema, or dependency changes.
- Update example version pins. Keep the v0.1.3 tag and published assets unchanged; Registry ingestion is verified separately after publication.

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
