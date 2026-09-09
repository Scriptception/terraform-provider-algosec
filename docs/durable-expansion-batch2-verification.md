# Tag/URL and review-fix sub-batch verification

Unreleased `0.3.0-dev`, single writer, synthetic local HTTPS only. No appliance,
credential/Vault access, live acceptance, remote changes, signing or publication.
Published version pins and release history remain historical.

Delivered surfaces: `algosec_tag` (A33.30 vendor EA) and
`algosec_url_ip_membership` (selected A33.20 contract). Current compiled schema:
**6 resources and 12 data sources**; exact source mappings: **31 operations**.
Tag-hostgroup assignment remains blocked on the specific identity mapping in
[tag contract](tag-contract.md); FireFlow and narrowed AppViz/ACE subsets remain
active work. This sub-batch is not final durable-family closure.

Independent batch 1 findings S1, P1 and P2 were reproduced as actual RED tests,
then fixed with preserved regressions. S1 permits the published placeholder DELETE
wrapper to reach exact absence confirmation. P1 validates serialized create size
before replacement, including known oversized values beside unknown siblings.
P2 isolates disabled ambient SaaS settings from AFA-only configuration. Explicit
whole-role destructive ownership consent and the vulnerability permission
prerequisite now apply; hidden description/LDAP metadata is never claimed preserved.

External numbered logs retain the actual execution evidence:

| Evidence | Result |
|---|---|
| `20`, `23`, `25`, `27`, `34`, `37` RED logs | Missing tag/IP clients and provider surfaces, ambiguous tag JSON, old inventory-schema rejection |
| `22`, `30`, `32`, `44` RED logs | Independent DELETE, oversized replacement, disabled ambient service and ownership/dependency regressions |
| `21`, `24`, `26`, `28`, `29`, `31`, `33`, `35`, `36`, `40`, `41`, `45` | Focused GREEN client/protocol/recovery/inventory checks |
| `43-subbatch2-release-check.log` | Initial full run found the old four-resource schema count; updated to verify six explicit resource names |
| `46-subbatch2-release-check.log` | Full `make release-check` passed on Terraform 1.16.1 |
| `47-subbatch2-minimum-protocol.log` | Entire race-enabled provider suite passed on Terraform 1.11.0 |
| `48-subbatch2-minimum-smoke.log` | Compiled offline plan/schema and candidate ZIP mirror install/validate/schema passed on Terraform 1.11.0 |

Release-check includes format, race/protocol tests, vet, root/tool vulnerability
scans, generated-doc parity, inventory invariants, compiled smoke, package smoke,
actionlint, module verification and GoReleaser configuration validation. ZIP tests
are unsigned local mirror installation, not Registry or live-appliance acceptance.
Cross-platform archives and remote CI remain the parent's separate responsibility.

Inventory checks reproduce frozen sanitized metadata and validate the current
implementation overlay: **975 records, 1,048 source observations, 747 selected
REST, 66 unresolved REST and 162 SOAP catalog names, zero certified QNames**.
All mappings have exact source/version/method identity and actual client/test files.
The audit's original fields remain historical evidence; new nominations are not
silently overwritten by earlier broad blockers. Final independent frozen-source
review remains pending.
