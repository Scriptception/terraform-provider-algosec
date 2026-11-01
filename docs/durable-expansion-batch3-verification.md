# FireFlow direct-binding sub-batch verification

Unreleased `0.3.0-dev`. Added `algosec_fireflow_role_member` (User/Role) and
`algosec_fireflow_role_permission` (System/CustomField/RequestTemplate).
This sub-batch compiled as **8 resources, 12 data sources**; the combined current
candidate now has 12 resources and 12 data sources. Its exact selected
method/route mappings were 35 before ACE integration. No additional parent-role inverse routes,
whole-role CRUD or live acceptance are counted. See [contract](fireflow-binding-contract.md).

External logs preserve the execution evidence:

- `50-fireflow-client-red.log`: missing typed client and tuple types.
- `52-fireflow-protocol-red.log`: missing provider configuration and resource surface.
- `51`, `53`, `54`, `55`, `57`: GREEN client, lifecycle, valid replacement, import,
  malformed/direct-inherited reads, permission/dependency errors, partial and mixed
  failures, ambiguous-write non-replay, TLS/auth separation, recovery and canonical
  identity checks. Known self-edges, System object IDs and oversized replacement
  payloads are rejected before the old direct binding is removed.
- `56-fireflow-inventory.log`: exact four-operation addition mapped to A33.30 IDs;
  original 975 records and 1,048 source observations preserved.
- `60` / `61`: initial gates failed at linking because the filesystem was full.
  This was an environment failure, not an API evidence blocker. Only this project's
  compiled cache entries and three inactive project build trees were reclaimed;
  source, logs, manifests and unrelated caches were preserved (`62` cleanup log).
- `63-fireflow-release-check.log`: complete `make release-check` passed on
  Terraform 1.16.1 after rerunning sequentially.
- `64-fireflow-minimum-protocol.log`: the entire race-enabled provider suite passed
  on Terraform 1.11.0.
- `65-fireflow-minimum-smoke.log`: compiled schema/offline plan and local ZIP mirror
  installation/validate/schema passed on Terraform 1.11.0.

Release-check includes format, race/protocol tests, vet, vulnerability scans,
generated docs, coverage/inventory invariants, compiled and package smoke,
actionlint, module verification and GoReleaser configuration validation. Local ZIP
installation is unsigned and does not establish Registry or appliance acceptance.

No appliance calls, credentials/Vault, live tests, external policy changes, remote
push/PR/merge, signing, tags or publication. Final independent frozen-source review
remains pending. Narrowed AppViz work remains; ACE's independent review and live
compatibility remain pending. This is an intermediate sub-batch, not final
durable-family closure.

Batch 2 final review additions are preserved in `67-batch2-review-red.log` and
`69-route-review-red.log`: four malformed wrapper shapes, duplicate-key create/read
ownership failures, and a wrong tag rename route accepted after regenerating the
overlay. `68` and `70` record GREEN. Regression tests retain state-level assertions,
valid distinct-case dynamic identifiers and fixed-schema alias collision rejection.
The full gates are rerun after these additions; earlier `63`–`65` evidence applies
to the FireFlow implementation before the review corrections.
