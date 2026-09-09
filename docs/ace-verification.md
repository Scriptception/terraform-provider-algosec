# ACE isolated implementation verification

Source baseline: `08bc6987728133b05c2c3dd1603435f1529d5df1`, branch
`feat/ace-durable-config`, development version unchanged at `0.3.0-dev`.
No published history or pins were changed. Parent frozen review and serial
integration remain separate from this implementation's local verification.

## Scope

Four ACE resources add eighteen method/route operations:

| Resource | Operations | Synthetic lifecycle evidence |
|---|---:|---|
| `algosec_ace_cd_notification_emails` | 2 | Empty preflight, positive PATCH ownership, import, selective update, drift, absence/recreate, explicit empty-array destroy, invalid replacement planning |
| `algosec_ace_jira_integration` | 3 | Singleton create/import, token conversion, no-op/destroy without token, replacement, drift, absence/recreate, missing-token and mixed-unknown invalid replacement rejection |
| `algosec_ace_threat_list_entry` | 3 | Create/import, replacement, metadata drift, absence/recreate, exact destination delete, complete pagination, duplicate/inconsistent/incomplete page rejection |
| `algosec_ace_cloud_account_registration` | 10 | AWS/Azure/GCP create/import, opaque accountKey matching, name-only update, replacement, tokenless operations, manual-provenance checks; Azure/GCP drift/absence; typed bootstrap DTOs |

Total in this isolated clone: **8 resources, 12 data sources, 42 selected operations**.
The 24-operation base and 934-record discovery ledger remain intact. The
[18-operation delta](ace-operation-additions.json) is intentionally portable and
marked for parent integration. There is no global product-completeness claim.

## Tests and security checks

Tests were written before each new client/resource implementation. The saved
`batch1` through `batch4` RED logs show missing implementations and protocol
registration failures, followed by passing client/protocol logs. Additional
assertion-based RED/GREEN regressions cover mixed-unknown bootstrap validation,
strict acknowledgement decoding, and malformed AWS role ARNs. The first broad
gate run exposed the expected old schema count (4 versus 8); the schema/count
assertions now match the implemented surface.

Framework recovery tests cover all four resources: unconfirmed create never
adopts or reads back, acknowledged identity survives readback errors, and owned
read/update/delete errors retain state. Client tests cover exact positive and
malformed/partial acknowledgements, missing/null reads, duplicate identities,
HTTP permission/error handling, verified TLS, no redirects or write replay,
read-only/experimental gates, and sanitized diagnostics. Fixtures and disposable
cryptographic test keys are synthetic, never tenant captures or credentials.

The compiled-provider smoke plans twelve creates without refresh or apply, and
checks that ephemeral Jira/bootstrap secret values are absent from the JSON plan
on Terraform 1.16.1. Terraform 1.11.0 remains covered by literal write-only
protocol tests and package/schema checks, but cannot serialize the recommended
ephemeral values in a saved plan.
Write-only attribute values are omitted from state; literals written directly
in HCL can still appear in Terraform's saved configuration expressions. The
examples therefore use ephemeral variables, and the contract documents this limit.

The test suite includes real Terraform protocol execution on Terraform 1.11.0,
the minimum for write-only arguments, and the current installed Terraform. The
recommended ephemeral saved-plan path is verified on Terraform 1.16.1.
ZIP filesystem-mirror init/validate/schema checks use both versions. These are
local installation checks, not Registry signature verification or publication.

## Gate commands

The final local gate runs are recorded in the worker's external evidence folder:

- `make release-check`: coverage-check, package-smoke, fmt-check, race/coverage
  tests, vet, vulnerability scans for provider and documentation tool, docs-check,
  compiled smoke, actionlint, module verification and GoReleaser configuration.
- Terraform 1.11.0 ACE/schema protocol suite with race detection and fresh execution.
- Terraform 1.11.0 package-smoke against the final local binary.
- Final generated-document consistency and `git diff --check`.

Forty-four official ACE operation nodes and three matching service exports were
independently re-fetched and matched the supplied public contracts. Six of those
nodes recheck the risk-profile/suppression blockers; eighteen are selected new
operations. Jira's token conversion was separately verified in the official guide.
All research dumps, detailed command logs and frozen commit/tree evidence stay
outside this repository.

No live tenant/appliance calls, approved secret-manager access, external IAM
changes, system installations, signing, tags, remotes or publication were used.
The [contract](ace-contract.md) records remaining compatibility, concurrency,
normalization, access-read and excluded-family reopening conditions. Local green
tests do not establish live ACE compatibility.
