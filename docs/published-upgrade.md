# Published 0.2.0 preserved-state upgrade regression

`TestPublishedUpgrade` installs the actual supplied published Linux amd64 ZIP
through a private packed filesystem mirror and runs real Terraform. It builds the
candidate from the current checkout with its `VERSION`. It never downloads a
provider, uses a development override, fabricates state, or imports to simulate an
upgrade. All configured API traffic goes to a synthetic localhost HTTPS fixture
with certificate validation enabled. No live compatibility is established.

Ordinary tests **skip this regression** without its explicit artifact/evidence
inputs; a green `make test` alone is not published-state upgrade acceptance.
Partial inputs fail. The published binary is not vendored. Obtain and independently
verify the release archive before running; supplying a hash is an assertion by the
caller, not fresh signature or GitHub provenance verification by this test.

Run separately with Terraform 1.11.0 and 1.16.1, using the same verified archive:

```sh
export ALGOSEC_UPGRADE_OLD_ARCHIVE=/absolute/path/terraform-provider-algosec_0.2.0_linux_amd64.zip
export ALGOSEC_UPGRADE_OLD_SHA256=dedadd03871808fd9819d8ef88f853fce7f5a988746a953b4671c6e7a36e39bf
export ALGOSEC_UPGRADE_EVIDENCE=/absolute/path/outside-checkout/published-upgrade/tf-1.11
export TF_ACC_TERRAFORM_PATH=/absolute/path/terraform-1.11.0
TF_ACC=0 go test -race -v -count=1 -timeout=10m ./internal/provider -run '^TestPublishedUpgrade$'

export ALGOSEC_UPGRADE_EVIDENCE=/absolute/path/outside-checkout/published-upgrade/tf-1.16
export TF_ACC_TERRAFORM_PATH=/absolute/path/terraform-1.16.1
TF_ACC=0 go test -race -v -count=1 -timeout=10m ./internal/provider -run '^TestPublishedUpgrade$'
```

Go and both Terraform executables must already be installed. This implementation
is intentionally limited to Linux amd64, matching the supplied published asset.
`ALGOSEC_UPGRADE_SCRATCH` optionally selects an existing executable filesystem for
temporary binaries, mirror and Terraform installation data; otherwise the OS temp
directory is used. This scratch directory is removed when the test exits normally.
On a disk-constrained Linux host, `ALGOSEC_UPGRADE_SCRATCH=/dev/shm TMPDIR=/dev/shm`
is usable only if that mount permits execution and has sufficient free memory.
Evidence is retained outside the checkout in a unique `run-*` directory even on
failure. Each Terraform command has a two-minute deadline; the candidate build
has a three-minute deadline. There is no automatic write retry.

The checks execute in this order:

1. Verify the old archive SHA256, exact versioned archive/member names and the
   binary's embedded Go module/version. Load actual old and candidate provider
   schemas via Terraform before creating a fixture. Require the three published
   version-zero resource schemas and their exact known attribute types; require
   those attributes/types to remain present in the candidate. Additional candidate
   fields/resources are allowed.
2. Exercise rejected checksum, archive version, embedded binary version, missing
   published schema and changed candidate ID-type inputs through the same guards.
   These are expected failures before a fixture exists, hence before managed writes.
3. Start the TLS fixture and use the **old binary** to create a device group, URL
   category and trusted-rule assignment. Verify three writes and expected IDs.
   Preserve the actual state bytes and SHA256, configuration, lock and values.
4. Change only the provider version pin and re-init against the candidate package.
   Assert re-init did not change the old state bytes. Require a no-change plan,
   refresh-only apply, stable IDs and every old attribute value, followed by a
   normal read/plan. Require zero additional managed mutations throughout.
5. Inject controlled fixture drift into group membership, category IP contents and
   trusted-rule comment. Require the exact plan: group update, category replacement,
   trusted assignment replacement. Planning must not mutate. Apply the saved plan
   and verify all owned values/IDs restored with exactly six additional operations
   (group add/remove, category delete/create, trusted assignment delete/create).
6. Require a clean plan and destroy with the candidate, exactly three more deletes
   and empty managed state. Unowned sentinel objects of all three kinds must retain
   their exact original values; the underlying firewall rule is never managed.

The run directory contains actual Terraform output/exit codes, schema JSON, saved
plans, published state/hash, old/candidate binary hashes, source HEAD/status, locks,
value snapshots and cumulative method/path events plus mutation counters and
fixture snapshots at each checkpoint. `PASS` is written only after final cleanup
and sentinel verification. These files contain synthetic data only; never commit
state, plans or binaries. Authentication is supplied only in the child environment;
request headers/bodies and credential values are not logged. The subprocess
environment excludes ambient AlgoSec settings, Terraform overrides, plugin caches,
proxy configuration and debug logging. The filesystem mirror has no direct/network
fallback. The fixture certificate is trusted through `SSL_CERT_FILE`; `insecure`
is explicitly false. Fixture calls are not appliance acceptance tests and do not
require or enable `TF_ACC=1`.

## Migration limits

This proves the specific valid, exclusively owned fixtures above survive the
published 0.2.0-to-current-checkout transition. It does not establish arbitrary
state compatibility, import compatibility, live appliance behavior, or acceptance
of separately merged implementation changes. The integrating parent must rerun
these commands on the final combined source and retain that source's evidence.

Existing ownership remains whole category, whole group membership and one trusted
assignment, respectively. New singleton URL/IP resources must not overlap a
category already managed as a whole. New provider gates/resources do not grant
ownership of existing objects automatically. Keep the existing group/trusted-rule
experimental opt-ins when upgrading.

Request-body and ownership validation may intentionally become stricter in the
candidate. Schema type compatibility does not mean every previously accepted
configuration or ambiguous server response remains valid. Review candidate
validation diagnostics and migration notes for the final source; reconcile invalid
values or ownership explicitly before applying. Do not edit state to bypass a
validation error, infer ownership from a same-name GET, or assume arbitrary legacy
payloads will remain accepted. This fixture uses valid IP addresses, nonblank exact
identifiers, complete readable ownership and a future trusted-rule expiration.
Category contents and trusted metadata drift intentionally produce replacements;
those replacements are tested only after the zero-mutation upgrade checkpoint.

## Bounded checkout verification

On 2026-09-09, the harness passed against the candidate built from base commit
`77b7ef95c673d76ee2ad2635292f806d1e39c76c` plus this test/documentation work,
with `VERSION=0.3.0-dev`. Both Terraform 1.11.0 and 1.16.1 produced the following
observed cumulative managed-mutation counts; each completed with 55 recorded HTTP
method/path events and unchanged unowned sentinels:

| Checkpoint | Terraform 1.11.0 | Terraform 1.16.1 |
| --- | ---: | ---: |
| Published binary created real state | 3 | 3 |
| Candidate upgrade plan and refresh | 3 | 3 |
| Candidate normal read and drift plan | 3 | 3 |
| Controlled reconciliation | 9 | 9 |
| Candidate final cleanup | 12 | 12 |

This is a local synthetic migration proof for that bounded source, **not final
combined-source acceptance**. Initial failed runs are retained alongside successful
runs: one exhausted disk space before fixture creation, and one exposed an
incorrect harness expectation that trusted metadata drift would update in place.
The corrected expectation explicitly requires the provider's replacement behavior.
