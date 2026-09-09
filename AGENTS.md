# Contributor guidance

- Scope is durable ASMS A32.60 administration. Read docs/api-coverage.md before
  adding endpoints. Public official contracts are primary; never invent routes,
  payloads, identifiers, response envelopes or delete/reset behavior.
- Use native Terraform Plugin Framework, internal/client typed HTTP methods and
  internal/provider typed schemas. No generic JSON CRUD or raw-response state.
- Preserve read-after-write, honest import, definitive absence handling and
  recoverable state. Do not reinterpret permission/HTTP errors as absence.
- Keep HTTPS/TLS verification default, refuse redirects, bound requests, and never
  replay writes automatically. Secrets must not be logged or stored in resources.
- Keep examples tenant-neutral. Fixtures are synthetic and must be labelled.
- Run make fmt-check test vet vuln docs-check smoke. Add focused contract and
  Terraform protocol lifecycle tests when changing schemas or lifecycles.
- Live tests require TF_ACC=1. Mutation additionally requires
  ALGOSEC_ACC_MUTATION=1 and ALGOSEC_ACC_DISPOSABLE=1. Read-only tests cannot mutate.
- Update generated docs through schema/examples and make generate; update API
  coverage, VERSION and CHANGELOG for changed capability or release behavior.
- Keep research source dumps out of this repository. Do not commit credentials,
  state, plans, appliance captures, generated binaries or tool downloads.
- Publication, commits, tags and external changes require explicit authorization.
