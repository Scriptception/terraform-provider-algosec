# Security

Do not include credentials, session cookies, Terraform state/plans, appliance
responses or tenant inventory in issue reports. Report reproducible behavior
using synthetic examples and redacted diagnostics.

The HTTP client enforces HTTPS origins, verifies TLS unless explicitly disabled,
refuses all redirects, bounds timeouts and body sizes, and never retries writes.
It does not log response bodies, URLs, auth headers or cookies. Environment
credentials are preferred; managed resources do not contain credentials.

Use stable administrator visibility for managed-device refresh. The API's
permission-filtered inventory cannot prove deletion if permissions change.
State contains ordinary administrative inventory and must be protected by the
operator. See README and docs/api-coverage.md for the remaining boundaries.
