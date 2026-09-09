# Read-only first user test (0.1.4 candidate)

This configuration queries devices and risk-profile names. It does not require
Panorama category preparation or enable experimental groups. No live compatibility
or Registry publication is claimed. See the root README for current release status.

Use Terraform 1.11+ and an administrator with complete inventory visibility.
Inject `ALGOSEC_URL` (HTTPS origin) and either `ALGOSEC_SESSION_ID` or both
`ALGOSEC_USERNAME` / `ALGOSEC_PASSWORD` using your approved secret manager's process
environment. Never put credentials in HCL, shell history, output logs or committed
files. Do not set both authentication modes. Login may create an authentication
session, but `read_only = true` prohibits administration mutations.

Trust the appliance CA through the operating system trust store. On supported Go
Unix platforms, `SSL_CERT_FILE` / `SSL_CERT_DIR` can select your CA bundle/directory.
Keep hostname verification valid and `insecure = false`; do not bypass TLS to make
the test pass. The provider has no custom CA-file attribute.

After the maintainer confirms Registry availability, or after configuring the
[filesystem mirror](../../docs/user-testing.md), copy this directory into a private
working directory, then run:

```sh
terraform init
terraform validate
terraform plan -input=false
```

`init` installs the plugin; `validate` checks configuration. **Plan reads the live
appliance**, even with `-refresh=false` for data sources. Run it only against your
authorized test system. Counts are the only declared outputs, but plans/state can
contain inventory names and addresses. Protect the working directory and backend
with access controls/encryption; exclude `.terraform`, state and plan files from
source control. Avoid `TF_LOG` and raw JSON output in shared logs. Read-only use
does not need apply; apply would persist inventory into state.

Category tests require administrator preparation of the Panorama override file.
For explicit disposable mutation, import, replacement and destroy instructions and
limitations, see [user testing](../../docs/user-testing.md). Keep that separate from
this read-only configuration.
