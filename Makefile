GO ?= go
TERRAFORM ?= terraform
GORELEASER ?= goreleaser
ACTIONLINT_VERSION := v1.7.12
GOVULNCHECK_VERSION := v1.8.0

.PHONY: build test test-unit vet vuln fmt fmt-check generate docs-check smoke release-check testacc-read testacc-mutation actionlint

build:
	$(GO) build -trimpath -o bin/terraform-provider-algosec .

test:
	@command -v $(TERRAFORM) >/dev/null
	TF_ACC=0 TF_ACC_TERRAFORM_PATH="$$(command -v $(TERRAFORM))" $(GO) test -race -cover -timeout=10m ./...

test-unit:
	TF_ACC=0 $(GO) test -race -timeout=5m ./...

vet:
	$(GO) vet ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
	cd tools && $(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

fmt:
	gofmt -w main.go internal tools
	$(TERRAFORM) fmt -recursive examples

fmt-check:
	@test -z "$$(gofmt -l main.go internal tools)"
	$(TERRAFORM) fmt -check -recursive examples

generate:
	cd tools && $(GO) run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name algosec --provider-dir ..

docs-check:
	python3 scripts/docs_check.py

smoke: build
	TERRAFORM=$(TERRAFORM) python3 scripts/smoke.py

actionlint:
	$(GO) run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

release-check: coverage-check package-smoke fmt-check test vet vuln docs-check smoke actionlint
	$(GO) mod verify
	$(GORELEASER) check

# These targets are intentionally separate from offline/synthetic verification.
testacc-read:
	TF_ACC=1 $(GO) test -v -timeout=30m ./internal/provider -run '^TestAcc.*ReadOnly$$'

testacc-mutation:
	@test "$$ALGOSEC_ACC_MUTATION" = 1
	@test "$$ALGOSEC_ACC_DISPOSABLE" = 1
	TF_ACC=1 $(GO) test -v -timeout=60m ./internal/provider -run '^TestAcc.*Mutation$$'

.PHONY: coverage-check package-smoke
coverage-check:
	python3 -B -m unittest discover -s scripts -p operation_inventory_test.py
	python3 scripts/coverage_check.py

package-smoke: build
	TERRAFORM=$(TERRAFORM) python3 scripts/package_smoke.py
