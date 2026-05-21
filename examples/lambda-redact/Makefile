# Makefile for the lambda-redact example submodule.
#
# All paths are relative to this directory. Invoke from the repo root via:
#
#     make -C examples/lambda-redact <target>
#
# The Makefile lives next to the code it builds; this avoids `cd` inside
# targets (which breaks `make -j` and IDE integration) and matches the
# standard Go submodule convention.

# ---- Configuration ----

# Lambda runtime: provided.al2023 + arm64 is the cheapest, fastest cold
# start path for a Go binary. Don't switch to a container image without
# benchmarking — container cold starts are 2–4x slower for this workload.
GOOS    ?= linux
GOARCH  ?= arm64

# AWS region for `make smoke`. Falls back to `aws configure get region`,
# then to us-east-1, mirroring awscurl's own resolution order.
AWS_REGION ?= $(shell aws configure get region 2>/dev/null || echo us-east-1)

# INVOKE_URL is required by `make smoke` and supplied by `terraform output
# invoke_url` (see ../terraform/, shipped in PR 2). The smoke target
# fails loud rather than running against a placeholder.
INVOKE_URL ?=

# Test fixture for `make smoke`. A Luhn-valid Visa test card and a
# canary email; the smoke target asserts both are absent from the
# response and that the response shape matches the security-by-default
# contract.
SMOKE_INPUT  ?= card 4532-0151-1283-0366 from alice@example.com
SMOKE_CC     ?= 4532-0151-1283-0366
SMOKE_EMAIL  ?= alice@example.com

.PHONY: build clean test vet smoke help

help:
	@echo "Targets:"
	@echo "  build   Cross-compile bootstrap binary for $(GOOS)/$(GOARCH) and zip it"
	@echo "  test    Run go test ./..."
	@echo "  vet     Run go vet ./..."
	@echo "  smoke   Hit the deployed gateway and verify redaction (requires INVOKE_URL)"
	@echo "  clean   Remove build artifacts"
	@echo ""
	@echo "Variables (override on the command line):"
	@echo "  GOOS=$(GOOS) GOARCH=$(GOARCH)"
	@echo "  AWS_REGION=$(AWS_REGION)"
	@echo "  INVOKE_URL=$(INVOKE_URL)"

# ---- Build ----

# Cross-compile a Go binary for the Lambda provided.al2023 runtime.
# - lambda.norpc tag drops the legacy RPC entry point (we use the
#   default lambda.Start path), shaving ~500 KB off the binary.
# - -ldflags='-s -w' strips the symbol table and DWARF, another ~30%.
# - -trimpath removes filesystem paths from the binary, making builds
#   reproducible across machines.
build: bootstrap function.zip
	@echo "build: produced $(PWD)/function.zip"

bootstrap: $(shell find . -name '*.go' -not -name '*_test.go') go.mod go.sum
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-tags lambda.norpc \
		-ldflags='-s -w' \
		-trimpath \
		-o bootstrap ./

function.zip: bootstrap
	zip -q function.zip bootstrap

# ---- Test ----

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

# ---- Smoke ----
#
# `make smoke` exercises a deployed gateway end-to-end. It is intentionally
# strict: a successful HTTP 200 with the wrong response shape, or with the
# original CC bytes leaking through, is a failure. A successful smoke run
# asserts:
#
#   1. The request returns a parseable JSON response with a `redacted` field.
#   2. The original CC bytes do NOT appear in the redacted output.
#   3. The original email bytes do NOT appear in the redacted output.
#   4. By default, `findings_by_type` is absent (the side-channel guard).
#
# Requires: awscurl (pip install awscurl), jq, and the function deployed
# via the terraform/ stack from PR 2. INVOKE_URL must be supplied.
smoke:
	@if [ -z "$(INVOKE_URL)" ]; then \
		echo "make smoke: INVOKE_URL is not set."; \
		echo ""; \
		echo "  This target requires a deployed gateway. PR 1 of the lambda-redact"; \
		echo "  work ships the handler and tests; the terraform/ stack that produces"; \
		echo "  an invoke URL is in PR 2. To run smoke after deploying:"; \
		echo ""; \
		echo "    INVOKE_URL=\$$(terraform -chdir=terraform output -raw invoke_url) \\"; \
		echo "      make -C examples/lambda-redact smoke"; \
		echo ""; \
		exit 1; \
	fi
	@command -v awscurl >/dev/null 2>&1 || { \
		echo "make smoke: awscurl not found. Install with: pip install awscurl"; exit 1; \
	}
	@command -v jq >/dev/null 2>&1 || { \
		echo "make smoke: jq not found. Install via your package manager."; exit 1; \
	}
	@echo "smoke: POST $(INVOKE_URL)/v1/redact (region=$(AWS_REGION))"
	@response=$$(awscurl --service execute-api --region $(AWS_REGION) \
		-X POST $(INVOKE_URL)/v1/redact \
		-d '{"text":"$(SMOKE_INPUT)","label":"smoke-test"}' 2>/dev/null); \
	if [ -z "$$response" ]; then \
		echo "smoke: empty response from gateway"; exit 1; \
	fi; \
	echo "$$response" | jq -e '.redacted' > /dev/null \
		|| { echo "smoke: response missing 'redacted' field: $$response"; exit 1; }; \
	echo "$$response" | jq -e '.redacted | contains("$(SMOKE_CC)")' > /dev/null \
		&& { echo "smoke: CC bytes leaked through redactor: $$response"; exit 1; } || true; \
	echo "$$response" | jq -e '.redacted | contains("$(SMOKE_EMAIL)")' > /dev/null \
		&& { echo "smoke: email bytes leaked through redactor: $$response"; exit 1; } || true; \
	echo "$$response" | jq -e 'has("findings_by_type")' > /dev/null \
		&& { echo "smoke: findings_by_type leaked into default response (side-channel guard regression): $$response"; exit 1; } || true; \
	echo "smoke: ok"

# ---- Clean ----

clean:
	rm -f bootstrap function.zip
