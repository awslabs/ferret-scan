# Lambda redact handler example

A reference implementation of an AWS Lambda redaction gateway built on
[`pkg/redact`](../../pkg/redact). The handler accepts a JSON request,
runs scan + redaction in-process (no subprocess, no filesystem), and
returns redacted text plus a payload-free audit record.

This directory is its own Go module. The AWS Lambda runtime dependency
(`github.com/aws/aws-lambda-go`) lives in this submodule's `go.mod`
only — the parent `ferret-scan` module stays free of any AWS SDK
imports, which means the CLI builds and the minimal scratch Dockerfile
in the repo root remain unaffected by this example.

## Quick start

```bash
# From the repo root.
make -C examples/lambda-redact build      # produces bootstrap + function.zip
make -C examples/lambda-redact test       # unit tests for the handler logic
make -C examples/lambda-redact vet
```

The `terraform/` directory in this submodule provisions the supporting
AWS infrastructure (Lambda function, IAM role, CloudWatch log groups,
API Gateway HTTP API with IAM auth + throttling, body-redacting access
log format) as a single-tenant, internal-experimental baseline. See
[terraform/README.md](terraform/README.md) for `terraform apply` walkthrough
and security defaults pinned in the IaC.

## Local invocation

Without the Lambda runtime, the handler accepts a single request via
argv when `FERRET_LOCAL=1` is set. Useful for debugging the handler
shape without spinning up infrastructure:

```bash
make -C examples/lambda-redact build
FERRET_LOCAL=1 ./examples/lambda-redact/bootstrap \
  'card 5500-0000-0000-0004 from alice@example.com'
```

Output is the same JSON the handler would return on a real Lambda
invocation:

```json
{
  "redacted": "card 5500-****-****-0004 from a****@example.com",
  "request_id": "local-test",
  "duration_ms": 2
}
```

## Build / deploy

The recommended path is the [terraform/](terraform/) stack:

```bash
make -C examples/lambda-redact build
cd examples/lambda-redact/terraform
cp terraform.tfvars.example terraform.tfvars   # optional
terraform init
terraform apply
```

After `apply`:

```bash
# Smoke-test end-to-end (asserts redaction is actually happening).
INVOKE_URL=$(terraform output -raw invoke_url) make -C .. smoke

# Get a ready-to-paste awscurl command.
terraform output -raw example_curl_invocation

# Get the IAM policy a caller needs to invoke the gateway.
terraform output -raw caller_invoke_policy_doc
```

### Manual deploy without Terraform

For a one-off test or a different infrastructure stack:

```bash
make -C examples/lambda-redact build
# Produces bootstrap (the binary) and function.zip (the Lambda artifact).

aws lambda create-function \
  --function-name redact-gateway \
  --runtime provided.al2023 \
  --architectures arm64 \
  --handler bootstrap \
  --zip-file fileb://examples/lambda-redact/function.zip \
  --role arn:aws:iam::ACCOUNT:role/lambda-redact-role \
  --memory-size 512 --timeout 10
```

The IAM role above needs `logs:CreateLogStream` and `logs:PutLogEvents`
on its own log group only. No other permissions. The `terraform/` stack
provisions that role explicitly with no wildcards.

## API

```http
POST /v1/redact
Content-Type: application/json

{
  "text": "card 5500-0000-0000-0004 from alice@example.com",
  "strategy": "format_preserving",
  "label": "req-abc-123"
}
```

```http
200 OK
Content-Type: application/json

{
  "redacted": "card 5500-****-****-0004 from a****@example.com",
  "request_id": "req-abc-123",
  "duration_ms": 12
}
```

`strategy` is one of: `simple`, `format_preserving` (default), `synthetic`.

### Returning finding counts on the wire

By default the response does **not** include per-type finding counts.
The full counts are always logged via the audit record, but they are
not echoed back to the caller. This is intentional: in a multi-tenant
gateway the per-type counts constitute a soft side-channel ("tenant X
consistently submits PASSPORT data") even though no payload bytes are
exposed.

For single-tenant or debug deployments where the caller already knows
what they sent, set `FERRET_INCLUDE_FINDINGS=true` to enable the
`findings_by_type` field in the response. Example response with the
flag enabled:

```json
{
  "redacted": "card 5500-****-****-0004 from a****@example.com",
  "findings_by_type": {"MASTERCARD": 1, "EMAIL": 1},
  "request_id": "req-abc-123",
  "duration_ms": 12
}
```

The side-channel guard is pinned by `TestBuildResponse_OmitsFindingsByDefault`
in `handler_test.go` so a regression here fails CI rather than shipping.

### Configuration env vars

| Variable | Default | Effect |
|---|---|---|
| `FERRET_CHECKS` | `all` | Comma-separated validator IDs (e.g. `EMAIL,SSN`) |
| `FERRET_STRATEGY` | `format_preserving` | Default redaction strategy |
| `FERRET_INCLUDE_FINDINGS` | `false` | Echo per-type counts in the response |
| `FERRET_LOCAL` | unset | When `1`, run a single argv invocation instead of `lambda.Start` |

## Architecture notes

- **One redact.Engine per execution environment**: the handler builds the
  `redact.Engine` in `init()` and reuses it for every invocation.
  Per-request setup cost is zero. With provisioned concurrency, the
  construction cost is paid during init phase rather than on the
  user's critical path.

- **No suppression file loaded by default**: per the public API
  contract, suppressions are passed per-request via
  `Request.AllowSuppressions`. The example doesn't pass any — a
  multi-tenant gateway should not.

- **Audit logging via `Result.AuditRecord()`**: the handler writes the
  audit record via `log.Printf` — in a Lambda deployment that lands in
  the function's log stream. The record carries no payload bytes, no
  offsets, and no matched substrings, so it is safe to ship to
  long-retention or WORM-style audit sinks (S3 with Object Lock, etc.)
  without leaking inputs.

- **Errors are sanitized**: the handler never returns the raw input or
  matched substring in error responses. A request ID is included for
  correlation.

- **No payload logging**: the handler does NOT log `req.Text` or
  `res.Redacted`. The only thing that hits the function's log stream
  is the audit record (counts + metadata). Never log PII.

- **Pure `buildResponse` function**: the side-channel guard
  (`includeFindings=false` elides `FindingsByType`) is implemented as
  a pure function, not via package-level mutable state. Security
  reviewers can verify the entire decision in three lines of code,
  and unit tests can exercise both the include-findings and
  omit-findings code paths without process-level setup.

## Smoke testing the deployed gateway

`make smoke` exercises a deployed gateway end-to-end:

```bash
# Set credentials in scope first (the gateway uses IAM auth).
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1

INVOKE_URL=$(terraform -chdir=examples/lambda-redact/terraform output -raw invoke_url) \
  make -C examples/lambda-redact smoke
```

Or use the ready-to-paste invocation rendered by Terraform:

```bash
$(terraform -chdir=examples/lambda-redact/terraform output -raw make_smoke_invocation)
```

Prerequisites: `awscurl` (`pip install awscurl` or `uv tool install
awscurl`) and `jq`. Full credential / region / error-path
documentation in [terraform/README.md § Testing the deployed gateway](terraform/README.md#testing-the-deployed-gateway).

The smoke target asserts:

1. The request returns a parseable JSON response with a `redacted` field.
2. The original CC bytes do NOT appear in the redacted output.
3. The original email bytes do NOT appear in the redacted output.
4. By default, `findings_by_type` is absent from the response.

A smoke run that succeeds at the network level but fails any of these
assertions exits non-zero. Without the assertions, "smoke" would
verify the network works — which `curl` does for free. The assertions
are what make this a *redaction* smoke test rather than a network one.

## Customizing for your own deployment

Copy this directory into your own module and customize:

```bash
mkdir my-redact-gateway && cd my-redact-gateway
cp /path/to/ferret-scan/examples/lambda-redact/* .
go mod init my-redact-gateway
go get github.com/aws/aws-lambda-go@latest
go get github.com/awslabs/ferret-scan@latest
# Drop the `replace` directive at the bottom of go.mod — it's only
# there to keep the example buildable from a fresh monorepo clone.
```

## What this example deliberately does NOT cover

- **Authentication / authorization**: API Gateway IAM auth, Cognito JWT,
  or a Lambda authorizer all go in front of this handler. Never deploy
  with `AuthorizationType.NONE`.
- **Throttling / rate limiting**: configure via API Gateway stage
  throttle + Lambda reserved concurrency. WAF for source-IP rate rules.
- **CloudFront / WAF**: optional edge layer, recommended for
  internet-facing deployments.
- **S3 async path for >6 MB payloads**: Lambda's sync invocation
  payload limit is 6 MB. Larger payloads need an S3 → Lambda fan-out.

These are infrastructure concerns owned by the consumer's CDK / Terraform.
The `terraform/` stack in this submodule provides a sane v1 baseline
(single-tenant, IAM auth, throttling pinned, no WAF/CloudFront).
