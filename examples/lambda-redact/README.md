# Lambda redact handler example

A reference implementation of an AWS Lambda redaction gateway built on
`pkg/redact`. The handler accepts a JSON request, runs scan + redaction
in-process (no subprocess, no filesystem), and returns redacted text
plus a payload-free audit record.

## Why a separate example

`pkg/redact` is the library. The handler that wires it up to a specific
runtime (Lambda, gRPC, HTTP) belongs in a consumer repo so the main
ferret-scan module stays free of runtime-specific dependencies (no
`aws-lambda-go`, no `gorilla/mux`, etc.).

This directory provides the canonical handler skeleton so every consumer
starts from the same shape rather than reverse-engineering it from the
docstrings.

## Build / deploy

This example uses a `//go:build examples_lambda` build tag so it
doesn't pollute the main module's build. To turn it into a deployable
Lambda function:

1. Copy `handler.go` into a new module:
   ```bash
   mkdir my-redact-gateway && cd my-redact-gateway
   go mod init my-redact-gateway
   cp /path/to/ferret-scan/examples/lambda-redact/handler.go .
   ```

2. Remove the `//go:build examples_lambda` tag at the top of the file.

3. Add the AWS Lambda runtime dependency:
   ```bash
   go get github.com/aws/aws-lambda-go@latest
   go get github.com/awslabs/ferret-scan/v2@latest
   ```

4. Uncomment the `lambda.Start(handle)` line at the bottom of `main()`
   (and the `aws-lambda-go/lambda` import).

5. Build for Lambda's `provided.al2023` runtime, arm64:
   ```bash
   GOOS=linux GOARCH=arm64 go build -tags lambda.norpc \
     -ldflags='-s -w' -o bootstrap ./
   zip function.zip bootstrap
   ```

6. Deploy:
   ```bash
   aws lambda create-function \
     --function-name redact-gateway \
     --runtime provided.al2023 \
     --architectures arm64 \
     --handler bootstrap \
     --zip-file fileb://function.zip \
     --role arn:aws:iam::ACCOUNT:role/lambda-redact-role \
     --memory-size 256 --timeout 10
   ```

## Architecture notes

- **One Engine per execution environment**: the handler builds the
  `redact.Engine` in `init()` and reuses it for every invocation.
  Per-request setup cost is zero.

- **No suppression file loaded by default**: per the public API
  contract, suppressions are passed per-request via
  `Request.AllowSuppressions`. The example doesn't pass any — a
  multi-tenant gateway should not.

- **Audit logging via `Result.AuditRecord()`**: the handler writes the
  audit record via `log.Printf` — in a Lambda deployment that lands in
  the function's CloudWatch log stream. The record carries no payload
  bytes, no offsets, and no matched substrings, so it is safe to ship
  to long-retention or WORM-style audit sinks (S3 with Object Lock,
  etc.) without leaking inputs.

- **Errors are sanitized**: the handler never returns the raw input or
  matched substring in error responses. A request ID is included
  for correlation.

- **No payload logging**: the handler does NOT log `req.Text` or
  `res.Redacted`. The only thing that hits the function's log stream is
  the audit record (counts + metadata). Never log PII.

## API

```http
POST /redact
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
The full counts are always logged to CloudWatch via the audit record,
but they are not echoed back to the caller. This is intentional: in a
multi-tenant gateway the per-type counts constitute a soft side-channel
("tenant X consistently submits PASSPORT data") even though no payload
bytes are exposed.

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

### Configuration env vars

| Variable | Default | Effect |
|---|---|---|
| `FERRET_CHECKS` | `all` | Comma-separated validator IDs (e.g. `EMAIL,SSN`). Case-sensitive; an unrecognized name (typo) fails the `init()` rather than silently disabling that validator. Valid IDs come from `redact.ValidCheckNames()`. |
| `FERRET_STRATEGY` | `format_preserving` | Default redaction strategy |
| `FERRET_INCLUDE_FINDINGS` | `false` | Echo per-type counts in the response |

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
