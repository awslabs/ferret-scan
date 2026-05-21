# Terraform stack for the lambda-redact gateway

Single-tenant, IAM-authenticated AWS infrastructure for the
ferret-scan redaction gateway. Provisions the Lambda function,
execution role, log groups, API Gateway HTTP API, throttling, and
access logging — sized as an **internal-experimental** baseline.

## Prerequisites

- Terraform ≥ 1.5
- AWS provider ~> 5.0 (auto-installed by `terraform init`)
- AWS credentials with permission to create the resources listed
  below
- The Lambda zip artifact built by `make -C examples/lambda-redact build`

## Quick start

```bash
# From the repo root.
make -C examples/lambda-redact build

cd examples/lambda-redact/terraform
cp terraform.tfvars.example terraform.tfvars   # optional; defaults are sensible
terraform init
terraform plan                                  # always plan before apply
terraform apply

# Verify it works end-to-end.
INVOKE_URL=$(terraform output -raw invoke_url) make -C ../ smoke

# Tear down when done.
terraform destroy
```

The Quick Start uses a **local state file** by default (`terraform.tfstate`
in this directory). For shared/team deployments configure an S3 +
DynamoDB backend separately; this example doesn't ship one because
the right backend choice is operator-specific.

## What gets created

| Resource | Notes |
| --- | --- |
| `aws_lambda_function` | `provided.al2023`, arm64, 512 MB / 10 s, **unreserved concurrency** |
| `aws_iam_role` + policy | Log-write only, no wildcards |
| `aws_cloudwatch_log_group` (function) | 30-day retention |
| `aws_cloudwatch_log_group` (access) | 30-day retention, body-redacting format |
| `aws_kms_key` + alias | **Optional** — only when `use_customer_managed_kms_key=true` |
| `aws_apigatewayv2_api` | HTTP API |
| `aws_apigatewayv2_route` | `POST /v1/redact`, `AuthorizationType=AWS_IAM` |
| `aws_apigatewayv2_integration` | AWS_PROXY into the Lambda |
| `aws_apigatewayv2_stage` (`$default`) | Throttle burst=20, rate=10 RPS |
| `aws_lambda_permission` | Lets API Gateway invoke the function |

## Security defaults pinned in the IaC

These choices live in `main.tf` and `variables.tf` rather than the
README so they survive copy/paste. Reviewers can grep the .tf files
to verify each property holds.

- **`AuthorizationType = AWS_IAM`** at the route level. There is no
  `AuthorizationType = NONE` route in this stack. Callers must
  SigV4-sign requests with credentials that have
  `execute-api:Invoke` on the route ARN. The `caller_invoke_policy_doc`
  output emits a ready-to-attach policy.

- **TLS 1.2 minimum** on the API Gateway endpoint (HTTP API's
  default policy).

- **Lambda execution role** has only `logs:CreateLogStream` and
  `logs:PutLogEvents` on its own log group ARN. No wildcards in
  `Action` or `Resource`. `kms:Decrypt` is added only when the CMK
  toggle is on.

- **Confused-deputy defense on the Lambda execution role**: the
  trust policy includes a `StringEquals: aws:SourceAccount` condition
  pinning role-assumption to this account only. Without it, any
  Lambda service principal in any account could in principle assume
  the role; the condition makes the role unusable to a different
  account's Lambda even if the role ARN leaked.

- **`kms:ViaService` condition on the CMK decrypt grant**: when the
  CMK toggle is on, the role's `kms:Decrypt`/`GenerateDataKey` grant
  is conditional on `kms:ViaService = logs.<region>.amazonaws.com`.
  The function never calls KMS directly — its only legitimate use
  of the CMK is via `logs:PutLogEvents`, so pinning the via-service
  forecloses any theoretical misuse of the role with this key
  against a different KMS-integrated service.

- **Lambda invoke permission scoped to the exact route**: the
  `aws_lambda_permission.apigw_invoke` source ARN is
  `<execution_arn>/*/POST/v1/redact`, not the more permissive
  `<execution_arn>/*/*`. A future change that adds a second route
  to this API requires an explicit new `aws_lambda_permission`
  resource — the wildcard form would have silently granted invoke
  rights to any new route added later.

- **X-Ray tracing in PassThrough mode**: traces only when the
  upstream caller propagates a trace header. PassThrough vs Active
  is deliberate — Active mode produces trace segments for ALL
  invocations, which can carry metadata (function name, errors)
  that PassThrough avoids when no caller is asking for tracing.

  Empirically verified: with API Gateway HTTP API v2 (which has no
  native tracing toggle, unlike REST API) plus the function in
  PassThrough mode, **zero trace segments are emitted regardless
  of whether the caller passes an X-Amzn-Trace-Id header** — API
  Gateway HTTP API does not propagate the header to the Lambda
  invocation envelope without explicit instrumentation. The
  no-trace-no-leak property is structural in this stack, not just
  a defensive default. Switch the function to Active mode (and
  switch to REST API) only if you need traces and have audited
  what segment fields would carry payload-derived metadata.

- **Log retention pinned** to 30 days. CloudWatch's default is
  "never expire" — silent cost grower, never the right choice
  for a service this small.

- **Access log format pinned** to a body-redacting shape. Logs the
  source IP, request ID, IAM principal, route, status, latency,
  and user agent — enough for incident response. Does NOT log
  `$context.requestBody` or `$context.responseBody`. Future
  contributors who "improve" the format must consider whether any
  added field could carry payload bytes.

- **API Gateway throttling** pinned at burst=20, rate=10 RPS. This
  is the DoS-bounding control. Reserved Lambda concurrency is left
  unset (uses the account pool) because reserved concurrency is a
  capacity reservation, not a safety control.

- **No CORS configuration**: deliberate. The gateway is service-
  to-service (IAM auth via SigV4), not browser-callable. Adding
  CORS would imply a public, browser-facing surface that this
  stack is not designed for. The browser's same-origin policy
  implicitly blocks cross-origin requests until CORS is configured,
  so the absence is itself a control.

- **CMK encryption context covers BOTH log groups** when enabled.
  The function log group and the access log group both have to
  match the encryption context condition; an earlier version
  pinned only the function log group ARN, which would have left
  access log writes silently failing.

## Authorization model — what AWS_IAM on HTTP API v2 actually grants

HTTP API v2 with `AuthorizationType = AWS_IAM` is **identity-based
authorization only**. The security boundary is "any AWS principal,
in any account, with `execute-api:Invoke` on the route ARN." There
is no resource-policy layer on the gateway to constrain which
accounts can call.

This is a structural limitation of HTTP API v2:
[AWS documentation explicitly states](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control-iam.html)
"Resource policies aren't currently supported for HTTP APIs." Adding
a `var.allowed_caller_principals` knob would be cosmetic — Terraform
would accept it and silently drop it, because the
`aws_apigatewayv2_api` resource has no `policy` argument.

Practical implications:

- **For the default single-tenant case** (you control all callers):
  the security boundary is whoever you grant the
  `caller_invoke_policy_doc` policy to. Treat that policy
  attachment as the access-control surface.

- **For cross-account callers**: the caller's account simply
  attaches the policy from `caller_invoke_policy_doc` to its own
  principal. The gateway side requires zero changes — HTTP API v2
  accepts SigV4-signed requests from any account whose principal
  has the right IAM permission.

- **If you require same-account-only enforcement** (e.g. compliance
  or threat-model reasons): HTTP API v2 cannot give you that. Two
  paths forward:
    1. **Switch to API Gateway REST API**. Supports resource
       policies with `aws:PrincipalAccount` conditions. Roughly
       70% more expensive per request, supports more advanced
       features (usage plans, request validation). The trade-off
       this stack made was cost over those features for v1.
    2. **Add a Lambda authorizer** that inspects
       `event.requestContext.identity.accountId` and rejects
       requests from foreign accounts. Adds one more Lambda
       invocation per request and removes API Gateway's native
       caching — measurable latency cost.

  Either path is a non-trivial rework, not a knob flip. Document
  the decision in your environment's threat model before flipping.

## Cross-account use

Calling this gateway from a principal in a different AWS account
is supported with no gateway-side changes — only IAM permissions on
the caller's side. To wire it up:

```bash
# In the GATEWAY account, capture the policy:
terraform output -raw caller_invoke_policy_doc > /tmp/policy.json

# In the CALLER account, attach the policy to the calling principal:
aws iam put-role-policy \
  --profile caller-account-profile \
  --role-name MyCallerRole \
  --policy-name InvokeFerretRedactGw \
  --policy-document file:///tmp/policy.json

# Test from the caller account (assume the role first if needed).
awscurl --service execute-api --region us-east-1 \
  -X POST $(terraform -chdir=path/to/gw output -raw invoke_url) \
  -d '{"text":"test"}'
```

Failure mode if step 2 is skipped: caller gets a 403 from the IAM
evaluation. The 403 surfaces in CloudWatch access logs with
`status=403` and the caller's userArn intact — operators triaging
the 403 should look at the access log to identify the exact
principal, then verify whether the policy attachment is missing on
the caller side.

## Intentional v1 omissions

These are documented separately so a security reviewer can map them
to your environment's risk model:

- **No VPC attachment**: Lambda runs in AWS-managed network. For
  data-sensitive workloads where compliance requires customer-
  controlled networking, attach the function to a VPC subnet with
  appropriate security groups. Adds 0.5–1s cold start cost.

- **No CloudWatch alarms** for error rate, throttling, or latency
  spikes. The `billing_alarm_setup_doc` output documents one cost
  alarm; operational alarms are a v2 concern with a per-service
  threshold conversation.

- **No CloudTrail data events** on the API. Management-plane
  events (CreateFunction, UpdatePolicy, etc.) are captured by
  default account-wide CloudTrail; data-plane events
  (`execute-api:Invoke` calls) are NOT enabled by default and
  would need a separate trail to audit individual invocations.
  v2 concern.

- **No private endpoint**: the API Gateway URL is reachable from
  the public internet. IAM auth blocks unauthenticated traffic,
  but the endpoint itself is publicly resolvable. For air-gapped
  workloads, switch to API Gateway's `PRIVATE` endpoint type and
  attach a VPC endpoint policy.

- **No backup / DR plan**: the stack is fully reproducible from
  source (Terraform + Lambda zip), so the DR story is "redeploy."
  No state to back up.

## Cost surface

This stack ships with deliberate cost trade-offs. Two facts a
consumer needs to see before `terraform apply`:

1. **Lambda is unreserved by default**: a runaway caller could
   scale to your account concurrency limit (typically 1000 in a
   new account). API Gateway throttling (burst=20, rate=10) is the
   primary protection. At a sustained 10 RPS for a full month,
   compute + API requests run roughly $80/month — see the
   `cost_at_throttle_ceiling` output for the live calculation
   based on your current `var.throttling_rate_limit`.

2. **Access logs are enabled by default for incident response**.
   CloudWatch Logs ingest is billed per GB; a runaway caller
   produces log volume proportional to traffic. The body-redacting
   format keeps each log line at ~200 bytes, so 1M requests = ~200
   MB ≈ $0.10 in ingest charges — small relative to compute, but
   non-zero.

The `estimated_monthly_cost_floor` output documents these in
detail with INCLUDED/EXCLUDED categories.

## Outputs

```bash
terraform output -raw invoke_url                  # gateway URL
terraform output -raw caller_invoke_policy_doc    # IAM policy for callers
terraform output -raw example_curl_invocation     # ready-to-paste awscurl
terraform output -raw make_smoke_invocation       # ready-to-paste make smoke
terraform output -raw billing_alarm_setup_doc     # CLI to set up cost alarm
terraform output     estimated_monthly_cost_floor # cost-floor docstring
```

The onboarding outputs save every consumer the same 5-minute IAM
puzzle and curl construction. They are intentionally part of this
stack rather than the README because they include real ARNs and
URLs that only exist after `apply`.

## Testing the deployed gateway

After `terraform apply`, you have a live gateway. This section
covers everything from "I have credentials" to "I'm running smoke
tests in CI" with copy-pasteable commands.

### 1. AWS credentials and region

The gateway uses IAM auth: every request must be SigV4-signed with
credentials that include `execute-api:Invoke` on the route ARN. How
those credentials get picked up depends on where you're calling
from.

**From a developer machine with a named AWS profile:**

```bash
# Pick up credentials from ~/.aws/credentials or credential_process.
export AWS_PROFILE=my-profile
export AWS_REGION=us-east-1   # match the deployment region

# Verify auth works before running tests.
aws sts get-caller-identity
```

If the call returns "session expired" or similar, refresh first
(`aws sso login --profile my-profile`, `aws login`, or whatever
your org's auth tooling uses). The gateway tests below all assume
valid credentials are in scope; they don't refresh on your behalf.

**From an EC2 instance, ECS task, or another Lambda:**

The instance/task/function role provides credentials automatically.
You don't need `AWS_PROFILE`. Make sure the role has the IAM policy
emitted by `terraform output -raw caller_invoke_policy_doc`
attached.

**From CI:**

GitHub Actions: use `aws-actions/configure-aws-credentials` with
OIDC (preferred) or short-lived access keys. GitLab: the same
SigV4 signing applies via OIDC role assumption. The gateway has
no opinion on how you got the credentials, only that they're
SigV4-signable for `execute-api:Invoke` on the route ARN.

### 2. Granting `execute-api:Invoke` to your caller

The principal you call from needs the policy:

```bash
# Capture the IAM policy this stack expects callers to have.
terraform output -raw caller_invoke_policy_doc

# Attach it to a role (replace MyCallerRole with your principal):
terraform output -raw caller_invoke_policy_doc \
  | aws iam put-role-policy \
      --role-name MyCallerRole \
      --policy-name InvokeFerretRedactGw \
      --policy-document file:///dev/stdin
```

If you're calling from the SAME principal that ran `terraform apply`
(e.g. you're an Admin in a sandbox account), no extra policy is
needed — Admin already has `execute-api:Invoke`.

### 3. Quickest test: `make smoke`

The repo's Makefile target asserts redaction is actually happening,
not just that the network round-trip works. Four real assertions:

```bash
INVOKE_URL=$(terraform -chdir=. output -raw invoke_url) \
  AWS_REGION=us-east-1 \
  make -C .. smoke

# Output: smoke: ok
```

Or use the ready-to-paste invocation Terraform renders for you:

```bash
$(terraform output -raw make_smoke_invocation)
```

The smoke target requires `awscurl` and `jq`. To install:

```bash
# awscurl: SigV4-signing curl wrapper (https://github.com/okigan/awscurl).
pip install awscurl                # if you have system pip
uv tool install awscurl            # if you use uv (no system pip needed)

# jq: usually already present.
brew install jq                    # macOS
apt-get install jq                 # Debian/Ubuntu
```

`make smoke` honors `AWS_PROFILE` and `AWS_REGION` from the
environment, so the same export commands above work.

### 4. Manual single requests

For ad-hoc testing during development, the `example_curl_invocation`
output gives you a ready-to-paste command:

```bash
$(terraform output -raw example_curl_invocation)

# Resolves to:
# awscurl --service execute-api --region us-east-1 \
#   -X POST https://abc123.execute-api.us-east-1.amazonaws.com/v1/redact \
#   -d '{"text":"card 5500-0000-0000-0004 from alice@example.com",...}'
```

### 5. Testing without `awscurl` (using `curl --aws-sigv4`)

If you'd rather not install another tool, recent versions of `curl`
(7.75+) support SigV4 natively:

```bash
# Export credentials in env-var format (the AWS CLI helper does this
# in one shot, including session token for STS-based credentials).
eval "$(aws configure export-credentials --format env)"

curl --aws-sigv4 'aws:amz:us-east-1:execute-api' \
     --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
     -H "x-amz-security-token: $AWS_SESSION_TOKEN" \
     -H 'Content-Type: application/json' \
     -X POST "$(terraform output -raw invoke_url)" \
     -d '{"text":"card 5500-0000-0000-0004","strategy":"format_preserving"}'
```

Notes:

- `aws configure export-credentials --format env` is the modern way
  to get current credentials into env vars, including the session
  token. Older docs use `aws sts get-session-token`; that path
  doesn't work with role-assumption flows.
- The `x-amz-security-token` header is required only if your
  credentials came from STS (assumed roles, SSO, Isengard) — empty
  is fine for permanent IAM users, which is the rare case.
- Add `-i` to see HTTP headers (status code, request ID).
- Add `-w '%{http_code}\n' -o /tmp/body.json` to capture the
  status code separately from the body.

### 6. Testing each error path

The handler returns specific HTTP status codes by category. Verify
the wiring is correct end-to-end:

```bash
URL=$(terraform output -raw invoke_url)

# 200 — success
awscurl --service execute-api --region us-east-1 -X POST $URL \
  -d '{"text":"card 5500-0000-0000-0004","label":"t1"}'

# 200 — clean text passes through
awscurl --service execute-api --region us-east-1 -X POST $URL \
  -d '{"text":"hello world","label":"t2"}'

# 400 — invalid strategy (silent fallback would hide a typo)
awscurl --service execute-api --region us-east-1 -X POST $URL \
  -d '{"text":"x","strategy":"unknown","label":"t3"}'

# 400 — empty text
awscurl --service execute-api --region us-east-1 -X POST $URL \
  -d '{"text":"","label":"t4"}'

# 400 — malformed JSON body (not echoed; just a category string)
awscurl --service execute-api --region us-east-1 -X POST $URL \
  -d 'this is not json'

# 403 — unsigned request blocked by IAM auth
curl -X POST $URL -H 'Content-Type: application/json' \
     -d '{"text":"x"}'
```

To assert the exact HTTP status (not just inspect the body), see
the `curl --aws-sigv4` recipe in section 5.

### 7. Verifying audit logs land payload-free

After running tests, confirm the audit log carries only counts and
metadata, never the input or output bytes:

```bash
aws logs tail \
  $(terraform output -raw log_group_name) \
  --since 5m --format short \
  | grep audit
```

Each line should look like:

```text
2026-05-21T15:38:01 audit gateway_request_id=abc123 {"Label":"t7","FindingsByType":{"BUSINESS":1,"MASTERCARD":1},"SuppressedByType":{},"Strategy":1,"InputBytes":47,"RedactedBytes":47,...}
```

If you see anything resembling `req.Text` or `res.Redacted` in
the log, that's a bug — file an issue immediately.

**Operator-side log lines that DO contain caller-controlled text
(by design, single-tenant assumption):**

- `invalid_strategy gateway_request_id=... value="..."` — fires when
  a caller submits an unrecognized `strategy` value. The value is
  captured for operators to identify misconfigured clients. The
  wire response carries only the fixed-shape "invalid strategy
  (want simple|format_preserving|synthetic)" category, never the
  caller's value. **In a multi-tenant deployment**, where less-
  privileged users have read access to the function log group,
  remove the `value=%q` field from `handler.go` and rely on the
  access log's requestId for correlation — otherwise callers can
  exfiltrate data through the strategy field.

- `panic_recovered type=... gateway_request_id=...` — fires when
  the deferred recover catches a downstream panic. Records the
  panic's TYPE only, never its value (which can include input
  bytes for runtime panics like nil-deref).

- `audit_marshal_failed err=... request_id=... gateway_request_id=...` —
  fires only if json.Marshal of the audit record fails (an unreachable
  case in practice; logged so operators notice if a future change
  breaks it).

- `response_marshal_failed err=... gateway_request_id=...` — fires
  only if json.Marshal of the success response fails (also
  unreachable in practice).

None of these lines contain `req.Text` or `res.Redacted` bytes.

The access log group has a separate, body-redacting format:

```bash
aws logs tail \
  $(terraform output -raw access_log_group_name) \
  --since 5m --format short
```

Each line is space-separated metadata only:

```text
203.0.113.42 abc123= arn:aws:sts::ACCT:assumed-role/Role POST /v1/redact 200 28 200 12 curl/8.7.1
# sourceIp requestId userArn route status latency-ms integration-status integration-latency-ms userAgent
```

No request bodies, no response bodies, no error envelope details.

### 8. Cold start vs warm path latency

To measure cold start, force a fresh container by updating the
function (any change triggers a redeployment):

```bash
# Update the function to flush the warm pool.
aws lambda update-function-configuration \
  --function-name $(terraform output -raw function_name) \
  --description "force-cold-$(date +%s)"

# Wait for the update to finish (a few seconds) then invoke.
sleep 10
time awscurl --service execute-api --region us-east-1 -X POST \
  $(terraform output -raw invoke_url) \
  -d '{"text":"hello"}'

# Read the REPORT line for the actual init duration.
aws logs tail $(terraform output -raw log_group_name) --since 1m \
  | grep REPORT | tail -1
```

Expected: ~50–100 ms init duration, sub-2ms warm-path duration.

### 9. Common pitfalls

- **`make smoke` fails with "INVOKE_URL is not set"**: the URL
  variable is required and unset. Use `INVOKE_URL=$(terraform
  output -raw invoke_url)` from the `terraform/` directory.
- **403 Forbidden on signed requests**: your principal lacks
  `execute-api:Invoke` on the route ARN. Re-attach the policy
  from `terraform output -raw caller_invoke_policy_doc`.
- **"session expired" / "ExpiredTokenException"**: refresh
  credentials with your org's auth tool and retry.
- **`awscurl: command not found`**: install via `pip install
  awscurl` or `uv tool install awscurl`. `pip` requires Python
  3.7+ and may need `--user` or a virtualenv depending on your
  setup.
- **Region mismatch**: the `--region` flag in awscurl/curl MUST
  match the deployment region. SigV4 includes the region in the
  signature, so a mismatch is a 403.
- **Wrong credentials in scope**: if you have multiple AWS
  profiles, double-check `aws sts get-caller-identity` returns
  the principal you intend. The gateway has no way to tell you
  "you're calling as the wrong role" — it returns 403 and you
  have to figure out why.

## Customizing

Most knobs are in `variables.tf`. A few common scenarios:

```hcl
# Bump throttling for measured production load.
throttling_burst_limit = 100
throttling_rate_limit  = 50

# Cap concurrency to prevent account-pool exhaustion.
reserved_concurrent_executions = 50

# Compliance / regulated workload — enable CMK on logs.
use_customer_managed_kms_key = true
log_retention_days           = 365

# Restrict the validator surface for performance.
ferret_checks = "EMAIL,SSN,CREDIT_CARD"

# Single-tenant debug deployment — return per-type counts.
include_findings_in_response = true
```

## What this stack DOES NOT do

These are intentional v1 omissions. Each has a well-defined hook
in `variables.tf` if you need to extend.

- **WAF / CloudFront edge layer** — single-tenant, internal use
  doesn't benefit. Add WAF when exposing publicly.
- **Cognito user pool** — IAM auth is sufficient for service-to-service.
- **S3 async path for >6 MB payloads** — Lambda's sync invoke
  payload limit is 6 MB. Larger inputs need a separate path.
- **Custom domain + ACM certificate** — operator concern.
- **Multi-region active/active** — not needed for a v1 example.
- **Remote state backend** — operator concern; use S3 + DynamoDB
  for shared/team deployments.

## Destroying

```bash
terraform destroy
```

Removes everything. The CloudWatch log groups have a non-zero
retention window so any logs they contain remain queryable for
the configured retention period **before destroy**. After destroy,
the log groups are deleted and the logs go with them.
