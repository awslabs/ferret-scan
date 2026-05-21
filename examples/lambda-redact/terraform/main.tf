# Lambda redact gateway — single-tenant, IAM-authenticated.
#
# Resource layout:
#
#   - Lambda function (zip, provided.al2023, arm64)
#   - Execution role + policy (log-write only, no wildcards)
#   - CloudWatch log group for the function (30-day retention)
#   - Optional: customer-managed KMS key for the log group
#   - HTTP API + POST /v1/redact route, AuthorizationType = AWS_IAM
#   - $default stage with throttling + access logging
#   - CloudWatch log group for API Gateway access logs (body-redacting format)
#   - Lambda permission for API Gateway to invoke
#
# What this stack DOES NOT do (intentionally, for v1):
#
#   - WAF / CloudFront edge layer — single-tenant, internal use
#   - Cognito user pool — IAM auth is sufficient for service-to-service
#   - S3 async path for >6 MB payloads — separate concern
#   - Custom domain + ACM certificate — operator concern
#   - Multi-region active/active — not needed for a v1 example
#
# These are all additive: variables.tf can grow without rewriting
# main.tf, and consumers can layer them on top of this baseline.

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Resolve access_log_retention_days: fall back to log_retention_days
  # when the operator didn't override it. Same retention is the right
  # default — there is no security reason to retain access logs longer
  # than function logs.
  access_log_retention = coalesce(var.access_log_retention_days, var.log_retention_days)
}

# ---------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = aws_iam_role.lambda.arn
  handler       = "bootstrap"

  # provided.al2023 + arm64 is the cheapest, fastest cold start path
  # for a Go binary on Lambda. Container images cold-start 2–4x slower
  # for this workload; do not switch without benchmarking.
  runtime       = "provided.al2023"
  architectures = ["arm64"]

  filename         = var.function_zip_path
  source_code_hash = filebase64sha256(var.function_zip_path)

  memory_size = var.memory_mb
  timeout     = var.timeout_seconds

  # Reserved concurrency: NULL means unreserved (uses account pool).
  # See variables.tf for the rationale — TL;DR reserved concurrency
  # is a capacity reservation, not a safety control. Throttling is
  # the DoS-bounding control.
  reserved_concurrent_executions = var.reserved_concurrent_executions

  # X-Ray in PassThrough mode: when API Gateway propagates an
  # X-Amzn-Trace-Id header (because the upstream caller initiated
  # tracing or API Gateway sampled this request), the Lambda
  # invocation participates in the trace. When no header is
  # propagated, no trace segments are produced. Cost: zero unless
  # someone upstream is already paying for tracing.
  #
  # PassThrough is preferred over Active for a single-tenant gateway:
  # Active mode samples 5% of requests by default and creates trace
  # segments for ALL invocations, including ones that may carry
  # sensitive metadata in segment annotations. PassThrough only
  # traces when explicitly requested by the caller, which keeps the
  # default behavior payload-free even at the trace layer.
  tracing_config {
    mode = "PassThrough"
  }

  environment {
    variables = {
      # Parsed by the handler's init() — see examples/lambda-redact/handler.go.
      FERRET_CHECKS           = var.ferret_checks
      FERRET_STRATEGY         = var.ferret_strategy
      FERRET_INCLUDE_FINDINGS = tostring(var.include_findings_in_response)
    }
  }

  # Explicit dependency on the log group so we don't lose the first
  # invocations to "log group not yet exists" errors. Without this,
  # Lambda creates the log group implicitly without our retention
  # policy or KMS key.
  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy_attachment.lambda_logs,
  ]
}

# ---------------------------------------------------------------------
# IAM execution role — log-write only
# ---------------------------------------------------------------------

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.function_name}-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  description        = "Execution role for ${var.function_name}; log-write only."
}

# Inline policy — log-write to ITS OWN log group only. No wildcard
# resources, no wildcard actions. Adding kms:Decrypt only when the
# CMK toggle is on, since the AWS-managed aws/logs key doesn't need
# an explicit grant on the function role.
data "aws_iam_policy_document" "lambda_logs" {
  statement {
    sid     = "WriteOwnLogs"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "${aws_cloudwatch_log_group.lambda.arn}:*",
    ]
  }

  dynamic "statement" {
    for_each = var.use_customer_managed_kms_key ? [1] : []
    content {
      sid     = "DecryptCMK"
      effect  = "Allow"
      actions = ["kms:Decrypt", "kms:GenerateDataKey"]
      resources = [
        aws_kms_key.logs[0].arn,
      ]
    }
  }
}

resource "aws_iam_policy" "lambda_logs" {
  name        = "${var.function_name}-logs"
  description = "Log-write to ${aws_cloudwatch_log_group.lambda.name} only."
  policy      = data.aws_iam_policy_document.lambda_logs.json
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda_logs.arn
}

# ---------------------------------------------------------------------
# CloudWatch log group for the function
# ---------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days

  # KMS encryption: customer-managed key when toggled on, AWS-managed
  # default otherwise. The AWS-managed `aws/logs` key is applied
  # automatically when no kms_key_id is set; we don't need to specify
  # anything in that case.
  kms_key_id = var.use_customer_managed_kms_key ? aws_kms_key.logs[0].arn : null
}

# Optional customer-managed KMS key for the log group. Only created
# when var.use_customer_managed_kms_key = true. Default deployments
# use the AWS-managed aws/logs key with no extra resources.
resource "aws_kms_key" "logs" {
  count = var.use_customer_managed_kms_key ? 1 : 0

  description             = "CMK for ${var.function_name} log groups."
  deletion_window_in_days = 7
  enable_key_rotation     = true

  # Allow CloudWatch Logs in this region+account to use the key.
  # The lambda role's kms:Decrypt grant is added separately in the
  # role policy (see data.aws_iam_policy_document.lambda_logs).
  #
  # The EncryptionContext condition uses ArnLike with TWO patterns
  # because we have two log groups: the function log group
  # (/aws/lambda/<name>) and the API Gateway access log group
  # (/aws/apigatewayv2/<name>-access). A single-ARN equality
  # condition would lock out the access log group, leaving its
  # writes silently failing — only discovered when someone went
  # looking for access logs that weren't there. Listing both ARNs
  # explicitly keeps the condition restrictive (still scoped to
  # this stack's log groups, not all log groups in the account)
  # while covering both legitimate writers.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountRoot"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.function_name}",
              "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/apigatewayv2/${var.function_name}-access",
            ]
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "logs" {
  count         = var.use_customer_managed_kms_key ? 1 : 0
  name          = "alias/${var.function_name}-logs"
  target_key_id = aws_kms_key.logs[0].key_id
}

# ---------------------------------------------------------------------
# API Gateway HTTP API
# ---------------------------------------------------------------------
#
# HTTP API rather than REST API: ~70% cheaper, lower latency, native
# IAM/JWT authorizer support. We don't use any REST-only features
# (usage plans, request validation, transformation), so HTTP API is
# the correct choice for this workload.

resource "aws_apigatewayv2_api" "this" {
  name          = var.function_name
  protocol_type = "HTTP"
  description   = "Single-tenant ferret-scan redaction gateway. IAM-authenticated."

  # No CORS configuration. This is intentional: the gateway is
  # service-to-service (IAM auth via SigV4), not browser-callable.
  # Adding CORS would imply a public, browser-facing surface that
  # this stack is not designed for. If you need browser access:
  #
  #   1. Add an authentication path that browsers can actually use
  #      (Cognito JWT or a Lambda authorizer with bearer tokens —
  #      browsers can't SigV4-sign).
  #   2. Configure cors_configuration here with allowed origins
  #      pinned to your specific domains, NOT "*".
  #   3. Add WAF in front for source-IP rate limiting (browsers
  #      are far more abuse-prone than service-to-service callers).
  #
  # Until those three are in place, leaving CORS unset means the
  # browser's same-origin policy implicitly blocks any malicious
  # cross-origin request without us having to think about it.
}

# Lambda integration. payload_format_version 2.0 is the current
# standard for HTTP APIs and the format the handler expects (the
# handler currently doesn't unwrap an APIGatewayV2 envelope — see
# the README's note about wrapping if you need full event access).
resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.this.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = var.timeout_seconds * 1000
}

# Single route. AuthorizationType = AWS_IAM means callers must
# SigV4-sign requests using credentials with execute-api:Invoke
# on this route's ARN. NEVER set this to NONE without explicit
# justification.
resource "aws_apigatewayv2_route" "redact" {
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = "POST /v1/redact"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "AWS_IAM"
}

# ---------------------------------------------------------------------
# API Gateway stage with access logging
# ---------------------------------------------------------------------
#
# Access log format: pinned to a body-redacting shape. Includes
# enough metadata for incident response (source IP, request ID,
# IAM principal, status, latency, integration status) but
# DELIBERATELY EXCLUDES:
#
#   - $context.requestBody       (the input we're protecting)
#   - $context.responseBody      (the redacted output, also potentially sensitive)
#   - $context.error.responseType (full error responses can leak request data)
#
# Future contributors who "improve" the format must consider whether
# any added field could carry payload bytes. Adding a body field is
# a security regression even if other fields look harmless.

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigatewayv2/${var.function_name}-access"
  retention_in_days = local.access_log_retention
  kms_key_id        = var.use_customer_managed_kms_key ? aws_kms_key.logs[0].arn : null
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = var.throttling_burst_limit
    throttling_rate_limit  = var.throttling_rate_limit
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn

    # Body-redacting format. Each field is one space-separated value.
    # The format is pinned in the IaC rather than left to operator
    # judgment because it's the ONLY chokepoint for what hits
    # CloudWatch from the access path. Body fields are NOT in this
    # list and must NEVER be added.
    #
    # Fields included (all metadata, no payload bytes):
    #   - sourceIp:           caller IP for incident response / abuse triage
    #   - requestId:          API Gateway request ID for correlation
    #   - userArn:            IAM principal that signed the request
    #   - routeKey:           "POST /v1/redact" — pinned by the route shape
    #   - status:             HTTP status code returned to caller
    #   - responseLatency:    end-to-end latency in ms
    #   - integrationStatus:  status code from Lambda invoke
    #   - integrationLatency: Lambda execution time in ms
    #   - userAgent:          User-Agent header — useful for
    #                         identifying client tooling during incident
    #                         response. Treated as caller-supplied; do
    #                         NOT use for security decisions.
    format = join(" ", [
      "$context.identity.sourceIp",
      "$context.requestId",
      "$context.identity.userArn",
      "$context.routeKey",
      "$context.status",
      "$context.responseLatency",
      "$context.integrationStatus",
      "$context.integrationLatency",
      "$context.identity.userAgent",
    ])
  }
}

# Allow API Gateway to invoke the function. The source_arn includes
# the api ID + a wildcard for stage/method/route, scoped to this
# specific API.
resource "aws_lambda_permission" "apigw_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*"
}
