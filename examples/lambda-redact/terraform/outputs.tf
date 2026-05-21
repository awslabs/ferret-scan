# Outputs for the lambda-redact stack.
#
# Cost-floor docstring convention: when a numeric output represents
# "what you pay if zero requests hit this stack for a month", the
# output name uses the suffix `_floor` and the docstring lists what
# is INCLUDED and EXCLUDED. Real costs are usage-dominated.

# ---- Identity / endpoints ----

output "invoke_url" {
  description = <<-EOT
    Full URL of the redaction endpoint. POST JSON requests here
    with SigV4 authentication (service = execute-api). The
    `example_curl_invocation` output renders a ready-to-paste
    awscurl command.
  EOT
  value       = "${aws_apigatewayv2_api.this.api_endpoint}/v1/redact"
}

output "function_arn" {
  description = "ARN of the Lambda function. Use to attach billing alarms or feed downstream metric subscriptions."
  value       = aws_lambda_function.this.arn
}

output "function_name" {
  description = "Lambda function name. Same as var.function_name; surfaced for convenience."
  value       = aws_lambda_function.this.function_name
}

output "log_group_name" {
  description = "CloudWatch log group for the Lambda function. Audit records (counts only, no payload) flow here via log.Printf in the handler."
  value       = aws_cloudwatch_log_group.lambda.name
}

output "access_log_group_name" {
  description = "CloudWatch log group for API Gateway access logs. Format is pinned in main.tf to exclude request/response bodies."
  value       = aws_cloudwatch_log_group.access.name
}

output "api_id" {
  description = "API Gateway HTTP API ID. Use to attach WAF or to identify this stack in CloudTrail."
  value       = aws_apigatewayv2_api.this.id
}

output "execution_arn" {
  description = "API Gateway execution ARN prefix (without stage/method/route). Used by the IAM policy doc below to scope execute-api:Invoke to this gateway."
  value       = aws_apigatewayv2_api.this.execution_arn
}

# ---- Onboarding helpers ----
#
# These outputs save every consumer the same 5-minute IAM/curl puzzle.
# They are documentation-as-data: emitted once at terraform apply
# time, available via `terraform output -raw <name>`, and pasted
# directly into wherever the consumer needs them.

output "caller_invoke_policy_doc" {
  description = <<-EOT
    IAM policy JSON granting execute-api:Invoke on this gateway's
    POST /v1/redact route only. Attach to the principal that needs
    to call the gateway:

        terraform output -raw caller_invoke_policy_doc \
          | aws iam put-role-policy \
              --role-name MyCallerRole \
              --policy-name InvokeFerretRedactGw \
              --policy-document file:///dev/stdin

    Policy is scoped to this exact route — no other gateway, no
    other method. Replace the role name above with whatever
    principal needs invoke access.
  EOT
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeFerretRedactGateway"
        Effect   = "Allow"
        Action   = "execute-api:Invoke"
        Resource = "${aws_apigatewayv2_api.this.execution_arn}/*/POST/v1/redact"
      },
    ]
  })
}

output "example_curl_invocation" {
  description = <<-EOT
    Ready-to-paste awscurl command for the deployed gateway. The
    fixture text contains a known Visa test number and email; a
    successful response should redact both.

    Requires awscurl: `pip install awscurl`. The caller's AWS
    credentials must include execute-api:Invoke on this route ARN
    (see caller_invoke_policy_doc above).
  EOT
  value       = <<-EOT
    awscurl --service execute-api --region ${local.region} \
      -X POST ${aws_apigatewayv2_api.this.api_endpoint}/v1/redact \
      -d '{"text":"card 5500-0000-0000-0004 from alice@example.com","strategy":"format_preserving","label":"manual-test"}'
  EOT
}

output "make_smoke_invocation" {
  description = <<-EOT
    Ready-to-paste invocation of the project's `make smoke`
    target against this deployed gateway. Runs a fuller set of
    assertions than the curl example above — verifies the
    redacted field is present, original CC bytes are absent,
    original email bytes are absent, and findings_by_type is
    omitted by default.
  EOT
  value       = <<-EOT
    INVOKE_URL=${aws_apigatewayv2_api.this.api_endpoint} AWS_REGION=${local.region} \
      make -C examples/lambda-redact smoke
  EOT
}

# ---- Cost transparency ----

output "estimated_monthly_cost_floor" {
  description = <<-EOT
    Hardcoded floor for monthly cost in USD when zero requests
    hit this stack for a calendar month. The value is always 0;
    the real cost story is in the embedded explanation rendered
    in the `cost_explanation` output below.

    INCLUDED in this floor:
      - Lambda function: $0.00 baseline (billed only on invocation
        regardless of reserved concurrency setting).
      - CloudWatch Log Groups: $0.00 baseline (storage is billed
        per GB-month; empty log groups have negligible cost. The
        real driver is ingest per GB).
      - API Gateway HTTP API: $0.00 baseline (pay-per-request).
      - IAM role/policies, KMS aliases: $0.00.

    EXCLUDED from this floor (these dominate the real bill at
    any meaningful traffic):
      - Lambda execution: $0.20 per 1M requests + ~$8.50 per 1M
        GB-seconds at 512 MB. A 1M-request month at p50 50ms costs
        ~$1.00 in compute.
      - CloudWatch Logs ingest: $0.50 per GB. The audit record per
        request is ~150 bytes; 1M requests ≈ 150 MB ≈ $0.08.
        Access logs add similar volume.
      - API Gateway HTTP API: $1.00 per million requests.
      - Data transfer out: ~$0.09/GB to internet.
      - Customer-managed KMS key (only when toggle is on): ~$1.00/month.

    Real bill ≈ $2-3 per million requests, dominated by Lambda
    compute + API Gateway requests + log ingest.
  EOT
  value       = "0"
}

output "cost_at_throttle_ceiling" {
  description = <<-EOT
    Approximate monthly cost in USD if a caller hits the
    configured API Gateway rate limit continuously for an
    entire month. This is the cost-bounding control: throttling
    caps real-world spend regardless of caller behavior.

    Calculation: rate_limit RPS * 60s * 60min * 24h * 30d *
    ($1/M API + $1/M Lambda + $0.50 log ingest per ~5 GB-month).

    Adjust the rate limit (var.throttling_rate_limit) to set
    your cost ceiling explicitly.
  EOT
  value       = format("~$%.2f/month at rate=%d RPS continuous", (tonumber(var.throttling_rate_limit) * 60 * 60 * 24 * 30 / 1000000.0) * 3, var.throttling_rate_limit)
}

output "billing_alarm_setup_doc" {
  description = <<-EOT
    AWS CLI snippet to set up a CloudWatch billing alarm at
    $X/month. Billing metrics live in us-east-1 regardless of
    the deployment region; the snippet pins us-east-1 for that
    reason.

    Replace $X with your threshold and configure the SNS topic
    ARN for notifications. The snippet uses the deployment's
    Project tag (rendered into the value below) for filtering.
  EOT
  value       = <<-EOT
    # Project tag for this stack: ${var.tags["Project"]}
    aws cloudwatch put-metric-alarm \
      --region us-east-1 \
      --alarm-name "${var.function_name}-billing-floor" \
      --alarm-description "Billing alarm for ${var.tags["Project"]} stack" \
      --metric-name EstimatedCharges \
      --namespace AWS/Billing \
      --statistic Maximum \
      --period 21600 \
      --evaluation-periods 1 \
      --threshold X \
      --comparison-operator GreaterThanThreshold \
      --dimensions Name=Currency,Value=USD \
      --alarm-actions arn:aws:sns:us-east-1:${local.account_id}:billing-alerts \
      --treat-missing-data notBreaching
  EOT
}

# ---- Stack metadata ----

output "region" {
  description = "AWS region this stack is deployed in. Surfaced so consumers calling `terraform output` don't need to read variables.tf."
  value       = local.region
}

output "tags" {
  description = "Tags applied to every resource. Use the Project tag for billing alarms."
  value       = var.tags
}
