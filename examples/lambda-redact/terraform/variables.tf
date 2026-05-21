# Variables for the lambda-redact Terraform stack.
#
# Defaults are tuned for a single-tenant internal experimental
# deployment. They are NOT recommended for multi-tenant or
# production-load use without revisiting at minimum: throttling
# limits, reserved concurrency, log retention, KMS key choice, and
# WAF/CloudFront placement (none of which are in this v1 stack).

# ---- AWS provider configuration ----

variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

# ---- Function naming and sizing ----

variable "function_name" {
  description = <<-EOT
    Name for the Lambda function. Also used as the prefix for the
    log group (/aws/lambda/<name>) and the API Gateway. Keep it
    short — Lambda enforces a 64-char limit and the value shows up
    in IAM ARNs and CloudWatch dashboards.
  EOT
  type        = string
  default     = "ferret-redact-gw"

  validation {
    condition     = length(var.function_name) > 0 && length(var.function_name) <= 64
    error_message = "function_name must be 1–64 characters."
  }
}

variable "memory_mb" {
  description = <<-EOT
    Lambda memory size in MB. 512 MB is the recommended default for
    this workload: regex evaluation can spike CPU, and Lambda
    allocates CPU proportionally to memory below 1769 MB. 256 MB is
    too tight for the SECRETS validator's PEM/JWT regexes; 1024 MB
    is overkill and adds cost without latency benefit on small
    payloads (typical request is single-digit ms at 512 MB).
  EOT
  type        = number
  default     = 512

  validation {
    condition     = var.memory_mb >= 128 && var.memory_mb <= 10240
    error_message = "memory_mb must be in [128, 10240]."
  }
}

variable "timeout_seconds" {
  description = <<-EOT
    Lambda invocation timeout in seconds. The handler typically
    completes in single-digit ms; the 10s default exists to absorb
    cold start + an unusually large payload (up to the 6 MB sync
    invoke limit) without timing out. API Gateway HTTP API caps
    integration timeout at 30s, so values above that are pointless.
  EOT
  type        = number
  default     = 10

  validation {
    condition     = var.timeout_seconds >= 1 && var.timeout_seconds <= 30
    error_message = "timeout_seconds must be in [1, 30] (API Gateway HTTP API integration limit)."
  }
}

variable "reserved_concurrent_executions" {
  description = <<-EOT
    Lambda reserved concurrency limit. NULL by default — the
    function uses unreserved concurrency from the account pool.

    Reserved concurrency is a CAPACITY RESERVATION, not a safety
    control: setting it carves capacity OUT of the account pool
    and SUBTRACTS from the limit available to other functions.
    The DoS-bounding control for this gateway is API Gateway
    throttling (see throttling_burst_limit / throttling_rate_limit
    below), which fires before invocations reach Lambda.

    Set this to a positive integer only when you have a real
    workload profile and need to prevent this gateway from
    exhausting the account-wide concurrency limit. A typical
    starting point for a measured production workload is
    `min(account_limit / 4, peak_rps * p99_latency_seconds * 2)`.
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.reserved_concurrent_executions == null || var.reserved_concurrent_executions >= 0
    error_message = "reserved_concurrent_executions must be null or non-negative."
  }
}

# ---- Logging ----

variable "log_retention_days" {
  description = <<-EOT
    CloudWatch Logs retention. CloudWatch's default is "never
    expire," which silently inflates the bill — pin a value
    explicitly. 30 days is enough for incident response on an
    experimental deployment; bump to 90+ days when you have
    compliance requirements that demand it.
  EOT
  type        = number
  default     = 30

  validation {
    condition = contains(
      [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653],
      var.log_retention_days
    )
    error_message = "log_retention_days must be one of CloudWatch's allowed values (see aws_cloudwatch_log_group docs)."
  }
}

variable "use_customer_managed_kms_key" {
  description = <<-EOT
    When true, encrypt the CloudWatch log group with a
    customer-managed KMS key (created and managed by this stack).
    When false (default), use the AWS-managed `aws/logs` key.

    AWS-managed is correct for v1: the CMK adds a key policy
    review, key rotation, kms:Decrypt grants on the Lambda role,
    and a small per-month KMS bill. Flip this to true only if you
    have a specific compliance requirement that mandates a CMK.
  EOT
  type        = bool
  default     = false
}

variable "access_log_retention_days" {
  description = <<-EOT
    Retention for the API Gateway access log group. Defaults to
    the same value as log_retention_days. The access log carries
    metadata only (source IP, request ID, status, latency,
    principal) — no request bodies, no response bodies — so the
    retention choice is driven by incident response needs, not
    by data sensitivity.
  EOT
  type        = number
  default     = null # falls back to log_retention_days in main.tf
}

# ---- API Gateway throttling ----

variable "throttling_burst_limit" {
  description = <<-EOT
    API Gateway burst limit (requests served from the token bucket
    before sustained-rate throttling kicks in). The DoS-bounding
    control for this gateway. Conservative for an internal tool;
    raise when you have a real workload profile.
  EOT
  type        = number
  default     = 20

  validation {
    condition     = var.throttling_burst_limit > 0
    error_message = "throttling_burst_limit must be positive."
  }
}

variable "throttling_rate_limit" {
  description = <<-EOT
    API Gateway sustained rate limit in requests per second.
    Defaults to 10 RPS for an internal tool — high enough for
    exploratory use, low enough to prevent a runaway caller from
    producing meaningful CloudWatch volume. Raise when measured
    usage justifies it.
  EOT
  type        = number
  default     = 10

  validation {
    condition     = var.throttling_rate_limit > 0
    error_message = "throttling_rate_limit must be positive."
  }
}

# ---- Build artifact ----

variable "function_zip_path" {
  description = <<-EOT
    Path to the Lambda deployment zip. Defaults to
    ../function.zip (the artifact produced by `make build` in the
    parent directory). Override if you want to deploy a zip from
    a different location (e.g. an S3-fetched build artifact).
  EOT
  type        = string
  default     = "../function.zip"
}

# ---- Handler runtime configuration ----

variable "ferret_checks" {
  description = <<-EOT
    Comma-separated list of validators to enable. Empty string
    or "all" enables every default validator. Restricts the
    handler's scan surface without rebuilding the binary.
  EOT
  type        = string
  default     = "all"
}

variable "ferret_strategy" {
  description = "Default redaction strategy: simple | format_preserving | synthetic."
  type        = string
  default     = "format_preserving"

  validation {
    condition     = contains(["simple", "format_preserving", "synthetic"], var.ferret_strategy)
    error_message = "ferret_strategy must be simple, format_preserving, or synthetic."
  }
}

variable "include_findings_in_response" {
  description = <<-EOT
    Wire-format toggle: when true, the handler returns a
    `findings_by_type` field with per-type counts. Defaults to
    false because the per-type counts constitute a soft
    side-channel in multi-tenant deployments. Flip to true only
    for single-tenant or debug deployments where the caller
    already knows what they sent.

    The audit log always carries the full counts regardless;
    operators can query the function's log stream for them
    without exposing them on the wire.
  EOT
  type        = bool
  default     = false
}

# ---- Tagging ----

variable "tags" {
  description = <<-EOT
    Tags applied to every resource created by this stack. The
    `Project` tag is the recommended dimension for billing alarms
    (see the billing_alarm_setup_doc output).
  EOT
  type        = map(string)
  default = {
    Project   = "ferret-redact-gw"
    ManagedBy = "terraform"
    Example   = "github.com/awslabs/ferret-scan/examples/lambda-redact"
  }
}
