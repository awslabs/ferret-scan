# Cloud Resource Validator

Detects cloud provider resource identifiers that may expose sensitive information such as account numbers, subscription IDs, and internal resource naming conventions.

> **What this is (and isn't).** Cloud resource identifiers are *references, not credentials* — they are non-secret by design (an AWS account ID appears in the cross-account role ARNs you intentionally share with partners). This validator is a **reconnaissance / IaC-hygiene** signal: it flags account IDs, subscription UUIDs, and internal resource names that may matter when an artifact crosses a trust boundary (a doc, a ticket, a chat message). It is **lower severity** than the PII/secrets validators. Actual secret material (e.g. `AKIA…` keys) is detected by the SECRETS validator, not this one.

## Supported Cloud Providers

### AWS — Amazon Resource Names (ARNs)

Detects AWS resource identifiers with 12-digit account IDs.

```text
arn:aws:iam::123456789012:role/MyRole
arn:aws:s3:::my-bucket/path/to/object
arn:aws:lambda:us-east-1:123456789012:function:my-function
arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123def456
```

**Extracted metadata:** account ID, service type, region

### Azure — Resource IDs

Detects Azure resource paths with subscription UUIDs and resource groups.

```text
/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/myRG/providers/Microsoft.Storage/storageAccounts/mystorageaccount
/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/web-server-01
```

**Extracted metadata:** subscription ID, resource group, resource type

### Google Cloud Platform — Resource Names

Detects GCP resource names with project IDs and zone/region information.

```text
projects/my-project/zones/us-central1-a/instances/my-vm
projects/my-project/regions/us-east1/subnetworks/my-subnet
projects/my-project/global/firewalls/allow-http
//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/my-vm
```

**Extracted metadata:** project ID, zone/region, resource type

### Oracle Cloud Infrastructure — OCIDs

Detects OCI identifiers with compartment and region information.

```text
ocid1.instance.oc1.us-phoenix-1.abcdefghijk123456
ocid1.compartment.oc1..aaaaaaaabbccddee
ocid1.bucket.oc1.us-ashburn-1.xyz789abc
```

**Extracted metadata:** resource type, region

### IBM Cloud — Cloud Resource Names (CRNs)

Detects IBM Cloud CRNs with account identifiers and service types.

```text
crn:v1:bluemix:public:cos:us-south:a/abc123def456:bucket-id:object-key
crn:v1:bluemix:public:iam:global:a/abc123def456:policy:policy-id
```

**Extracted metadata:** account ID, service type, region

### Alibaba Cloud — ARNs

Detects Alibaba Cloud resource ARNs with account numbers.

```text
acs:ecs:cn-hangzhou:123456789:instance/i-abc123def
acs:oss:cn-beijing:123456789:bucket/my-bucket
acs:rds:cn-shanghai:123456789:dbinstance/rm-abc123
```

**Extracted metadata:** account ID, service type, region

## Confidence Scoring

Confidence is **tiered by how much tenant identity an identifier exposes**, so the
default-on validator does not bury PII/secret findings under low-value infrastructure
noise. The score maps onto ferret-scan's bands (HIGH ≥ 90, MEDIUM 60–89, LOW < 60),
so `--confidence high,medium` keeps only identity-bearing resources.

**Per-type base confidence:**

| Resource form | Base | Band | Rationale |
| ------------- | ---- | ---- | --------- |
| AWS IAM/Lambda/EC2/generic ARN (12-digit account) | 85 | HIGH (with +10 account) | Account ID + principal/resource name |
| Azure subscription resource path | 90 | HIGH | Validated subscription GUID + topology |
| GCP project resource | 85 | HIGH (with +10 project) | Project ID is the account-equivalent anchor |
| IBM CRN / Alibaba ARN | 80 | MEDIUM→HIGH (with +10 account) | Account anchor present only in some forms |
| GCP folder/organization | 65 | MEDIUM | Hierarchy ID, no project anchor |
| AWS S3 bucket ARN | 55 | LOW | No account/region by design — just a bucket name |
| OCI OCID | 55 | LOW | No tenancy surfaced; opaque id |
| Azure management group | 55 | LOW | Group name only, no subscription GUID |

**Adjustments:** `+10` valid account/subscription/project anchor present; `-10` match < 20 chars;
`-15` match > 500 chars; `-20` a whole-token test/example keyword on the match's **own line**
(line-local, *not* document-wide — an `example` elsewhere in the file no longer penalizes a
real finding). Test-context keywords: `example`, `test`, `demo`, `sample`, `fake`, `mock`,
`dummy`, `placeholder`, `template`, `tutorial`, `documentation`.

**Public-by-design resources are not reported at all:** AWS-managed policy ARNs
(`arn:aws:iam::aws:policy/*`) and public GCP datasets (`bigquery-public-data`,
`gcp-public-data-*`, `google.com:*`). These are ubiquitous in IaC and carry no
tenant identity.

## Configuration

Configuration is optional. All cloud providers are enabled by default.

### YAML Configuration

```yaml
validators:
  cloud_resources:
    # Enable/disable specific providers
    enabled_providers:
      aws: true
      azure: true
      gcp: true
      oci: true
      ibm: true
      alibaba: true

    # Add custom regex patterns (Go regex syntax)
    custom_patterns:
      - "arn:aws:custom-service:[a-zA-Z0-9-]*:[0-9]{12}:[a-zA-Z0-9:/_-]+"
      - "/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/Custom\\.[^/]+/[^/]+/[^/]+"
```

### Disabling Specific Providers

To scan only for AWS and Azure resources:

```yaml
validators:
  cloud_resources:
    enabled_providers:
      aws: true
      azure: true
      gcp: false
      oci: false
      ibm: false
      alibaba: false
```

## Usage

### Command Line

```bash
# Scan a single file
ferret-scan --file infrastructure.tf --checks CLOUD_RESOURCES

# Scan recursively with verbose output
ferret-scan --file . --recursive --checks CLOUD_RESOURCES --verbose

# Filter by confidence level
ferret-scan --file deployment.yaml --checks CLOUD_RESOURCES --confidence high,medium
```

### Output Metadata

Each finding includes structured metadata. By default the matched value and any
value-bearing metadata (account ID, region, …) are redacted to `[HIDDEN]`; pass
`--show-match` to reveal them. The example below is shown with `--show-match`:

```json
{
  "text": "arn:aws:iam::123456789012:role/MyRole",
  "type": "AWS_ARN",
  "confidence": 95.0,
  "validator": "cloud_resources",
  "metadata": {
    "provider": "aws",
    "resource_type": "AWS_ARN",
    "account_id": "123456789012",
    "service": "iam",
    "confidence_factors": ["base_match:+85", "valid_account_id:+10"]
  }
}
```

(IAM ARNs are global, so no `region` field is emitted; regional services like
Lambda/EC2 include `"region": "us-east-1"`.)

## Troubleshooting

| Issue | Resolution |
|-------|-----------|
| No matches found | Verify correct providers are enabled. Use `--verbose` for debug output. |
| Too many false positives | Check if content contains test/example data. Confidence scoring reduces these automatically. |
| Custom pattern not working | Verify your regex is valid Go regex syntax. Use `--verbose` to see compilation errors. |
| Provider not detected | Ensure the provider is enabled in your configuration. |
