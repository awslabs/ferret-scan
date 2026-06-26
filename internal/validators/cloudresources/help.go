// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import "github.com/awslabs/ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the cloud resources check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "CLOUD_RESOURCES",
		ShortDescription: "Detects cloud provider resource identifiers (ARNs, Resource IDs, OCIDs)",
		DetailedDescription: `The Cloud Resource Validator detects resource identifiers from major cloud providers that may contain sensitive information such as account numbers, subscription IDs, and internal resource naming conventions.

SUPPORTED CLOUD PROVIDERS:
• AWS - Amazon Resource Names (ARNs) with 12-digit account IDs
• Azure - Resource IDs with subscription UUIDs and resource groups
• Google Cloud Platform - Resource names with project IDs and zones
• Oracle Cloud Infrastructure - OCIDs with compartment information
• IBM Cloud - Cloud Resource Names (CRNs) with account identifiers
• Alibaba Cloud - ARNs with account numbers and service information

The validator automatically extracts account/subscription IDs, resource types, and regional information for security analysis.

Cloud resource identifiers are references, not credentials — they are non-secret by design (an AWS account ID appears in cross-account role ARNs you intentionally share with partners). The value here is reconnaissance / IaC-hygiene: catching an account ID, subscription UUID, or internal resource name in an artifact that crosses a trust boundary. Confidence is therefore tiered by how much tenant identity an identifier exposes: those embedding an account/subscription/project anchor (IAM role ARNs, Azure subscription paths, GCP project resources) score HIGH, while account-less low-signal forms (S3 bucket ARNs, OCIDs, Azure management groups) score LOW so '--confidence high,medium' hides them. Public-by-design resources (AWS-managed policy ARNs, public GCP datasets) are not reported.`,

		Patterns: []string{
			"AWS ARNs: arn:aws:service:region:account-id:resource",
			"Azure Resource IDs: /subscriptions/{uuid}/resourceGroups/{name}/providers/{provider}/{type}/{name}",
			"GCP Resource Names: projects/{project-id}/zones/{zone}/instances/{name}",
			"OCI OCIDs: ocid1.{type}.oc1.{region}.{unique-id}",
			"IBM CRNs: crn:v1:bluemix:public:service:region:account:resource-type:resource-id",
			"Alibaba ARNs: acs:service:region:account-id:resource-type/resource-name",
		},

		SupportedFormats: []string{
			"AWS ARN format (arn:aws:service:region:account-id:resource)",
			"AWS IAM ARNs (roles, users, groups, policies)",
			"AWS S3 bucket ARNs",
			"AWS Lambda function ARNs",
			"AWS EC2 instance ARNs",
			"Azure subscription resource paths (/subscriptions/{uuid}/...)",
			"Azure management group paths (/providers/Microsoft.Management/...)",
			"GCP zonal resources (projects/{id}/zones/{zone}/{type}/{name})",
			"GCP regional resources (projects/{id}/regions/{region}/{type}/{name})",
			"GCP global resources (projects/{id}/global/{type}/{name})",
			"GCP full URI format (//service.googleapis.com/projects/...)",
			"OCI OCIDs (ocid1.{type}.oc1.{region}.{unique-id})",
			"IBM Cloud CRNs (crn:v1:bluemix:public:...)",
			"Alibaba Cloud ARNs (acs:service:region:account:resource)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Base (identity-bearing)", Description: "Per-type base for resources embedding an account/subscription/project anchor (IAM/Azure-subscription/GCP-project): HIGH band", Weight: 85},
			{Name: "Base (account-less)", Description: "Per-type base for low-signal forms with no tenant identity (S3 bucket, OCID, Azure management group): LOW band", Weight: 55},
			{Name: "Valid Account ID", Description: "A genuine account/subscription/project anchor is present", Weight: 10},
			{Name: "Short Match Penalty", Description: "Match shorter than 20 chars may be a false positive", Weight: -10},
			{Name: "Long Match Penalty", Description: "Match longer than 500 chars may be a false positive", Weight: -15},
			{Name: "Test Context Penalty", Description: "The match's OWN line contains a whole-token test/example keyword (line-local, not document-wide)", Weight: -20},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		ConfigurationInfo: `Configuration is optional. By default, all cloud providers are enabled.

To configure in your ferret-scan YAML config file:

  validators:
    cloud_resources:
      enabled_providers:
        aws: true
        azure: true
        gcp: true
        oci: true
        ibm: true
        alibaba: true
      custom_patterns:
        - "arn:aws:custom-service:[a-zA-Z0-9-]*:[0-9]{12}:[a-zA-Z0-9:/_-]+"

TROUBLESHOOTING:

COMMON ISSUES:
• "No matches found" — Verify the correct providers are enabled. Use --verbose for debug output.
• "Low-value findings (S3 buckets, OCIDs) clutter results" — These score in the LOW band by design; filter with --confidence high,medium to keep only identity-bearing resources.
• "Custom pattern not working" — Verify your regex is valid Go regex syntax. Use --verbose to see compilation errors.
• "Provider not detected" — Ensure the provider is enabled in your configuration.

DEBUGGING TIPS:
• Use --verbose or debug mode to see pattern matching decisions
• Check confidence_factors in metadata to understand scoring
• Use --checks CLOUD_RESOURCES to run only this validator
• Review enabled_providers in config to confirm provider is active
• For custom patterns, test regex at https://regex101.com (select Go flavor)`,

		Examples: []string{
			"ferret-scan --file infrastructure.tf --checks CLOUD_RESOURCES",
			"ferret-scan --file deployment.yaml --checks CLOUD_RESOURCES --verbose",
			"ferret-scan --file . --recursive --checks CLOUD_RESOURCES --confidence high,medium",
		},
	}
}
