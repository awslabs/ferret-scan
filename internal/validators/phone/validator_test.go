package phone

import (
	"testing"
)

// TestPhoneValidator_BeforeStructuralAnalysis documents current behavior
// These tests show what the validator currently does (including false positives)
func TestPhoneValidator_BeforeStructuralAnalysis(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name            string
		content         string
		expectMatch     bool
		description     string
		currentBehavior string // What it does now
	}{
		// AWS Resource IDs (FALSE POSITIVES - should NOT match)
		{
			name:            "AWS EC2 Instance ID",
			content:         "Instance: i-0570342429318abcd",
			expectMatch:     false,
			description:     "EC2 instance IDs contain 10-digit sequences",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "AWS AMI ID",
			content:         "AMI: ami-0504513759291234",
			expectMatch:     false,
			description:     "AMI IDs contain 10-digit sequences",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "AWS VPC ID",
			content:         "VPC: vpc-1234567890abcdef",
			expectMatch:     false,
			description:     "VPC IDs contain 10-digit sequences",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "AWS Subnet ID",
			content:         "Subnet: subnet-0123456789abc",
			expectMatch:     false,
			description:     "Subnet IDs contain digit sequences",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "AWS Security Group ID",
			content:         "SecurityGroup: sg-0123456789abcdef",
			expectMatch:     false,
			description:     "Security group IDs contain digit sequences",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "AWS ARN with Account ID",
			content:         "arn:aws:iam::123456789012:role/MyRole",
			expectMatch:     false,
			description:     "ARNs contain 12-digit account IDs",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "AWS CloudFormation Stack ID",
			content:         "StackId: arn:aws:cloudformation:us-east-1:123456789012:stack/MyStack/12345678-1234",
			expectMatch:     false,
			description:     "Stack IDs contain account numbers",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},

		// Timestamps (FALSE POSITIVES - should NOT match)
		{
			name:            "Unix Timestamp",
			content:         "Timestamp: 1234567890",
			expectMatch:     false,
			description:     "10-digit Unix timestamps",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "Millisecond Timestamp",
			content:         "Created: 1234567890123",
			expectMatch:     false,
			description:     "13-digit millisecond timestamps",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "Build Number",
			content:         "Build: 20231215123456",
			expectMatch:     false,
			description:     "Build numbers with timestamps",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},

		// Credit Card Fragments (FALSE POSITIVES - should NOT match)
		{
			name:            "Credit Card Last 4",
			content:         "Card ending in 1234",
			expectMatch:     false,
			description:     "Credit card last 4 digits",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "Credit Card Fragment",
			content:         "Payment: ****-****-****-1234",
			expectMatch:     false,
			description:     "Masked credit card with last 4",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},

		// Serial Numbers and IDs (FALSE POSITIVES - should NOT match)
		{
			name:            "Serial Number",
			content:         "Serial: SN1234567890",
			expectMatch:     false,
			description:     "Product serial numbers",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "Order ID",
			content:         "Order: ORD-1234567890",
			expectMatch:     false,
			description:     "Order IDs with digits",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},
		{
			name:            "Transaction ID",
			content:         "Transaction: TXN1234567890ABC",
			expectMatch:     false,
			description:     "Transaction IDs",
			currentBehavior: "CURRENTLY MATCHES (false positive)",
		},

		// Legitimate Phone Numbers (SHOULD match)
		{
			name:            "US Phone Standard",
			content:         "Call us at (555) 123-4567",
			expectMatch:     true,
			description:     "Standard US phone format",
			currentBehavior: "CORRECTLY MATCHES",
		},
		{
			name:            "US Phone Dashed",
			content:         "Phone: 555-123-4567",
			expectMatch:     true,
			description:     "Dashed US phone format",
			currentBehavior: "CORRECTLY MATCHES",
		},
		{
			name:            "International Phone",
			content:         "Contact: +1-555-123-4567",
			expectMatch:     true,
			description:     "International format",
			currentBehavior: "CORRECTLY MATCHES",
		},
		{
			name:            "Phone with Extension",
			content:         "Office: (555) 123-4567 ext 890",
			expectMatch:     true,
			description:     "Phone with extension",
			currentBehavior: "CORRECTLY MATCHES",
		},
		{
			name:            "Toll-Free Number",
			content:         "Support: 1-800-555-1234",
			expectMatch:     true,
			description:     "Toll-free number",
			currentBehavior: "CORRECTLY MATCHES",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			hasMatch := len(matches) > 0

			// Document current behavior
			t.Logf("Current Behavior: %s", tt.currentBehavior)
			t.Logf("Expected: match=%v, Got: match=%v", tt.expectMatch, hasMatch)

			if hasMatch {
				for _, m := range matches {
					t.Logf("  Match: %s (%.0f%% confidence)", m.Text, m.Confidence)
				}
			}

			// This test documents current behavior, not expected behavior
			// We expect some tests to fail before implementing structural analysis
		})
	}
}

// TestPhoneValidator_StructuralAnalysis tests the new structural analysis approach
func TestPhoneValidator_StructuralAnalysis(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		// AWS Resource IDs (should NOT match after fix)
		{
			name:        "AWS EC2 Instance ID",
			content:     "Instance: i-0570342429318abcd",
			expectMatch: false,
			description: "Hyphen before digits indicates resource ID",
		},
		{
			name:        "AWS AMI ID",
			content:     "AMI: ami-0504513759291234",
			expectMatch: false,
			description: "ami- prefix indicates AMI ID",
		},
		{
			name:        "AWS VPC ID",
			content:     "VPC: vpc-1234567890abcdef",
			expectMatch: false,
			description: "vpc- prefix indicates VPC ID",
		},
		{
			name:        "AWS Subnet ID",
			content:     "Subnet: subnet-0123456789abc",
			expectMatch: false,
			description: "subnet- prefix indicates subnet ID",
		},
		{
			name:        "AWS Security Group",
			content:     "SecurityGroup: sg-0123456789abcdef",
			expectMatch: false,
			description: "sg- prefix indicates security group",
		},
		{
			name:        "AWS ARN Account ID",
			content:     "arn:aws:iam::123456789012:role/MyRole",
			expectMatch: false,
			description: "Colon after digits indicates ARN component",
		},
		{
			name:        "AWS CloudFormation Stack",
			content:     "arn:aws:cloudformation:us-east-1:123456789012:stack/MyStack",
			expectMatch: false,
			description: "Colon after account ID in ARN",
		},
		{
			name:        "AWS S3 Bucket ARN",
			content:     "arn:aws:s3:::my-bucket-1234567890",
			expectMatch: false,
			description: "Digits in S3 bucket name",
		},
		{
			name:        "AWS Lambda ARN",
			content:     "arn:aws:lambda:us-east-1:123456789012:function:MyFunction",
			expectMatch: false,
			description: "Account ID in Lambda ARN",
		},

		// Timestamps (should NOT match after fix)
		{
			name:        "Unix Timestamp",
			content:     "Timestamp: 1234567890",
			expectMatch: false,
			description: "No separators indicates timestamp",
		},
		{
			name:        "Millisecond Timestamp",
			content:     "Created: 1234567890123",
			expectMatch: false,
			description: "13 digits indicates millisecond timestamp",
		},
		{
			name:        "Build Timestamp",
			content:     "Build: 20231215123456",
			expectMatch: false,
			description: "Date-like timestamp",
		},
		{
			name:        "Timestamp in JSON",
			content:     `{"created_at": 1234567890, "updated": 1234567891}`,
			expectMatch: false,
			description: "Timestamps in JSON",
		},

		// Serial Numbers and IDs (should NOT match after fix)
		{
			name:        "Serial Number",
			content:     "Serial: SN1234567890",
			expectMatch: false,
			description: "Letter before digits indicates serial",
		},
		{
			name:        "Order ID",
			content:     "Order: ORD-1234567890",
			expectMatch: false,
			description: "Prefix indicates order ID",
		},
		{
			name:        "Transaction ID",
			content:     "Transaction: TXN1234567890ABC",
			expectMatch: false,
			description: "Alphanumeric indicates transaction ID",
		},
		{
			name:        "UUID with digits",
			content:     "UUID: 12345678-1234-5678-1234-567890123456",
			expectMatch: false,
			description: "UUID format",
		},

		// Credit Card Fragments (should NOT match after fix)
		{
			name:        "Credit Card Last 4",
			content:     "Card ending in 1234",
			expectMatch: false,
			description: "Only 4 digits",
		},
		{
			name:        "Masked Credit Card",
			content:     "Payment: ****-****-****-1234",
			expectMatch: false,
			description: "Masked card number",
		},

		// Legitimate Phone Numbers (SHOULD match)
		{
			name:        "US Phone Standard",
			content:     "Call us at (555) 123-4567",
			expectMatch: true,
			description: "Standard US phone with space after",
		},
		{
			name:        "US Phone Dashed",
			content:     "Phone: 555-123-4567",
			expectMatch: true,
			description: "Dashed format with space after",
		},
		{
			name:        "US Phone Plain",
			content:     "Contact: 5551234567",
			expectMatch: true,
			description: "Plain 10-digit format",
		},
		{
			name:        "International Phone",
			content:     "Call: +1-555-123-4567",
			expectMatch: true,
			description: "International format",
		},
		{
			name:        "Phone with Extension",
			content:     "Office: (555) 123-4567 ext 890",
			expectMatch: true,
			description: "Phone with extension keyword",
		},
		{
			name:        "Toll-Free Number",
			content:     "Support: 1-800-555-1234",
			expectMatch: true,
			description: "Toll-free number",
		},
		{
			name:        "Phone in Sentence",
			content:     "Please call (555) 123-4567 for assistance.",
			expectMatch: true,
			description: "Phone followed by space and text",
		},
		{
			name:        "Phone at End",
			content:     "Contact: 555-123-4567",
			expectMatch: true,
			description: "Phone at end of line",
		},
		{
			name:        "Multiple Phones",
			content:     "Office: 555-123-4567, Mobile: 555-987-6543",
			expectMatch: true,
			description: "Multiple phones separated by comma",
		},

		// Tabular Data (SHOULD match)
		{
			name:        "CSV with Phones",
			content:     "John Doe,555-123-4567,john@example.com",
			expectMatch: true,
			description: "Phone in CSV format",
		},
		{
			name:        "Tab-Separated",
			content:     "Jane Smith\t555-987-6543\tjane@example.com",
			expectMatch: true,
			description: "Phone in tab-separated data",
		},
		{
			name:        "Fixed-Width Table",
			content:     "John Doe        555-123-4567    john@example.com",
			expectMatch: true,
			description: "Phone in fixed-width table",
		},
		{
			name:        "Pipe-Separated",
			content:     "Alice | 555-111-2222 | alice@example.com",
			expectMatch: true,
			description: "Phone in pipe-separated data",
		},

		// Edge Cases
		{
			name:        "Phone in Parentheses",
			content:     "Contact (555-123-4567) for details",
			expectMatch: true,
			description: "Phone in parentheses",
		},
		{
			name:        "Phone with Comma",
			content:     "Call 555-123-4567, ask for John",
			expectMatch: true,
			description: "Phone followed by comma",
		},
		{
			name:        "Phone with Period",
			content:     "Number: 555-123-4567.",
			expectMatch: true,
			description: "Phone at end of sentence",
		},
		{
			name:        "Phone in Quotes",
			content:     `Phone: "555-123-4567"`,
			expectMatch: true,
			description: "Phone in quotes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			hasMatch := len(matches) > 0

			if hasMatch != tt.expectMatch {
				t.Errorf("%s: expected match=%v, got=%v (found %d matches)",
					tt.description, tt.expectMatch, hasMatch, len(matches))
				if hasMatch {
					for _, m := range matches {
						t.Logf("  Unexpected match: %s (%.0f%% confidence) in: %s",
							m.Text, m.Confidence, m.Context.FullLine)
					}
				}
			}
		})
	}
}

// TestPhoneValidator_AWSResourcePatterns specifically tests AWS resource patterns
func TestPhoneValidator_AWSResourcePatterns(t *testing.T) {
	validator := NewValidator()

	awsPatterns := []struct {
		name        string
		content     string
		expectMatch bool
	}{
		// EC2 Resources
		{"EC2 Instance", "i-0123456789abcdef0", false},
		{"EC2 AMI", "ami-0123456789abcdef", false},
		{"EC2 Snapshot", "snap-0123456789abcdef", false},
		{"EC2 Volume", "vol-0123456789abcdef", false},

		// VPC Resources
		{"VPC", "vpc-0123456789abcdef", false},
		{"Subnet", "subnet-0123456789abcdef", false},
		{"Security Group", "sg-0123456789abcdef", false},
		{"Network ACL", "acl-0123456789abcdef", false},
		{"Internet Gateway", "igw-0123456789abcdef", false},
		{"NAT Gateway", "nat-0123456789abcdef", false},
		{"Route Table", "rtb-0123456789abcdef", false},
		{"VPC Endpoint", "vpce-0123456789abcdef", false},

		// ARN Formats
		{"IAM Role ARN", "arn:aws:iam::123456789012:role/MyRole", false},
		{"S3 Bucket ARN", "arn:aws:s3:::my-bucket-1234567890", false},
		{"Lambda ARN", "arn:aws:lambda:us-east-1:123456789012:function:MyFunc", false},
		{"DynamoDB ARN", "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable", false},
		{"SNS Topic ARN", "arn:aws:sns:us-east-1:123456789012:MyTopic", false},
		{"SQS Queue ARN", "arn:aws:sqs:us-east-1:123456789012:MyQueue", false},

		// CloudFormation
		{"Stack ID", "arn:aws:cloudformation:us-east-1:123456789012:stack/MyStack/guid", false},
		{"Stack Name", "my-stack-1234567890", false},

		// ECS/EKS
		{"ECS Cluster", "arn:aws:ecs:us-east-1:123456789012:cluster/my-cluster", false},
		{"ECS Task", "arn:aws:ecs:us-east-1:123456789012:task/my-cluster/1234567890", false},
		{"EKS Cluster", "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster", false},

		// RDS
		{"RDS Instance", "arn:aws:rds:us-east-1:123456789012:db:mydb", false},
		{"RDS Snapshot", "arn:aws:rds:us-east-1:123456789012:snapshot:mysnap", false},

		// ElastiCache
		{"ElastiCache Cluster", "arn:aws:elasticache:us-east-1:123456789012:cluster:mycluster", false},

		// Account IDs (12 digits)
		{"Account ID in ARN", "arn:aws:iam::123456789012:root", false},
		{"Account ID Standalone", "Account: 123456789012", false},
	}

	for _, tt := range awsPatterns {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			hasMatch := len(matches) > 0

			if hasMatch != tt.expectMatch {
				t.Errorf("AWS pattern '%s' should not match as phone, but found %d matches",
					tt.name, len(matches))
				for _, m := range matches {
					t.Logf("  Match: %s (%.0f%% confidence)", m.Text, m.Confidence)
				}
			}
		})
	}
}

// TestPhoneValidator_TabularData tests phone detection in various tabular formats
func TestPhoneValidator_TabularData(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "CSV Format",
			content: "John Doe,555-123-4567,john@example.com,123 Main St",
		},
		{
			name:    "TSV Format",
			content: "Jane Smith\t555-987-6543\tjane@example.com\t456 Oak Ave",
		},
		{
			name:    "Pipe-Separated",
			content: "Bob Jones | 555-111-2222 | bob@example.com | 789 Elm St",
		},
		{
			name:    "Fixed-Width",
			content: "Alice Brown     555-444-3333    alice@example.com    321 Pine Rd",
		},
		{
			name:    "Semicolon-Separated",
			content: "Charlie Davis; 555-777-8888; charlie@example.com; 654 Maple Dr",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			if len(matches) == 0 {
				t.Errorf("Should detect phone in tabular data: %s", tt.name)
			} else {
				t.Logf("✓ Detected phone in %s: %s (%.0f%% confidence)",
					tt.name, matches[0].Text, matches[0].Confidence)
			}
		})
	}
}

// TestPhoneValidator_ContextAnalysis tests context-based confidence adjustments
func TestPhoneValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		content        string
		expectMatch    bool
		minConfidence  float64
		maxConfidence  float64
		expectedImpact string // "positive", "negative", or "neutral"
	}{
		{
			name:           "Strong Phone Context",
			content:        "Phone number: 555-123-4567",
			expectMatch:    true,
			minConfidence:  50,
			maxConfidence:  100,
			expectedImpact: "positive",
		},
		{
			name:           "Timestamp Context",
			content:        "Timestamp: 1234567890",
			expectMatch:    false,
			minConfidence:  0,
			maxConfidence:  30,
			expectedImpact: "negative",
		},
		{
			name:           "Resource ID Context",
			content:        "Instance ID: i-1234567890abc",
			expectMatch:    false,
			minConfidence:  0,
			maxConfidence:  30,
			expectedImpact: "negative",
		},
		{
			name:           "Neutral Context",
			content:        "The number is 555-123-4567",
			expectMatch:    true,
			minConfidence:  40,
			maxConfidence:  80,
			expectedImpact: "neutral",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			hasMatch := len(matches) > 0

			if hasMatch != tt.expectMatch {
				t.Errorf("Expected match=%v, got=%v", tt.expectMatch, hasMatch)
			}

			if hasMatch && len(matches) > 0 {
				confidence := matches[0].Confidence
				if confidence < tt.minConfidence || confidence > tt.maxConfidence {
					t.Errorf("Confidence %.2f not in expected range [%.2f, %.2f]",
						confidence, tt.minConfidence, tt.maxConfidence)
				}
			}
		})
	}
}

// TestPhoneValidator_RegressionTests tests known issues and edge cases
func TestPhoneValidator_RegressionTests(t *testing.T) {
	validator := NewValidator()

	t.Run("AWS EC2 Instance ID regression", func(t *testing.T) {
		content := "Launch instance i-0570342429318abcd in us-east-1"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}

		if len(matches) > 0 {
			t.Errorf("AWS EC2 instance ID should not be detected as phone, but found %d matches:", len(matches))
			for _, m := range matches {
				t.Logf("  Match: %s (%.0f%% confidence)", m.Text, m.Confidence)
			}
		}
	})

	t.Run("Legitimate phone still detected", func(t *testing.T) {
		content := "For support, call (555) 123-4567"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}

		if len(matches) == 0 {
			t.Errorf("Legitimate phone should be detected")
		}
	})

	t.Run("Unix timestamp not detected as phone", func(t *testing.T) {
		content := "Created at timestamp: 1234567890"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}

		if len(matches) > 0 {
			t.Errorf("Unix timestamp should not be detected as phone")
		}
	})
}
