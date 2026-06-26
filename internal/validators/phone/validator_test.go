package phone

import (
	"strings"
	"testing"
	"time"
)

// TestPhoneValidator_SingleLineDoSRegression guards against the O(n^2) blowup
// that previously made ValidateContent take minutes on a single very long line
// densely packed with phone-like matches (no newlines). The pathological costs
// were: a per-match strings.Index(line, match) rescan, an O(M^2) dedup that
// re-ran the clean regex over every accepted match, and a per-match
// strings.ToLower(line) + whole-line keyword scan. The fix makes the work linear
// in the input size.
//
// The bound is intentionally generous (well above the observed ~1s on this
// machine) so it catches an algorithmic regression without being flaky on slow
// CI. Before the fix this same input did not finish within 600s.
func TestPhoneValidator_SingleLineDoSRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}

	v := NewValidator()

	// Build a single ~1MB line (no '\n') packed with many distinct dashed phone
	// numbers separated by spaces. Distinct numbers force the dedup path to do
	// real comparison work, and the absence of newlines is the worst case (all
	// matches land on one line).
	const targetBytes = 1 << 20
	var b strings.Builder
	b.Grow(targetBytes + 32)
	b.WriteString("contact ")
	for i := 0; b.Len() < targetBytes; i++ {
		a := 200 + (i % 700)
		b.WriteString("555-")
		b.WriteByte(byte('0' + (a/100)%10))
		b.WriteByte(byte('0' + (a/10)%10))
		b.WriteByte(byte('0' + a%10))
		b.WriteByte('-')
		b.WriteByte(byte('0' + (i/1000)%10))
		b.WriteByte(byte('0' + (i/100)%10))
		b.WriteByte(byte('0' + (i/10)%10))
		b.WriteByte(byte('0' + i%10))
		b.WriteByte(' ')
	}
	content := b.String()
	if strings.Contains(content, "\n") {
		t.Fatalf("worst-case input must be a single line")
	}

	const ceiling = 5 * time.Second
	start := time.Now()
	matches, err := v.ValidateContent(content, "worstcase.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if raceEnabled {
		// -race inflates wall-clock 5-20x; the scan ran above (so -race checks
		// for data races), but the timing ceiling is skipped.
		t.Logf("processed %d-byte single line, found %d matches (timing assertion skipped under -race)", len(content), len(matches))
		return
	}
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a %d-byte single line took %s, exceeding the %s ceiling (likely an O(n^2) regression)",
			len(content), elapsed, ceiling)
	}
	t.Logf("processed %d-byte single line in %s, found %d matches", len(content), elapsed, len(matches))
}

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
			// "number" was removed from negativeKeywords (L28) — it collides with
			// legitimate phone context and tabular contact data, so it no longer
			// applies a penalty. A valid-looking number with no real negative
			// signal now scores high, as it should.
			name:           "Neutral Context",
			content:        "The entry is 555-123-4567",
			expectMatch:    true,
			minConfidence:  40,
			maxConfidence:  100,
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

// TestPhoneValidator_NANPAreaCodesNotTimestamps is a regression test for M6/M12:
// formatted NANP numbers in area codes 200-214 (and 19xx/20xx long forms) were
// penalized -60 as Unix timestamps/dates. The timestamp heuristic now only fires
// on a bare digit run with no phone separators.
func TestPhoneValidator_NANPAreaCodesNotTimestamps(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"call (212) 555-0173 now",
		"Phone: (202) 555-0173",
		"contact 213-555-0173",
		"phone 201-998-7654",
	} {
		matches, _ := v.ValidateContent(line, "test.txt")
		var best float64
		for _, m := range matches {
			if m.Confidence > best {
				best = m.Confidence
			}
		}
		if best < 60 {
			t.Errorf("formatted NANP number in %q should reach MEDIUM, got %.1f", line, best)
		}
	}
	// A bare 10-digit run with no separators may still be treated as a timestamp.
	if !v.looksLikeTimestamp("2125550173") {
		t.Error("a bare 10-digit run should still be eligible as a timestamp")
	}
	if v.looksLikeTimestamp("(212) 555-0173") {
		t.Error("a separator-formatted phone must not be treated as a timestamp")
	}
}

// TestPhoneValidator_UKNationalThreeGroup is a regression test for M8/M9: a
// full UK national number (area + two subscriber groups) was truncated to two
// groups and the leading-0 form was penalized as invalid.
func TestPhoneValidator_UKNationalThreeGroup(t *testing.T) {
	v := NewValidator()
	matches, _ := v.ValidateContent("ring 0161 496 0345 today", "test.txt")
	found := false
	for _, m := range matches {
		if m.Text == "0161 496 0345" {
			found = true
		}
	}
	if !found {
		got := make([]string, 0, len(matches))
		for _, m := range matches {
			got = append(got, m.Text)
		}
		t.Errorf("full UK number '0161 496 0345' should be captured whole, got %v", got)
	}
}

// TestPhoneValidator_VersionStringNotPhone is a regression test for M10: dotted,
// "+"-prefixed version tags ("+2024.1.1", "+1.2.3.4") matched as international
// phone numbers.
func TestPhoneValidator_VersionStringNotPhone(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{"git tag +2024.1.1 released", "version +1.2.3.4 here"} {
		matches, _ := v.ValidateContent(line, "test.txt")
		if len(matches) > 0 {
			t.Errorf("version string %q should not match as a phone, got %d", line, len(matches))
		}
	}
	// Real international numbers still match.
	if m, _ := v.ValidateContent("call +44 20 7946 0958 now", "test.txt"); len(m) == 0 {
		t.Error("real international number should still be detected")
	}
}

// TestPhoneValidator_NoDuplicatePartials is a regression test for M11:
// overlapping patterns emitted a truncated partial of the same number alongside
// the full match.
func TestPhoneValidator_NoDuplicatePartials(t *testing.T) {
	v := NewValidator()
	matches, _ := v.ValidateContent("Reach me +44 20 7946 0958 today", "test.txt")
	if len(matches) != 1 {
		got := make([]string, 0, len(matches))
		for _, m := range matches {
			got = append(got, m.Text)
		}
		t.Errorf("expected a single match for one phone number, got %d: %v", len(matches), got)
	}
}

// TestPhoneValidator_LowSeverityFindings covers three LOW-severity fixes:
// L28 generic words (number/name/id/account) removed from negativeKeywords;
// L29 test-pattern matching anchored to the full number (not short fragments);
// L30 a bare leading "1" country code is stripped for US/CA format validation.
func TestPhoneValidator_LowSeverityFindings(t *testing.T) {
	v := NewValidator()

	// L28: legitimate "phone number"/contact-record context must not demote.
	for _, line := range []string{
		"Phone number: 415-555-2671",
		"name, id, account, phone 415-555-2671",
	} {
		matches, _ := v.ValidateContent(line, "test.txt")
		var best float64
		for _, m := range matches {
			if m.Confidence > best {
				best = m.Confidence
			}
		}
		if best < 60 {
			t.Errorf("L28: %q should stay MEDIUM/HIGH, got %.1f", line, best)
		}
	}

	// L29: real numbers that merely contain a test fragment are not test numbers;
	// full known test numbers and the fictional 555-01xx range still are.
	for _, real := range []string{"415-123-4567", "303-987-6543"} {
		if v.isTestPhoneNumber(real) {
			t.Errorf("L29: %s is a real number, not a test number", real)
		}
	}
	for _, test := range []string{"555-0100", "123-456-7890"} {
		if !v.isTestPhoneNumber(test) {
			t.Errorf("L29: %s should still be recognized as a test number", test)
		}
	}

	// L30: a bare leading "1" must be stripped for US/CA 10-digit validation.
	if !v.isValidCountryFormat("1-800-555-1234", phonePattern{country: "US/CA"}) {
		t.Error("L30: bare-1 toll-free number should be a valid US/CA format")
	}
}
