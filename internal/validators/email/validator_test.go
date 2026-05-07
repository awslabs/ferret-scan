package email

import (
	"testing"

	"ferret-scan/internal/detector"
)

func TestEmailValidator_URLStructureDetection(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		// URL/URI patterns (should NOT match as emails)
		{
			name:        "Git SSH with colon-path",
			content:     "git clone git@github.com:user/repo.git",
			expectMatch: false,
			description: "Git SSH URL with colon-path should be filtered",
		},
		{
			name:        "Git SSH AWS CodeCommit",
			content:     "git clone git@github.com:awslabs/aws-ssm-cli.git",
			expectMatch: false,
			description: "AWS CodeCommit SSH URL should be filtered",
		},
		{
			name:        "SCP command",
			content:     "scp user@server.com:/path/to/file.txt .",
			expectMatch: false,
			description: "SCP command with colon-path should be filtered",
		},
		{
			name:        "SSH with port",
			content:     "ssh user@host.com:22",
			expectMatch: false,
			description: "SSH with port number should be filtered",
		},
		{
			name:        "PostgreSQL connection",
			content:     "postgres://user@localhost:5432/database",
			expectMatch: false,
			description: "Database connection string should be filtered",
		},
		{
			name:        "SFTP URL",
			content:     "sftp://admin@server.com/uploads",
			expectMatch: false,
			description: "SFTP URL with slash should be filtered",
		},
		{
			name:        "Rsync command",
			content:     "rsync -av user@remote.com:/backup/ /local/",
			expectMatch: false,
			description: "Rsync with colon-path should be filtered",
		},
		{
			name:        "Docker registry",
			content:     "docker pull registry.io/user@image:latest",
			expectMatch: false,
			description: "Docker registry with colon should be filtered",
		},
		{
			name:        "MongoDB connection",
			content:     "mongodb://admin@db.server.com:27017/mydb",
			expectMatch: false,
			description: "MongoDB connection string should be filtered",
		},

		// Email patterns (SHOULD match)
		{
			name:        "Email with space after",
			content:     "Contact: support@company.com for help",
			expectMatch: true,
			description: "Email followed by space should match",
		},
		{
			name:        "Email with comma",
			content:     "Send to: alice@company.com, bob@company.com",
			expectMatch: true,
			description: "Email in comma-separated list should match",
		},
		{
			name:        "Email at end of sentence",
			content:     "Email us at support@example.com.",
			expectMatch: true,
			description: "Email at end of sentence should match",
		},
		{
			name:        "Email in parentheses",
			content:     "John Doe (john.doe@company.com) will attend",
			expectMatch: true,
			description: "Email in parentheses should match",
		},
		{
			name:        "Email with semicolon",
			content:     "Recipients: admin@site.com; support@site.com",
			expectMatch: true,
			description: "Email with semicolon separator should match",
		},
		{
			name:        "Email at end of line",
			content:     "Contact: webmaster@domain.org",
			expectMatch: true,
			description: "Email at end of line should match",
		},
		{
			name:        "Email in brackets",
			content:     "Team [team@company.com] is responsible",
			expectMatch: true,
			description: "Email in brackets should match",
		},
		{
			name:        "Email with exclamation",
			content:     "Write to sales@company.com!",
			expectMatch: true,
			description: "Email with exclamation should match",
		},

		// Edge cases
		{
			name:        "Git user without colon",
			content:     "The git user is git@server.com for authentication",
			expectMatch: true,
			description: "git@ without colon is legitimate email",
		},
		{
			name:        "Email in markdown link",
			content:     "[Contact](mailto:info@company.com)",
			expectMatch: true,
			description: "Email in markdown should match",
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

func TestEmailValidator_StructuralAnalysis(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		match    string
		line     string
		expected bool
	}{
		// URL structures
		{"git@github.com", "git clone git@github.com:user/repo", true},
		{"user@host.com", "scp user@host.com:/path/file", true},
		{"admin@server.com", "ssh admin@server.com:22", true},
		{"user@db.com", "postgres://user@db.com:5432/db", true},
		{"user@server.com", "sftp://user@server.com/path", true},

		// Email structures
		{"support@company.com", "Contact: support@company.com for help", false},
		{"alice@example.com", "Email: alice@example.com, bob@example.com", false},
		{"info@domain.org", "Write to info@domain.org.", false},
		{"team@company.com", "Team (team@company.com) responsible", false},
		{"admin@site.com", "Admin: admin@site.com;", false},
	}

	for _, tt := range tests {
		t.Run(tt.match+" in "+tt.line, func(t *testing.T) {
			result := validator.hasURLStructure(tt.match, tt.line)
			if result != tt.expected {
				t.Errorf("hasURLStructure(%q, %q) = %v, want %v",
					tt.match, tt.line, result, tt.expected)
			}
		})
	}
}

func TestEmailValidator_ConfidenceCalculation(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name             string
		email            string
		minConfidence    float64
		maxConfidence    float64
		shouldPassChecks []string
		shouldFailChecks []string
	}{
		{
			name:          "Valid business email",
			email:         "john.doe@company.com",
			minConfidence: 40, // Adjusted: base confidence without context
			maxConfidence: 100,
			shouldPassChecks: []string{
				"valid_format", "valid_domain", "valid_tld",
				"reasonable_length",
			},
		},
		{
			name:             "Test email",
			email:            "test@example.com",
			minConfidence:    0,
			maxConfidence:    80,
			shouldFailChecks: []string{"not_test_email"},
		},
		{
			name:             "Invalid TLD",
			email:            "user@domain.invalidtld",
			minConfidence:    0,
			maxConfidence:    90,
			shouldFailChecks: []string{"valid_tld"},
		},
		{
			name:             "Consecutive dots",
			email:            "user..name@domain.com",
			minConfidence:    0,
			maxConfidence:    95,
			shouldFailChecks: []string{"no_consecutive_dots"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, checks := validator.CalculateConfidence(tt.email)

			if confidence < tt.minConfidence || confidence > tt.maxConfidence {
				t.Errorf("Confidence %.2f not in range [%.2f, %.2f]",
					confidence, tt.minConfidence, tt.maxConfidence)
			}

			for _, checkName := range tt.shouldPassChecks {
				if !checks[checkName] {
					t.Errorf("Check %q should pass but failed", checkName)
				}
			}

			for _, checkName := range tt.shouldFailChecks {
				if checks[checkName] {
					t.Errorf("Check %q should fail but passed", checkName)
				}
			}
		})
	}
}

func TestEmailValidator_ContextAnalysis(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name           string
		match          string
		line           string
		expectedImpact string // "positive", "negative", or "neutral"
	}{
		{
			name:           "Email keyword in context",
			match:          "support@company.com",
			line:           "For email support contact support@company.com",
			expectedImpact: "positive",
		},
		{
			name:           "Git clone context",
			match:          "git@github.com",
			line:           "git clone git@github.com:user/repo",
			expectedImpact: "negative",
		},
		{
			name:           "Test keyword in context",
			match:          "user@domain.com",
			line:           "This is a test email: user@domain.com",
			expectedImpact: "negative",
		},
		{
			name:           "Neutral context",
			match:          "info@company.com",
			line:           "The address is info@company.com",
			expectedImpact: "positive", // "address" is a positive keyword
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			context := detector.ContextInfo{
				FullLine: tt.line,
			}

			impact := validator.AnalyzeContext(tt.match, context)

			switch tt.expectedImpact {
			case "positive":
				if impact <= 0 {
					t.Errorf("Expected positive impact, got %.2f", impact)
				}
			case "negative":
				if impact >= 0 {
					t.Errorf("Expected negative impact, got %.2f", impact)
				}
			case "neutral":
				if impact < -10 || impact > 10 {
					t.Errorf("Expected neutral impact (-10 to 10), got %.2f", impact)
				}
			}
		})
	}
}

func TestEmailValidator_RegressionTests(t *testing.T) {
	validator := NewValidator()

	// Regression test for reported issue
	t.Run("AWS CodeCommit SSH URL regression", func(t *testing.T) {
		content := "git clone git@github.com:awslabs/aws-ssm-cli.git"
		matches, err := validator.ValidateContent(content, "README.md")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}

		if len(matches) > 0 {
			t.Errorf("AWS CodeCommit SSH URL should not be detected as email, but found %d matches:", len(matches))
			for _, m := range matches {
				t.Logf("  Match: %s (%.0f%% confidence)", m.Text, m.Confidence)
			}
		}
	})

	// Additional regression tests
	t.Run("GitHub SSH URL", func(t *testing.T) {
		content := "git clone git@github.com:user/repo.git"
		matches, err := validator.ValidateContent(content, "README.md")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}

		if len(matches) > 0 {
			t.Errorf("GitHub SSH URL should not be detected as email")
		}
	})

	t.Run("Legitimate email still detected", func(t *testing.T) {
		content := "For support, contact: support@company.com"
		matches, err := validator.ValidateContent(content, "README.md")
		if err != nil {
			t.Fatalf("ValidateContent() error = %v", err)
		}

		if len(matches) == 0 {
			t.Errorf("Legitimate email should be detected")
		}
	})
}
