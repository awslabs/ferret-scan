// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import "fmt"

// GetHelp returns help information for the secrets validator
func GetHelp() string {
	return fmt.Sprintf(`
Secrets Validator - Detects API keys, tokens, and other secrets

DETECTION METHODS:
• High Entropy Strings: Uses Shannon entropy analysis to detect random-looking strings
• Keyword Patterns: Searches for common secret keywords with associated values
• Specific Pattern Recognition: Identifies known secret formats and structures

ENTROPY ANALYSIS:
• Base64 strings: Entropy threshold %.1f (20+ characters)
• Hex strings: Entropy threshold %.1f (16+ characters)
• Analyzes character distribution to identify cryptographic material

SUPPORTED SECRET TYPES:
• SSH_PRIVATE_KEY - SSH private keys and certificates
• CERTIFICATE - X.509 certificates and encrypted private keys  
• JWT_TOKEN - JSON Web Tokens (eyJ...)
• AWS_ACCESS_KEY - Amazon Web Services access keys (AKIA...)
• GITHUB_TOKEN - GitHub personal access tokens (ghp_, gho_, etc.)
• GOOGLE_CLOUD_API_KEY - Google Cloud Platform API keys (AIza...)
• STRIPE_API_KEY - Stripe payment processing API keys (sk_live_, pk_live_, etc.)
• GITLAB_TOKEN - GitLab personal access tokens (glpat-...)
• DOCKER_TOKEN - Docker Hub personal access tokens (dckr_pat_...)
• SLACK_TOKEN - Slack bot and user tokens (xoxb-, xoxp-)
• PGP_PRIVATE_KEY - PGP/GPG private keys
• API_KEY_OR_SECRET - Generic high-entropy secrets and API keys

KEYWORD DETECTION:
Searches for patterns like:
• api_key = "value"
• "password": "value"
• auth_token = "value"
• private_key: "[PRIVATE_KEY_VALUE]"

SUPPORTED KEYWORDS:
• API keys: api_key, auth_key, service_key, client_key
• Passwords: password, passwd, pwd
• Tokens: token, bearer, oauth, jwt, access_token
• Credentials: secret, credential, private, session

CONFIDENCE SCORING:
• HIGH (90-100%%): Strong entropy + keyword context or specific pattern match
• MEDIUM (60-89%%): Good entropy or keyword match
• LOW (40-59%%): Weak signals or test data patterns

CONTEXT ANALYSIS:
Positive indicators: api, key, secret, token, auth, credential
Negative indicators: test, example, demo, sample, fake, mock

EXAMPLES:
✓ api_key = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6" → STRIPE_API_KEY
✓ "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." → JWT_TOKEN
✓ private_key = "[SSH PRIVATE KEY CONTENT]" → SSH_PRIVATE_KEY
✓ "AKIAIOSFODNN7EXAMPLE" → AWS_ACCESS_KEY
✗ password = "test123" (test data)
✗ api_key = "your_key_here" (placeholder)

MEMORY SECURITY:
• Detected secrets are stored in secure memory structures
• Memory is cleared after processing to minimize exposure
• Multiple overwrite passes for sensitive data cleanup
`, 4.5, 3.0)
}
