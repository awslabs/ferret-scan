# Enhanced Secrets Validator

The Enhanced Secrets Validator detects API keys, tokens, passwords, and other sensitive credentials using advanced techniques inspired by the [detect-secrets](https://github.com/Yelp/detect-secrets) project, enhanced with context analysis, environment detection, and intelligent pattern learning.

## Advanced Detection Methods

### 1. High Entropy String Analysis with Statistical Validation

Uses Shannon entropy to identify random-looking strings that are likely to be cryptographic material:

- **Base64 strings**: Entropy threshold 4.5, minimum 20 characters
- **Hex strings**: Entropy threshold 3.0, minimum 16 characters
- **Statistical validation**: Analyzes character distribution patterns
- **Context-aware entropy**: Adjusts thresholds based on document context

### 2. Enhanced Keyword Pattern Matching

Searches for common secret keywords followed by values with context understanding:

```
api_key = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6"
"password": "super_secret_password_123"
auth_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 3. Environment Detection & Context Analysis 🚀

**Automatic Environment Recognition:**
- **Development Environment**: Detects dev/staging keywords, applies -15% confidence penalty
- **Production Environment**: Identifies prod/live keywords, applies +10% confidence boost
- **Test Environment**: Recognizes test patterns, applies -25% confidence penalty

**Domain-Specific Intelligence:**
- **Financial Domain**: +12% confidence boost for API keys (higher likelihood)
- **Healthcare Domain**: Variable adjustments based on secret type
- **Document Type Analysis**: Configuration files (+15%), Code files (+8%), JSON/YAML (+12%)

### 4. Global Test Pattern Database

**Comprehensive Test Secret Detection:**
- 16+ common test patterns: `test_api_key_here`, `your_api_key_here`, `example_secret_key`
- Pattern variations: `abcdef123456789`, `xxxxxxxxxxxxxxxx`, `replace_with_actual`
- Documentation patterns: `tutorial_secret`, `readme_example`, `documentation_key`
- **Impact**: -35% confidence penalty for matches

## Supported Secret Types

The validator now identifies specific secret types and displays them in the TYPE column for better categorization:

### **Cryptographic Keys (High Confidence: 95-96%)**

The validator detects various cryptographic key formats:
- **SSH_PRIVATE_KEY** - SSH private key detection
- **CERTIFICATE** - Certificate and private key detection  
- **PGP_PRIVATE_KEY** - PGP private key detection

### **Cloud Provider API Keys (High Confidence: 94-95%)**
- **AWS_ACCESS_KEY** - `AKIA[0-9A-Z]{16}` (Amazon Web Services)
- **GOOGLE_CLOUD_API_KEY** - `AIza[0-9A-Za-z_-]{35}` (Google Cloud Platform)

### **Development Platform Tokens (High Confidence: 92-94%)**
- **GITHUB_TOKEN** - `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 characters
- **GITLAB_TOKEN** - `glpat-[a-zA-Z0-9_-]{20}` (GitLab Personal Access Tokens)
- **DOCKER_TOKEN** - `dckr_pat_[a-zA-Z0-9_-]{36}` (Docker Hub Personal Access Tokens)
- **SLACK_TOKEN** - `xoxb-` or `xoxp-` + structured format

### **Payment Processing Keys (High Confidence: 95%)**
- **STRIPE_API_KEY** - `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_` + 24 characters

### **Authentication Tokens (High Confidence: 92%)**
- **JWT_TOKEN** - `eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` (JSON Web Tokens)



### **Generic Secrets (Medium-High Confidence: 60-85%)**
- **API Keys** - Keyword patterns like `api_key = "value"`
- **Passwords** - Password fields like `"password": "value"`
- **Tokens** - Authentication tokens with keyword patterns
- **High Entropy Strings** - Base64 (4.5+ entropy, 20+ chars) and Hex (3.0+ entropy, 16+ chars)

## Detection Capabilities

### High Entropy Detection
- **Shannon Entropy Calculation**: Measures randomness in character distribution
- **Charset-Specific Analysis**: Different thresholds for base64 vs hex strings
- **Length Filtering**: Minimum lengths to reduce false positives
- **Quote Detection**: Focuses on quoted strings to reduce noise

### Keyword Pattern Detection
- **Assignment Patterns**: `keyword = "value"`
- **JSON/YAML Patterns**: `"keyword": "value"`
- **Case Insensitive**: Matches regardless of case
- **Flexible Separators**: Handles various assignment operators

## Confidence Scoring

### Base Confidence (85%)
Starting confidence level for detected patterns.

### Positive Factors
- **High Entropy**: +0-15% based on Shannon entropy score
- **Keyword Context**: +5-10% for relevant keywords nearby
- **Proper Format**: +0% (maintains base confidence)

### Negative Factors
- **Short Length**: -30% for strings under 8 characters
- **Common Words**: -20% for containing "password", "secret", etc.
- **Low Entropy**: -25% for entropy below threshold
- **Test Patterns**: -30% for "test", "demo", "example", etc.
- **Invalid Format**: -15% for containing spaces or tabs

### Context Analysis
- **Positive Keywords**: api, key, secret, token, auth, credential
- **Negative Keywords**: test, example, demo, sample, fake, mock

## Implementation Details

### Memory Security
- Uses `SecureString` for sensitive data storage
- Multiple memory overwrite passes during cleanup
- Automatic memory clearing after processing

### Pattern Compilation
- Pre-compiled regex patterns for performance
- Optimized for common secret formats
- Flexible keyword matching with optional separators

### Entropy Calculation
```go
entropy := 0.0
for _, char := range charset {
    count := strings.Count(data, string(char))
    if count > 0 {
        p := float64(count) / float64(len(data))
        entropy += -p * math.Log2(p)
    }
}
```

## Usage Examples

### Command Line
```bash
# Scan for secrets in a file
./ferret-scan --file config.json --checks SECRETS

# High confidence secrets only
./ferret-scan --file .env --checks SECRETS --confidence high

# Verbose output with entropy scores
./ferret-scan --file app.py --checks SECRETS --verbose
```

### Configuration File
```yaml
profiles:
  security-audit:
    checks: SECRETS
    confidence_levels: high,medium
    verbose: true
    description: "Security audit focusing on secrets detection"
```

## Detection Examples

### ✅ Detected Secrets

```bash
# Cloud Service Keys
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GOOGLE_API_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLan_Qkby0Oc-0
STRIPE_SECRET_KEY=sk_live_1234567890abcdef1234567890abcdef

# Platform Tokens
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef123456
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
SLACK_BOT_TOKEN=xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx
DOCKER_TOKEN=dckr_pat_1234567890abcdef1234567890abcdef123456

# JWT Tokens
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# SSH Private Keys
-----BEGIN [EXAMPLE] PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8xtarhDdXMCbVvdaZ
[... truncated for security ...]
-----END [EXAMPLE] PRIVATE KEY-----

# Generic API Keys
api_key = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6rQqXYZ1234567890abcdef"
db_password = "P@ssw0rd!2023_SecureDB"
```

### ❌ Ignored Patterns

```javascript
// Test data
api_key = "test_key_123"

// Placeholder values
password = "your_password_here"

// Short strings
token = "abc123"

// Common words
secret = "password"
```

## Performance Considerations

- **Regex Optimization**: Pre-compiled patterns for better performance
- **Entropy Caching**: Calculated once per unique string
- **Context Limiting**: Bounded context analysis to prevent slowdowns
- **Memory Efficient**: Streaming file processing for large files

## Security Features

- **Memory Scrubbing**: Sensitive data cleared from memory after processing
- **Secure Storage**: Uses controlled byte slices instead of strings
- **Minimal Exposure**: Reduces time sensitive data remains in memory
- **Multiple Overwrites**: Paranoid memory clearing with multiple passes

## Integration

The Secrets Validator integrates seamlessly with:
- **CLI Tool**: Available via `--checks SECRETS`
- **Web UI**: Accessible through the web interface
- **Configuration**: Supports profile-based configuration
- **Suppressions**: Compatible with the suppression system
- **GenAI**: Works with preprocessed content from AI services
