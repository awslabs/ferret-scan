# Amazon Comprehend PII Validator

This validator uses Amazon Comprehend's machine learning models to detect personally identifiable information (PII) and protected health information (PHI) in text content.

## Overview

Amazon Comprehend is a natural language processing (NLP) service that uses machine learning to find insights and relationships in text. The PII detection feature can identify various types of sensitive information with high accuracy and confidence scores.

## Features

- **AI-Powered Detection**: Uses Amazon's machine learning models for PII detection
- **High Accuracy**: Professional-grade detection with confidence scoring
- **Multiple PII Types**: Detects 20+ types of sensitive information
- **PHI Classification**: Identifies Protected Health Information
- **Risk Assessment**: Provides risk level analysis (HIGH/MEDIUM/LOW)
- **Context Redaction**: Safely displays context with PII redacted

## Detected PII Types

### High-Risk PII
- **SSN**: Social Security Numbers
- **CREDIT_DEBIT_NUMBER**: Credit and debit card numbers
- **AWS_ACCESS_KEY/AWS_SECRET_KEY**: AWS credentials
- **PASSWORD**: Passwords and authentication tokens
- **PIN**: Personal identification numbers
- **PASSPORT**: Passport numbers
- **DRIVER_ID**: Driver's license numbers

### Medium-Risk PII
- **PHONE**: Phone numbers
- **EMAIL**: Email addresses
- **ADDRESS**: Physical addresses
- **DATE_TIME**: Dates and timestamps
- **PERSON/NAME**: Personal names
- **AGE**: Age information

### Additional Types
- **USERNAME**: Usernames and account identifiers
- **URL**: Web addresses
- **IP_ADDRESS**: IP addresses
- **MAC_ADDRESS**: MAC addresses
- **BANK_ACCOUNT_NUMBER**: Bank account numbers
- **BANK_ROUTING**: Bank routing numbers

## Prerequisites

### AWS Configuration
1. **AWS Account**: Active AWS account with billing enabled
2. **AWS Credentials**: Configure using one of these methods:
   ```bash
   # Option 1: AWS CLI
   aws configure

   # Option 2: Environment Variables
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

### IAM Permissions
Your AWS credentials need the following IAM policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "comprehend:DetectPiiEntities"
      ],
      "Resource": "*"
    }
  ]
}
```

### Supported AWS Regions
Comprehend PII detection is available in these regions:
- `us-east-1` (N. Virginia) - Default
- `us-east-2` (Ohio)
- `us-west-2` (Oregon)
- `eu-west-1` (Ireland)
- `ap-southeast-2` (Sydney)
- And others - check AWS documentation for current list

## Usage

### Basic Usage
The Comprehend validator is automatically enabled when using the `--enable-genai` flag:

```bash
# Enable GenAI mode (includes Comprehend PII detection)
./ferret-scan --file document.txt --enable-genai

# Run only Comprehend PII detection
./ferret-scan --file document.txt --enable-genai --checks COMPREHEND_PII

# Specify AWS region
./ferret-scan --file document.txt --enable-genai --textract-region us-west-2
```

### Advanced Usage
```bash
# Debug mode to see processing details and costs
./ferret-scan --file document.txt --enable-genai --debug --checks COMPREHEND_PII

# JSON output with PII detection
./ferret-scan --file *.txt --enable-genai --format json --checks COMPREHEND_PII

# Combine with other validators
./ferret-scan --file document.pdf --enable-genai --checks COMPREHEND_PII,CREDIT_CARD
```

## Cost Information

### Pricing Structure
- **DetectPiiEntities API**: $0.0001 per 100 characters (as of 2024)
- **Billing Unit**: Per 100-character unit
- **Minimum Charge**: 1 unit (100 characters) per request

### Cost Examples
```bash
# 1,000 characters: ~$0.001
./ferret-scan --file small-doc.txt --enable-genai --checks COMPREHEND_PII

# 10,000 characters: ~$0.01
./ferret-scan --file medium-doc.txt --enable-genai --checks COMPREHEND_PII

# 100,000 characters: ~$0.10
./ferret-scan --file large-doc.txt --enable-genai --checks COMPREHEND_PII
```

### Cost Estimation
The validator provides cost estimates in debug mode:
```bash
./ferret-scan --file document.txt --enable-genai --debug --checks COMPREHEND_PII
# Output: [DEBUG] Comprehend estimated cost for document.txt: $0.001234
```

## Integration with Other Features

### Text Extraction Integration
The Comprehend validator works seamlessly with text extraction:

```bash
# Extract text from PDF and analyze with Comprehend
./ferret-scan --file scanned-document.pdf --enable-genai

# Extract text from images via Textract, then analyze with Comprehend
./ferret-scan --file screenshot.png --enable-genai

# Extract text from Office documents and analyze with Comprehend
./ferret-scan --file presentation.pptx --enable-genai --checks COMPREHEND_PII
```

### Confidence Scoring
The validator converts Comprehend's confidence scores (0-1) to percentage scores (0-100):

- **HIGH** (90-100%): Very likely to be PII
- **MEDIUM** (60-89%): Possibly PII
- **LOW** (0-59%): Likely false positive

High-sensitivity PII types receive confidence boosts for better accuracy.

## Output Format

### Text Output
```
PII Detection Results:
===================
File: document.txt
Type: COMPREHEND_PII

HIGH CONFIDENCE MATCHES:
- SSN: [HIDDEN] (95% confidence)
  Context: "Please provide your ... [HIDDEN] ... for verification"

- EMAIL: [HIDDEN] (92% confidence)
  Context: "Contact us at ... [HIDDEN] ... for support"

MEDIUM CONFIDENCE MATCHES:
- PHONE: [HIDDEN] (78% confidence)
  Context: "Call ... [HIDDEN] ... during business hours"
```

### JSON Output
```json
{
  "matches": [
    {
      "type": "PII",
      "subtype": "SSN",
      "value": "[HIDDEN]",
      "confidence": 95,
      "line": 1,
      "column": 45,
      "context": "Please provide your ... [HIDDEN] ... for verification",
      "file_path": "document.txt",
      "description": "Amazon Comprehend detected SSN with 95.2% confidence"
    }
  ]
}
```

## Security Considerations

### Data Transmission
- **Files Sent to AWS**: Text content is transmitted to Amazon Comprehend
- **Temporary Processing**: AWS processes data temporarily for analysis
- **No Data Retention**: Comprehend doesn't store your data after processing
- **Encryption**: Data is encrypted in transit and at rest

### Privacy Protection
- **Context Redaction**: PII is redacted in context display
- **Secure Output**: Sensitive values are masked in output
- **Debug Safety**: Debug output avoids exposing actual PII values

### Best Practices
- **Test Environment**: Test with non-sensitive data first
- **Cost Monitoring**: Set up AWS billing alerts
- **Access Control**: Use IAM roles with minimal required permissions
- **Compliance**: Ensure cloud processing meets your compliance requirements

## Troubleshooting

### Common Issues

#### "AWS credentials not found"
```bash
# Solution: Configure AWS credentials
aws configure
# Or set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
```

#### "Region not supported"
```bash
# Use a supported region
./ferret-scan --file document.txt --enable-genai --textract-region us-east-1
```

#### "Access denied" errors
```bash
# Ensure your IAM user/role has comprehend:DetectPiiEntities permission
# Check AWS IAM console for proper permissions
```

#### "Text too long" errors
- Comprehend has a 5,000 character limit per request
- Large documents are automatically chunked
- Consider splitting very large files

### Debug Information
Enable debug mode for detailed processing information:
```bash
./ferret-scan --file document.txt --enable-genai --debug --checks COMPREHEND_PII
```

Debug output includes:
- AWS credential validation
- Cost estimation
- Processing time
- Number of PII entities found
- Risk level assessment

## Performance Considerations

- **Network Latency**: Processing time depends on internet connection
- **Text Length**: Longer texts take more time to process
- **Concurrent Processing**: Multiple files processed in parallel
- **Rate Limits**: AWS service limits may apply for high-volume usage

## Limitations

1. **Language Support**: Primarily optimized for English text
2. **Character Limit**: 5,000 characters per API request
3. **Context Dependency**: Some PII types require context for accurate detection
4. **Cost Scaling**: Costs increase with text volume
5. **Internet Required**: Requires connection to AWS services

## Integration Examples

### With Configuration Files
```yaml
# ferret.yaml
profiles:
  pii-scan:
    format: json
    checks: COMPREHEND_PII
    confidence_levels: high,medium
    verbose: true
    description: "PII-focused scan using Comprehend"
```

```bash
./ferret-scan --file documents/ --enable-genai --config ferret.yaml --profile pii-scan
```

### With Other Validators
```bash
# Comprehensive sensitive data scan
./ferret-scan --file document.txt --enable-genai --checks COMPREHEND_PII,CREDIT_CARD,SSN

# Focus on financial data
./ferret-scan --file financial-report.pdf --enable-genai --checks COMPREHEND_PII,CREDIT_CARD
```

## Support and Resources

### Documentation
- [AWS Comprehend Documentation](https://docs.aws.amazon.com/comprehend/)
- [Comprehend PII Detection](https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html)
- [AWS Comprehend Pricing](https://aws.amazon.com/comprehend/pricing/)

### Best Practices
- Start with small test files to understand costs
- Use debug mode to monitor processing
- Consider data sensitivity before using cloud services
- Set up AWS cost alerts for budget control
