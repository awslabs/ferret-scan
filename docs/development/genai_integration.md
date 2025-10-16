# GenAI Integration - Amazon AI Services

[← Back to Documentation Index](../README.md)

This document provides comprehensive information about Ferret Scan's AI-powered capabilities using Amazon Web Services, including Textract OCR and Comprehend PII detection.

## Overview

Ferret Scan integrates with multiple Amazon AI services to provide advanced capabilities:

- **Amazon Textract**: Advanced Optical Character Recognition (OCR) for extracting text from images and scanned documents
- **Amazon Comprehend**: Machine learning-powered PII detection for identifying sensitive information in text content

## Key Features

### Amazon Textract OCR
- **High-Accuracy OCR**: Professional-grade text extraction using AWS machine learning models
- **Multi-Format Support**: PDF, PNG, JPEG, TIFF image formats
- **Confidence Scoring**: Each extracted text block includes confidence metrics
- **Cost Estimation**: Provides cost estimates before processing

### Amazon Comprehend PII Detection
- **AI-Powered PII Detection**: Uses machine learning to identify 20+ types of sensitive information
- **High Accuracy**: Professional-grade detection with confidence scoring
- **PHI Classification**: Identifies Protected Health Information
- **Risk Assessment**: Provides risk level analysis (HIGH/MEDIUM/LOW)
- **Context Redaction**: Safely displays context with PII redacted

### Integration Features
- **Seamless Integration**: Works alongside existing text extraction and validation methods
- **Unified Configuration**: Single `--enable-genai` flag enables both services
- **Cost Transparency**: Clear cost information and estimates

## When to Use GenAI Mode

### Ideal Use Cases
- **Scanned Documents**: PDFs created from scanned paper documents
- **Image-Based PDFs**: PDFs containing images of text rather than selectable text
- **Screenshots**: Images containing text that needs to be analyzed
- **Handwritten Documents**: Limited support for clear handwriting
- **Legacy Documents**: Old documents that have been digitized as images

### Not Recommended For
- **Standard Text Files**: Use regular text extraction for .txt, .docx, etc.
- **Cost-Sensitive Scenarios**: Each page/image incurs AWS charges
- **Offline Environments**: Requires internet connection to AWS
- **High-Volume Processing**: Consider costs for large batches

## Prerequisites

### AWS Account Setup
1. **Active AWS Account**: Must have billing enabled
2. **AWS Credentials**: Configure using one of these methods:
   ```bash
   # Option 1: AWS CLI
   aws configure

   # Option 2: Environment Variables
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"

   # Option 3: AWS Credentials File
   # ~/.aws/credentials
   [default]
   aws_access_key_id = your-access-key
   aws_secret_access_key = your-secret-key
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
        "textract:DetectDocumentText"
      ],
      "Resource": "*"
    }
  ]
}
```

### Supported AWS Regions
Textract is available in these regions:
- `us-east-1` (N. Virginia) - Default
- `us-east-2` (Ohio)
- `us-west-2` (Oregon)
- `eu-west-1` (Ireland)
- `ap-southeast-2` (Sydney)
- `ca-central-1` (Canada)
- And others - check AWS documentation for current list

## Usage

### Basic Usage
```bash
# Enable GenAI mode for a single file
./ferret-scan --file scanned-document.pdf --enable-genai

# Process multiple files
./ferret-scan --file *.pdf --enable-genai

# Specify AWS region
./ferret-scan --file image.png --enable-genai --textract-region us-west-2
```

### Advanced Usage
```bash
# Combine with other options
./ferret-scan --file documents/ --enable-genai --recursive --format json --confidence high

# Debug mode to see processing details
./ferret-scan --file scanned.pdf --enable-genai --debug

# Use with specific checks
./ferret-scan --file image.jpg --enable-genai --checks CREDIT_CARD,SSN
```

### Configuration File
```yaml
# ferret.yaml
defaults:
  enable_preprocessors: true

preprocessors:
  textract:
    enabled: false  # Still requires --enable-genai flag
    region: us-east-1

profiles:
  genai:
    format: text
    confidence_levels: all
    checks: all
    verbose: true
    recursive: true
    description: "GenAI mode with Textract OCR"
```

## Cost Information

### Pricing Structure
- **DetectDocumentText API**: $0.0015 per page/image (as of 2024)
- **Billing Unit**: Per page for PDFs, per image for image files
- **Region Variations**: Prices may vary slightly by AWS region

### Cost Examples
```bash
# Single image: ~$0.0015
./ferret-scan --file screenshot.png --enable-genai

# 10-page PDF: ~$0.015
./ferret-scan --file document.pdf --enable-genai

# 100 images: ~$0.15
./ferret-scan --file *.jpg --enable-genai
```

### Cost Estimation
The tool provides cost estimates in debug mode:
```bash
./ferret-scan --file document.pdf --enable-genai --debug
# Output: [DEBUG] Textract estimated cost for document.pdf: $0.0045
```

## Technical Details

### File Size Limits
- **Images**: Maximum 10MB per file
- **PDFs**: Maximum 500MB per file
- **Pages**: DetectDocumentText processes single pages

### Supported Formats
| Format | Extension | Max Size | Notes |
|--------|-----------|----------|-------|
| PDF | .pdf | 500MB | Scanned or image-based PDFs |
| PNG | .png | 10MB | Lossless image format |
| JPEG | .jpg, .jpeg | 10MB | Compressed images |
| TIFF | .tiff, .tif | 10MB | High-quality images |

### Processing Flow
1. **File Validation**: Check format and size limits
2. **AWS Authentication**: Validate credentials and permissions
3. **Cost Estimation**: Calculate approximate processing cost
4. **Upload to Textract**: Send file to AWS service
5. **Text Extraction**: Process with OCR algorithms
6. **Result Processing**: Parse and format extracted text
7. **Confidence Analysis**: Evaluate extraction quality

## Integration Architecture

### Preprocessor Pipeline
```
Input File → Format Check → Textract Preprocessor → Text Extraction → Validation
```

### Fallback Behavior
- If Textract fails, processing continues with standard methods
- Error messages are logged but don't stop the scan
- Mixed processing: some files via Textract, others via standard extraction

### Priority Order
1. **GenAI Enabled**: Textract preprocessor takes precedence for supported formats
2. **Standard Extraction**: Used for unsupported formats or when GenAI is disabled
3. **Metadata Only**: Falls back to metadata extraction if text extraction fails

## Security Considerations

### Data Transmission
- **Files Sent to AWS**: Your documents are transmitted to Amazon's servers
- **Temporary Storage**: AWS may temporarily store files during processing
- **Data Retention**: Check AWS Textract data retention policies
- **Encryption**: Data is encrypted in transit and at rest

### Best Practices
- **Sensitive Data**: Consider data sensitivity before using cloud OCR
- **Compliance**: Ensure cloud processing meets your compliance requirements
- **Access Control**: Use IAM roles with minimal required permissions
- **Audit Logging**: Enable CloudTrail for API call auditing

### Risk Mitigation
- **Test Environment**: Test with non-sensitive data first
- **Cost Monitoring**: Set up AWS billing alerts
- **Error Handling**: Implement proper error handling for failed requests
- **Credential Security**: Secure AWS credentials appropriately

## Troubleshooting

### Common Issues

#### "AWS credentials not found"
```bash
# Solution 1: Configure AWS CLI
aws configure

# Solution 2: Set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"

# Solution 3: Check credentials file
cat ~/.aws/credentials
```

#### "Region not supported"
```bash
# Use a supported region
./ferret-scan --file image.png --enable-genai --textract-region us-east-1
```

#### "File too large"
```bash
# Reduce file size or split large PDFs
# For images: reduce resolution
# For PDFs: split into smaller files
```

#### "Low confidence scores"
- **Improve Image Quality**: Use higher resolution, better lighting
- **Check Orientation**: Ensure text is right-side up
- **Clean Images**: Remove noise, improve contrast
- **Font Clarity**: Ensure text is clearly visible

### Debug Information
Enable debug mode for detailed processing information:
```bash
./ferret-scan --file document.pdf --enable-genai --debug
```

Debug output includes:
- AWS credential validation
- Cost estimation
- Processing time
- Confidence scores
- Error details

### Performance Optimization
- **Batch Processing**: Process multiple files in one command
- **Region Selection**: Use the closest AWS region
- **File Optimization**: Optimize image quality vs. file size
- **Concurrent Processing**: Tool supports parallel processing

## Monitoring and Logging

### AWS CloudWatch
Monitor Textract usage through AWS CloudWatch:
- API call counts
- Error rates
- Processing times
- Cost tracking

### Application Logs
Ferret Scan provides detailed logging:
```bash
# Enable debug logging
./ferret-scan --file document.pdf --enable-genai --debug 2> ferret.log

# View processing details
tail -f ferret.log
```

## Future Enhancements

### Planned Features
- **Multi-page PDF Support**: Process all pages in large PDFs
- **Batch Cost Optimization**: Optimize costs for large batches
- **Result Caching**: Cache results to avoid reprocessing
- **Additional OCR Providers**: Support for other OCR services

### Configuration Enhancements
- **Cost Limits**: Set maximum cost thresholds
- **Quality Thresholds**: Set minimum confidence requirements
- **Format Preferences**: Prefer certain extraction methods

## Support and Resources

### Documentation
- [AWS Textract Documentation](https://docs.aws.amazon.com/textract/)
- [AWS Textract Pricing](https://aws.amazon.com/textract/pricing/)
- [Ferret Scan Main Documentation](../README.md)

### Community
- Report issues on the project's GitHub repository
- Join discussions about OCR integration
- Share best practices and use cases

### AWS Support
- AWS Support plans for production usage
- AWS Forums for community support
- AWS Documentation for technical details
