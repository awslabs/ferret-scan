# Amazon Textract Text Extractor Library

This library provides text extraction capabilities using Amazon Textract OCR service for images and scanned documents.

## Overview

Amazon Textract is a machine learning service that automatically extracts text and data from scanned documents. This library integrates Textract into the Ferret Scan preprocessing pipeline to enable text extraction from:

- PDF documents (scanned or image-based)
- PNG images
- JPEG images
- TIFF images

## Features

- **OCR Text Extraction**: Extract text from images and scanned documents
- **Confidence Scoring**: Provides confidence levels for extracted text
- **Cost Estimation**: Estimates AWS costs before processing
- **AWS Integration**: Uses AWS SDK with standard credential providers
- **Multi-format Support**: Handles PDF, PNG, JPEG, and TIFF formats

## Prerequisites

### AWS Configuration

1. **AWS Credentials**: Configure AWS credentials using one of these methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
   - AWS credentials file

2. **IAM Permissions**: Ensure your AWS credentials have the following permission:
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

3. **AWS Region**: Textract is available in specific AWS regions. Supported regions include:
   - us-east-1 (N. Virginia)
   - us-east-2 (Ohio)
   - us-west-2 (Oregon)
   - eu-west-1 (Ireland)
   - ap-southeast-2 (Sydney)
   - And others - check AWS documentation for current list

## Usage

### Basic Text Extraction

```go
import "ferret-scan/internal/preprocessors/text-extractors/textract-extractor-lib"

// Extract text from an image
content, err := textract_extractor_lib.ExtractText("document.pdf", "us-east-1")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Extracted text: %s\n", content.Text)
fmt.Printf("Confidence: %.2f%%\n", content.Confidence)
```

### Check File Support

```go
if textract_extractor_lib.IsSupportedFileType("image.png") {
    // Process the file
}
```

### Validate AWS Setup

```go
err := textract_extractor_lib.ValidateAWSCredentials("us-east-1")
if err != nil {
    log.Printf("AWS setup issue: %v", err)
}
```

### Cost Estimation

```go
cost, err := textract_extractor_lib.EstimateTextractCost("document.pdf")
if err == nil {
    fmt.Printf("Estimated cost: $%.4f\n", cost)
}
```

## Supported File Types

| Format | Extension | Notes |
|--------|-----------|-------|
| PDF | .pdf | Scanned or image-based PDFs |
| PNG | .png | Lossless image format |
| JPEG | .jpg, .jpeg | Compressed image format |
| TIFF | .tiff, .tif | High-quality image format |

## Pricing Information

Amazon Textract charges per page/image processed:
- **DetectDocumentText**: $0.0015 per page (as of 2024)
- Pricing may vary by region
- Check [AWS Textract Pricing](https://aws.amazon.com/textract/pricing/) for current rates

**Cost Examples:**
- Single image: ~$0.0015
- 10-page PDF: ~$0.015
- 100-page document: ~$0.15

## Error Handling

The library handles various error conditions:

- **File not found**: Returns file system error
- **Unsupported format**: Check with `IsSupportedFileType()`
- **AWS credential issues**: Use `ValidateAWSCredentials()`
- **Network/API errors**: Returns Textract service errors
- **Large files**: Textract has size limits (10MB for images, 500MB for PDFs)

## Limitations

1. **File Size Limits**:
   - Images: Maximum 10MB
   - PDFs: Maximum 500MB

2. **Page Limits**:
   - DetectDocumentText: Single page processing
   - For multi-page PDFs, each page is processed separately

3. **Language Support**:
   - Primarily optimized for English text
   - May work with other Latin-script languages

4. **Image Quality**:
   - Better results with high-resolution, clear images
   - Poor quality scans may have lower confidence scores

## Integration with Ferret Scan

This library is integrated into Ferret Scan's preprocessing pipeline when the `--enable-genai` flag is used:

1. **Automatic Detection**: Files are automatically checked for Textract compatibility
2. **Preprocessing**: Text is extracted before validation
3. **Cost Awareness**: Users are warned about potential AWS costs
4. **Fallback**: Falls back to standard processing if Textract fails

## Security Considerations

- **Data Transmission**: Files are sent to AWS Textract service
- **Data Retention**: AWS may temporarily store data for processing
- **Sensitive Data**: Consider data sensitivity before using cloud OCR
- **Credentials**: Secure your AWS credentials appropriately

## Troubleshooting

### Common Issues

1. **"AWS credentials not found"**
   - Configure AWS credentials using `aws configure`
   - Set environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

2. **"Region not supported"**
   - Use a region where Textract is available
   - Default region is `us-east-1`

3. **"File too large"**
   - Reduce image resolution or file size
   - Split large PDFs into smaller chunks

4. **"Low confidence scores"**
   - Improve image quality
   - Ensure text is clearly visible
   - Check image orientation

### Debug Information

Enable debug mode in Ferret Scan to see detailed Textract processing information:

```bash
./ferret-scan --file document.pdf --enable-genai --debug
```

## Performance

- **Processing Time**: Varies by file size and complexity
- **Network Dependency**: Requires internet connection to AWS
- **Concurrent Processing**: Library supports concurrent requests
- **Caching**: No built-in caching - consider implementing if needed

## Examples

See the main Ferret Scan documentation for complete usage examples with the `--enable-genai` flag.
