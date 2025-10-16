# Amazon Transcribe Audio Extractor

This library provides audio transcription capabilities using Amazon Transcribe service for the Ferret Scan sensitive data detection tool.

## Features

- **Real-time Transcription**: Convert audio files to text using Amazon Transcribe
- **Multiple Audio Formats**: Support for MP3, WAV, M4A, and FLAC files
- **Flexible S3 Storage**: Use existing buckets or auto-create temporary ones
- **Cost Estimation**: Provides upfront cost estimates before processing
- **Automatic Cleanup**: Removes temporary files and buckets after processing
- **AWS SDK v2**: Uses latest AWS SDK with improved performance and security

## Supported Audio Formats

- **MP3**: MPEG Audio Layer III
- **WAV**: Waveform Audio File Format
- **M4A**: MPEG-4 Audio
- **FLAC**: Free Lossless Audio Codec

## Prerequisites

1. **AWS Account**: Active AWS account with billing enabled
2. **AWS Credentials**: Configured using one of these methods:
   - AWS CLI: `aws configure`
   - Environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - IAM roles (for EC2 instances)
   - AWS credentials file (~/.aws/credentials)

3. **IAM Permissions**: Your credentials need:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "transcribe:StartTranscriptionJob",
                   "transcribe:GetTranscriptionJob",
                   "s3:PutObject",
                   "s3:DeleteObject",
                   "s3:CreateBucket",
                   "s3:DeleteBucket",
                   "s3:HeadBucket"
               ],
               "Resource": "*"
           }
       ]
   }
   ```

## Usage

### Basic Usage

```go
import transcribe_extractor_lib "ferret-scan/internal/preprocessors/audio-extractors/transcribe-extractor-lib"

// Basic usage with auto-created bucket
content, err := transcribe_extractor_lib.TranscribeText("audio.mp3", "us-east-1", "")

// Using existing S3 bucket
content, err := transcribe_extractor_lib.TranscribeText("audio.mp3", "us-east-1", "my-bucket")
```

### Command Line Examples

```bash
# Basic usage with auto-created bucket
./ferret-scan --enable-genai --file audio.mp3

# Using existing S3 bucket
./ferret-scan --enable-genai --transcribe-bucket my-bucket --file audio.mp3

# With specific AWS region
./ferret-scan --enable-genai --textract-region us-west-2 --file audio.mp3
```

### Standalone Example

```bash
# Run standalone example
cd examples/preprocessors
go run transcribe-example.go audio.mp3

# With custom bucket and region
go run transcribe-example.go audio.mp3 --region=us-west-2 --bucket=my-bucket
```

## Configuration Options

- `--region=<region>`: AWS region (default: us-east-1)
- `--bucket=<bucket>`: S3 bucket name (optional, creates temporary if not specified)

## Cost Considerations

- **Transcribe Pricing**: ~$0.024 per minute of audio
- **S3 Storage**: Minimal costs for temporary storage during processing
- **Data Transfer**: Standard AWS data transfer rates apply

### Cost Estimation

The library provides upfront cost estimation:

```go
cost, err := transcribe_extractor_lib.EstimateTranscribeCost("audio.mp3")
fmt.Printf("Estimated cost: $%.4f\n", cost)
```

## Troubleshooting

### Common Issues

1. **AWS Credentials Not Found**
   - Verify credentials are configured: `aws sts get-caller-identity`
   - Check IAM permissions for Transcribe and S3 services

2. **Bucket Access Denied**
   - Verify bucket exists and is accessible
   - Check S3 permissions in your IAM policy

3. **Transcription Failed**
   - Ensure audio file is in supported format
   - Check file size limits (500MB max for audio files)
   - Verify AWS region supports Transcribe service

4. **Timeout Errors**
   - Large audio files may take longer to process
   - Consider using existing buckets to reduce S3 costs

## API Reference

### Functions

#### `TranscribeText(filePath, region, bucket string) (*TranscribedContent, error)`

Transcribes audio file using Amazon Transcribe.

**Parameters:**
- `filePath`: Path to audio file
- `region`: AWS region for Transcribe service
- `bucket`: S3 bucket name (empty for auto-creation)

**Returns:**
- `*TranscribedContent`: Transcription results
- `error`: Error if transcription fails

#### `IsSupportedAudioType(filePath string) bool`

Checks if audio file format is supported.

#### `ValidateAWSCredentials(region string) error`

Validates AWS credentials and region.

#### `EstimateTranscribeCost(filePath string) (float64, error)`

Estimates transcription cost based on file size.

### Data Structures

#### `TranscribedContent`

```go
type TranscribedContent struct {
    Filename     string  // Original filename
    AudioType    string  // Audio format (e.g., "MP3 Audio")
    Duration     float64 // Audio duration in seconds
    Text         string  // Transcribed text content
    Confidence   float64 // Transcription confidence (0-100)
    WordCount    int     // Number of words in transcript
    CharCount    int     // Number of characters in transcript
    LineCount    int     // Number of lines in transcript
    JobName      string  // Transcribe job identifier
}
```

## Integration with Ferret Scan

The transcribe extractor integrates seamlessly with Ferret Scan's preprocessing pipeline:

1. **Audio Detection**: Automatically detects supported audio formats
2. **Transcription**: Converts audio to text using Amazon Transcribe
3. **Validation**: Feeds transcribed text to all sensitive data validators
4. **Results**: Reports sensitive data found in audio content

## Security Considerations

- **Data Transmission**: Audio files are uploaded to AWS S3 for processing
- **Temporary Storage**: Files are automatically cleaned up after processing
- **Access Control**: Use IAM policies to restrict access to S3 buckets
- **Encryption**: Consider using S3 encryption for sensitive audio content

## Performance Tips

- Use existing S3 buckets to reduce setup time
- Process audio files in the same AWS region as your bucket
- Consider file size limits when processing large audio files
- Monitor AWS costs when processing multiple files
