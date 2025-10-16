// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package transcribe_extractor_lib

// GENAI_DISABLED: This entire file has been disabled as part of GenAI feature removal
// The AWS SDK v2 dependencies required for this functionality have been removed from go.mod
// to reduce binary size and eliminate cloud service dependencies.

/*
import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/transcribe"
	"github.com/aws/aws-sdk-go-v2/service/transcribe/types"
)
*/

/*
// TranscribedContent represents the content transcribed by Amazon Transcribe
type TranscribedContent struct {
	Filename   string
	AudioType  string
	Duration   float64
	Text       string
	Confidence float64
	WordCount  int
	CharCount  int
	LineCount  int
	JobName    string
}

// TranscribeText transcribes audio from a file using Amazon Transcribe
func TranscribeText(filePath, region, customBucket string) (*TranscribedContent, error) {
	// Create context with timeout for AWS operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Generate unique job name
	timestamp := time.Now().UnixNano()
	jobName := fmt.Sprintf("ferret-scan-%d", timestamp)

	// Use custom bucket or generate unique one
	var bucketName string
	var shouldCleanupBucket bool
	if customBucket != "" {
		bucketName = customBucket
		shouldCleanupBucket = false
	} else {
		// Get AWS account ID for unique bucket naming
		accountID, err := getAWSAccountID(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to get AWS account ID: %w", err)
		}
		bucketName = fmt.Sprintf("ferret-scan-transcribe-%s-%d", accountID, timestamp)
		shouldCleanupBucket = true
	}

	s3Key := fmt.Sprintf("audio/%d-%s", timestamp, filepath.Base(filePath))

	content := &TranscribedContent{
		Filename:  filepath.Base(filePath),
		AudioType: getAudioType(filePath),
		JobName:   jobName,
	}

	// Create S3 and Transcribe clients
	s3Client := s3.NewFromConfig(cfg)
	transcribeClient := transcribe.NewFromConfig(cfg)

	// Validate bucket exists if custom bucket is specified
	if customBucket != "" {
		if err := validateBucketExists(s3Client, bucketName); err != nil {
			return nil, fmt.Errorf("bucket validation failed: %w", err)
		}
	}

	// Upload file to S3
	s3URI := fmt.Sprintf("s3://%s/%s", bucketName, s3Key)
	if err := uploadToS3(ctx, s3Client, filePath, bucketName, s3Key); err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Start transcription job
	if err := startTranscriptionJob(ctx, transcribeClient, jobName, s3URI); err != nil {
		return nil, fmt.Errorf("failed to start transcription: %w", err)
	}

	// Wait for completion and get results
	transcript, err := waitForTranscription(ctx, transcribeClient, jobName)
	if err != nil {
		return nil, fmt.Errorf("transcription failed: %w", err)
	}

	// Clean up S3 object and bucket (only cleanup bucket if we created it)
	cleanupS3(ctx, s3Client, bucketName, s3Key)
	if shouldCleanupBucket {
		cleanupBucket(ctx, s3Client, bucketName)
	}

	// Populate content
	content.Text = transcript
	content.Confidence = 95.0 // Transcribe doesn't provide overall confidence
	content.WordCount = len(strings.Fields(content.Text))
	content.CharCount = len(content.Text)
	content.LineCount = strings.Count(content.Text, "\n") + 1

	return content, nil
}

// uploadToS3 uploads a file to S3
func uploadToS3(ctx context.Context, client *s3.Client, filePath, bucket, key string) error {
	// First try to create bucket if it doesn't exist
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	// Ignore error if bucket already exists

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   file,
	})
	return err
}

// startTranscriptionJob starts a Transcribe job
func startTranscriptionJob(ctx context.Context, client *transcribe.Client, jobName, s3URI string) error {
	_, err := client.StartTranscriptionJob(ctx, &transcribe.StartTranscriptionJobInput{
		TranscriptionJobName: aws.String(jobName),
		Media: &types.Media{
			MediaFileUri: aws.String(s3URI),
		},
		MediaFormat:  types.MediaFormatMp3, // Adjust based on file type
		LanguageCode: types.LanguageCodeEnUs,
	})
	return err
}

// waitForTranscription waits for job completion and returns transcript
func waitForTranscription(ctx context.Context, client *transcribe.Client, jobName string) (string, error) {
	for i := 0; i < 60; i++ { // Wait up to 5 minutes
		resp, err := client.GetTranscriptionJob(ctx, &transcribe.GetTranscriptionJobInput{
			TranscriptionJobName: aws.String(jobName),
		})
		if err != nil {
			return "", err
		}

		switch resp.TranscriptionJob.TranscriptionJobStatus {
		case types.TranscriptionJobStatusCompleted:
			return downloadTranscript(*resp.TranscriptionJob.Transcript.TranscriptFileUri)
		case types.TranscriptionJobStatusFailed:
			return "", fmt.Errorf("transcription failed: %s", *resp.TranscriptionJob.FailureReason)
		}

		time.Sleep(5 * time.Second)
	}
	return "", fmt.Errorf("transcription timeout")
}

// downloadTranscript downloads and parses the transcript JSON
func downloadTranscript(uri string) (string, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Simple extraction - in production, parse JSON properly
	transcript := string(body)
	if strings.Contains(transcript, `"transcript":`) {
		start := strings.Index(transcript, `"transcript":"`)
		if start != -1 {
			start += len(`"transcript":"`)
			end := strings.Index(transcript[start:], `"`)
			if end != -1 {
				return transcript[start : start+end], nil
			}
		}
	}
	return "[Transcription completed but text extraction failed]", nil
}

// cleanupS3 removes the temporary S3 object
func cleanupS3(ctx context.Context, client *s3.Client, bucket, key string) {
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
}

// cleanupBucket removes the temporary S3 bucket
func cleanupBucket(ctx context.Context, client *s3.Client, bucket string) {
	client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
}

// getAudioType determines the audio type based on file extension
func getAudioType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".mp3":
		return "MP3 Audio"
	case ".wav":
		return "WAV Audio"
	case ".m4a":
		return "M4A Audio"
	case ".flac":
		return "FLAC Audio"
	default:
		return "Audio File"
	}
}

// IsSupportedAudioType checks if the file type is supported by Transcribe
func IsSupportedAudioType(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	supportedTypes := map[string]bool{
		".mp3":  true,
		".wav":  true,
		".m4a":  true,
		".flac": true,
	}
	return supportedTypes[ext]
}

// ValidateAWSCredentials checks if AWS credentials are available
func ValidateAWSCredentials(region string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	_, err = cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("AWS credentials not found or invalid: %w", err)
	}

	return nil
}

// EstimateTranscribeCost provides a rough cost estimate for transcription
func EstimateTranscribeCost(filePath string) (float64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to get file info: %w", err)
	}

	// Transcribe pricing: $0.024 per minute
	// Rough estimate: 1MB ≈ 1 minute of audio
	estimatedMinutes := float64(fileInfo.Size()) / (1024 * 1024)
	if estimatedMinutes < 1 {
		estimatedMinutes = 1
	}

	return estimatedMinutes * 0.024, nil
}

// getAWSAccountID retrieves a unique identifier for bucket naming
func getAWSAccountID(cfg aws.Config) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", err
	}
	// Generate unique identifier for bucket naming
	return fmt.Sprintf("%x", time.Now().Unix())[:8], nil
}

// validateBucketExists checks if the specified bucket exists and is accessible
func validateBucketExists(client *s3.Client, bucket string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return fmt.Errorf("bucket '%s' does not exist or is not accessible: %w", bucket, err)
	}
	return nil
}
*/
