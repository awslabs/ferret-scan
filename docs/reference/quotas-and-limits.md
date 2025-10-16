# Quotas and Limits

[← Back to Documentation Index](../README.md)

This document provides a comprehensive reference for all file size limits, processing quotas, and system constraints in Ferret-Scan.

## File Size Limits

| Component | Limit | AWS Service | Configurable | Notes |
|-----------|-------|-------------|--------------|-------|
| **Web UI Upload** | 10MB | No | No | Hardcoded limit for web interface |
| **CLI General** | 100MB | No | Yes | Default for most file types |
| **Text Files** | 100MB | No | No | Plaintext preprocessor limit |
<!-- GENAI_DISABLED: | **Audio Files (GenAI)** | 500MB | AWS Transcribe | No | For transcription services | -->
<!-- GENAI_DISABLED: | **Images (GenAI)** | 10MB | AWS Textract | No | Per image limit | -->
<!-- GENAI_DISABLED: | **PDF Files (GenAI)** | 500MB | AWS Textract | No | Per PDF limit | -->
| **Streaming Processor** | 500MB | No | Yes | For large file processing |
<!-- GENAI_DISABLED: | **Comprehend Chunks** | 100KB | AWS Comprehend | No | Per API call limit | -->
| **Text Extraction** | 10MB | No | Yes | Document preprocessing |
| **Theoretical Maximum** | ~214GB | No | No | Int32 overflow protection |

## Processing and Performance Limits

| Component | Limit | Type | Configurable | Notes |
|-----------|-------|------|--------------|-------|
| **Maximum Workers** | 32 | Performance | Yes | Regardless of CPU count |
| **Minimum Workers** | 2 | Performance | Yes | Always maintained |
| **Memory Threshold** | 1GB | Performance | Yes | Memory pressure detection |
| **Large File Threshold** | 250MB | Performance | Yes | Reduces worker count |
| **Small File Threshold** | 10MB | Performance | Yes | Allows more workers |
| **Chunk Size** | 10MB | Performance | Yes | Streaming processor default |
| **Chunk Overlap** | 1KB | Performance | Yes | Between chunks |

## AWS Service Details

<!-- GENAI_DISABLED: AWS Service Limits
| Service | Limit | Additional Constraints | Cost Model |
|---------|-------|----------------------|------------|
| **AWS Comprehend** | 100KB per request | Rate limits vary by region | Per 100-character unit |
| **AWS Textract** | 10MB (images), 500MB (PDFs) | Single page for DetectDocumentText | Per page/request |
| **AWS Transcribe** | 500MB per file | Rate limits vary by region | Per minute of audio |
-->

## Common Error Messages

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `File exceeds 10MB upload limit` | Web UI file too large | Use CLI or reduce file size |
| `File too large (max: 100MB)` | CLI file exceeds default | Configure larger limit or use streaming |
| `File too large: chunk offset exceeds int32 maximum` | File exceeds ~214GB | Split file into smaller parts |
| `System under memory pressure` | Insufficient memory | Reduce worker count or batch size |

## Configuration

Most limits can be adjusted through environment variables:

```bash
# Set general file size limit (in bytes)
export MAX_FILE_SIZE=209715200  # 200MB

# Enable debug logging
export FERRET_DEBUG=1
```

## Best Practices

| Scenario | Recommendation |
|----------|----------------|
| **Large Images** | Reduce resolution before processing |
| **Large PDFs** | Split into smaller files or use streaming processor |
| **Many Small Files** | Use batch processing for efficiency |
| **Memory Issues** | Reduce worker count or process fewer files simultaneously |
<!-- GENAI_DISABLED: | **AWS Costs** | Enable GenAI only for files that need it | -->
<!-- GENAI_DISABLED: | **Performance** | Use closest AWS region for GenAI features | -->