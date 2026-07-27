# Quotas and Limits

[← Back to Documentation Index](../README.md)

This document provides a comprehensive reference for all file size limits, processing quotas, and system constraints in Ferret-Scan.

## File Size Limits

| Component | Limit | Configurable | Notes |
|-----------|-------|--------------|-------|
| **Web UI Upload** | 100MB | No | Per-file decompression-bomb guard (`internal/web/server.go`); folder uploads have no count limit |
| **CLI General** | 100MB | Yes | Default for most file types |
| **Text Files** | 100MB | No | Plaintext preprocessor limit |
| **Streaming Processor** | 500MB | Yes | For large file processing |
| **Text Extraction** | 10MB | Yes | Document preprocessing |
| **Theoretical Maximum** | ~214GB | No | Int32 overflow protection |

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

## Common Error Messages

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `File too large: ... bytes (max: 104857600 bytes)` | Web UI / CLI file > 100 MB | Reduce file size or split into chunks |
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
