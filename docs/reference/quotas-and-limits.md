# Quotas and Limits

[← Back to Documentation Index](../README.md)

This document provides a comprehensive reference for all file size limits, processing quotas, and system constraints in Ferret-Scan.

## File Size Limits

| Component | Limit | Configurable | Notes |
|-----------|-------|--------------|-------|
| **Web UI Upload** | 100MB | No | Per-file decompression-bomb guard (`internal/web/server.go`); folder uploads have no count limit |
| **CLI, every file type** | 100MB | No | `router.MaxFileSize`. File discovery derives its own limit from that same constant, so the two gates cannot disagree |
| **Text Files** | 100MB | No | Plaintext preprocessor limit |
| **Text Extraction** | 10MB | No | Per-entry `io.LimitReader` during document preprocessing |
| **Theoretical Maximum** | ~214GB | No | Int32 overflow protection |

**100MB is the effective limit for every file type, including audio and video.** Some
extractors carry a higher ceiling of their own — the video metadata extractor and the media
resource manager both name 500MB — but every file passes the 100MB CLI gate first, so those
ceilings are never reached. Audio is capped at 100MB three more times over, by the audio
extractor and by the media resource manager, so raising the CLI gate alone would not scan a
larger recording.

A file over the limit is **not** silently dropped: if it is a type the tool could have
processed, it is reported under `files_not_examined`, listed in the `NOT FULLY EXAMINED`
block, and `--fail-on-incomplete` exits 3. See [Coverage Disclosure](../COVERAGE_DISCLOSURE.md).

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
| `File too large (max: 100MB)` | CLI file exceeds the 100MB limit | Split the file, or extract the metadata-bearing part and scan that |
| `File too large: chunk offset exceeds int32 maximum` | File exceeds ~214GB | Split file into smaller parts |
| `System under memory pressure` | Insufficient memory | Reduce worker count or batch size |

## Configuration

The file size limits above are compile-time constants; there is no flag, config key or
environment variable that changes them. Raising one means editing `router.MaxFileSize`, which
every gate derives from.

```bash
# Enable debug logging
export FERRET_DEBUG=1
```

## Best Practices

| Scenario | Recommendation |
|----------|----------------|
| **Large Images** | Reduce resolution before processing |
| **Large PDFs** | Split into smaller files |
| **Many Small Files** | Use batch processing for efficiency |
| **Memory Issues** | Reduce worker count or process fewer files simultaneously |
