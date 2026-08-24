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

### Video metadata bounds

Video metadata lives in the `moov` box, which the standards allow anywhere in the file — ISO/IEC
14496-12 cl. 8.2.1.1 says it is "normally ... close to the beginning or end of the file, though this
is not required", and Apple's QuickTime format reference states outright that "QuickTime does not
impose any rules about the order of these atoms". ffmpeg and typical cameras write it **last**;
`-movflags faststart` is a second pass that moves it to the front.

The extractor therefore has **no positional limit** — it walks the top-level boxes by header and
reads only the metadata ones, so a `moov` at the end of a 99MB file is read exactly like one at the
start, and the media payload is never read at all. Two work bounds remain:

| Bound | Value | Configurable | Disclosed when it bites |
|---|---|---|---|
| `MaxMoovParse` | 32MB of `moov` payload parsed | No | Yes |
| `MaxTopLevelBoxes` | 1,048,576 top-level boxes walked | No | Yes |

Both are far above any real file: a real `moov` measures a fraction of a percent of its file, and a
well-formed movie has a handful of top-level boxes. When either bound is reached the result is a
`coverage cut short` disclosure, not a silent truncation.

Before this, the extractor stopped once the walk passed a 10MB **file offset** — counting the media
bytes it skipped without reading — so a camera-default recording over about 10MB reported no metadata
at all, at exit 0, with nothing under `files_not_examined`.

### Embedded part bounds (Office containers)

An OOXML container (`.docx`, `.xlsx`, `.pptx` and their macro-enabled forms) can hold arbitrarily
many arbitrarily large parts under `media/` and `embeddings/`, all attacker-controlled and all
cheap to declare. Four bounds apply, because each one leaves the others unbounded:

| Bound | Value | Configurable | Disclosed when it bites |
|---|---|---|---|
| `MaxEmbeddedMediaSize` | 50MB per single embedded part | No | Yes |
| `embedded.BudgetBytes` | 200MB of embedded bytes per container | No | Yes |
| `maxEmbeddedParts` | 4,096 embedded parts per container | No | Yes |
| `embedded.MaxDepth` | 3 levels of container-inside-container | No | Yes |

The count bound exists because the other two do not imply it: an **empty** part charges nothing
against the per-part cap or the byte budget, while still costing an inflate, a temp file and a
routing decision. Measured on `.docx` files whose media entries hold an 8-byte PNG signature and
nothing else, the cost is linear with a large per-part constant:

| embedded parts | input size | before the cap | with the cap |
|---|---|---|---|
| 10,000 | 1.2MB | 9.0s, 120MB RSS | 3.6s, 72MB RSS |
| 50,000 | 6.2MB | 43.8s, 352MB RSS | 3.6s, 76MB RSS |
| 200,000 | 25.2MB | 184.3s, 1182MB RSS | 4.1s, 156MB RSS |

4,096 comes from the real distribution: across 420 real Office documents the largest part count in
any one file was 361 (next 201, 201, 198), the median 0 and the mean 7, so the cap sits about 11x
above the largest legitimate file measured. Report output was byte-identical across all 420 with the
cap in place.

`embedded.BudgetBytes` and `MaxEmbeddedMediaSize` are **per container**, not per traversal — a
nested tree grants a fresh allowance at each container, so the aggregate over a nest is not bounded
by either number. `MaxDepth` bounds the depth factor; nothing bounds the fan-out factor.

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
