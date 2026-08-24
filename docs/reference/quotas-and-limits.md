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

### Audio metadata bounds

Audio metadata sits behind a declared length: a box size in `.m4a`, a chunk size in `.wav`, a block
length in `.flac`, a synchsafe frame size in `.mp3`. Every one of those numbers is read **out of the
file**, so it is chosen by whoever produced the file.

Some of those lengths have a fixed ceiling:

| Bound | Value | Applies to |
|---|---|---|
| `MaxID3v2Size` | 1MB | the whole ID3v2 tag in `.mp3` |
| `MaxMetadataRead` | 1MB | one metadata read on the `.mp3` path |
| string/text atom caps | 1KB / 10KB | `.m4a` tag atoms |

The rest are bounded by **the file itself**: a declared length is clamped to the bytes actually
remaining from the current offset before anything is allocated. That is the only bound in this area
an attacker does not also write — bounding one declaration by another bounds nothing, since both come
out of the same file.

There is no configurable quota here and nothing is disclosed, because nothing is skipped: on a
well-formed file the declared length already fits and the clamp changes nothing. Verified on 600 real
audio files (548 `.m4a`, 50 `.wav`, 2 `.mp3`): report output byte-identical with and without the
clamp.

Before the clamp existed, a **52-byte** `.m4a` whose `mvhd` declared `0xFFFFFFFF` allocated 4096MB,
and an **8-byte** `.flac` whose first metadata block declared `0xFFFFFF` allocated 16MB. A directory
of six such `.m4a` files plus one real recording — 220KB of input — reached 4.03GB of resident memory;
now 0.03GB.

> One measurement caveat worth knowing when reproducing this class: Go does not zero a span it takes
> fresh from the OS, so a **single** bomb reserves memory it never writes and peak RSS stays near
> 30MB. The pages only become resident once the runtime reuses a dirty span and has to zero it. A
> one-file RSS measurement will therefore look clean even when the allocation is happening.

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
