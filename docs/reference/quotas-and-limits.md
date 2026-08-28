# Quotas and Limits

[← Back to Documentation Index](../README.md)

This document provides a comprehensive reference for all file size limits, processing quotas, and system constraints in Ferret-Scan.

## File Size Limits

| Component | Limit | Configurable | Notes |
|-----------|-------|--------------|-------|
| **Web UI Upload** | 100MB | No | Per-file decompression-bomb guard (`internal/web/server.go`); folder uploads have no count limit |
| **CLI, video containers** | 500MB | No | `router.MaxVideoFileSize`, for `.mp4` `.m4v` `.mov` `.3gp` `.3g2` |
| **CLI, every other file type** | 100MB | No | `router.MaxFileSize`. File discovery derives its limit from `router.MaxSizeForPath`, so the two gates cannot disagree |
| **Text Files** | 100MB | No | Plaintext preprocessor limit |
| **Text Extraction** | 10MB | No | Per-entry `io.LimitReader` during document preprocessing (`officelib.MaxXMLSize`) |

**100MB is the effective limit for every file type except video, which is 500MB.**

Video is the one exemption, and it exists because the file's size was never what bounded the
work: the extractor parses the `moov` box and seeks past the media data, so its memory is
`O(min(|moov|, 32MB))` and independent of the file's length. Measured peak RSS is **29MB for a
453MB file**, flat across the range. The video metadata extractor and the media resource manager
had both named 500MB since they were written, and neither ceiling was reachable — every file met
the flat 100MB gate first and was refused there, so the tool declined to scan files it was fully
capable of scanning.

**Audio is deliberately not exempt.** It is capped at 100MB three more times over, by the audio
extractor and by the media resource manager, so raising the front gate alone would not scan a
larger recording — measured on 150MB and 450MB files, it yielded zero additional findings. An
allowance there would only change which counter recorded the miss.

Two paths keep the flat 100MB ceiling on purpose:

- **`--stdin`** has no filename to take a type from (`--stdin-name` is a label the caller
  invents), and it refuses binary content outright, so it can never scan a video regardless.
- **Web UI uploads** *materialize* the bytes into a temp file before anything reads them, so the
  video allowance would let one request write 500MB of temp disk chosen by an attacker-supplied
  filename. This path refuses *more* than the CLI and discloses the refusal as a coverage gap.

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

### Embedded part bounds (Office containers)

An OOXML container (`.docx`, `.xlsx`, `.pptx` and their macro-enabled forms) can hold arbitrarily
many arbitrarily large parts under `media/` and `embeddings/`, all attacker-controlled and all
cheap to declare. Five bounds apply, because each one leaves the others unbounded:

| Bound | Value | Configurable | Disclosed when it bites |
|---|---|---|---|
| `MaxEmbeddedMediaSize` | 50MB per single embedded part | No | Yes |
| `embedded.BudgetBytes` (per container) | 200MB of embedded bytes one container may inflate | No | Yes |
| `embedded.Budget` (per top-level file) | 200MB of embedded bytes the whole traversal may **materialise** | No | Yes |
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

#### Per container and per traversal are two different bounds

`MaxEmbeddedMediaSize` and the per-container form of `embedded.BudgetBytes` bound **one container**.
On their own that is not enough, because the aggregate then scales with the number of containers:
every child was materialised as its own file and re-entered extraction, drawing a fresh 200MB
allowance. `MaxDepth` bounded the depth factor and nothing bounded fan-out, so splitting one refused
container into sixty admissible ones defeated the budget entirely.

`embedded.Budget` closes that. It is created once per **top-level file**, inherited by every
descendant of it, and released when that file finishes — per-file rather than process-wide, because
files are scanned by a parallel worker pool and a shared counter would make *which* parts get
examined depend on worker interleaving. Measured before and after, on `.docx` fixtures built from a
real document (bytes written to temp during one scan):

| fixture | input | before | after |
|---|---|---|---|
| 4 levels of nesting | 198KB | 180MB, silent | 135MB, disclosed |
| 16 sibling containers | 642KB | 713MB, silent | 180MB, disclosed |
| 64 sibling containers | 2.4MB | **2,733MB**, silent | **141MB**, disclosed |

The "before" column grows linearly with container count; the "after" column is flat and under
`BudgetBytes`. Findings were **identical** in every row — the refusals fall on decompression-bomb
padding, not on content — and across 381 real Office documents (147 of them carrying embedded parts,
2,625 parts materialised) the two binaries reported the same 6,844 findings with no refusals at all.

Two details decide whether this bound works:

- It is reserved on a part's **declared** size *before* any bytes are written, and trued up to the
  real length afterwards. Charging after the copy bounds what gets *scanned* but not what gets
  *written* — measured, all 16 parts of the fan-out fixture still wrote their 45MB before being
  correctly refused. A bound that fires after the cost is paid is not a bound.
- `MaxDepth` is consulted **before** parts are materialised, not only in the router afterwards.
  Otherwise the deepest level's bytes are written to temp and immediately discarded.

## Processing and Performance Limits

| Component | Limit | Configurable | Notes |
|-----------|-------|--------------|-------|
| **File workers** | `min(NumCPU, 8)` | No | `parallel.FileWorkers()`. Derived from the CPU count; the 8 is `parallel.MaxFileWorkers` |
| **Concurrent validator invocations** | `GOMAXPROCS` | Via the `GOMAXPROCS` environment variable | `execguard.DefaultLimiter`, sized once at process start. Deliberately *not* capped at 8: the worker pool bounds I/O breadth, this bounds CPU-bound validation depth |
| **Live extracted bytes** | no cap by default | Yes — `--max-live-bytes` | Bounds total extracted content held across concurrently scanned files. Off unless the flag is given |
| **XML parse time, per Office part** | 30s | No | `officelib.XMLParseTimeout` |

There is **no adaptive worker scaling**: the pool size is fixed for the life of the process, no
limit reacts to memory pressure or to file size, and no scan is chunked. The worker count has no
flag, config key or environment-variable input — the only performance lever an operator has is
`--max-live-bytes`, and the only way to change the rest is to edit the constants and rebuild.

### Output bounds

| Bound | Value | Configurable | Applies to |
|---|---|---|---|
| `shared.ContextSnippetCap` | 1024 bytes of source line per finding | No | `sarif`, `gitlab-sast` — the only formats that embed the line |
| `--limit` | 200 findings displayed | Yes — `--limit 0` for all | every format |

The SARIF and gitlab-sast formatters embed the finding's source line once **per finding** when
`--show-match` is set, so on a document whose content sits on ONE long line the report is quadratic
in findings × line length. Measured on a single 258KB line with 8,000 findings:

| | sarif output | wall |
|---|---|---|
| unbounded | **4,143,145,063 B** | 24.16s |
| capped at 1024 B | 35,168,967 B | 1.01s |

That is 4.1GB from a 258KB input. The growth per doubling of findings was 8.7× unbounded and 2.3×
capped — quadratic against linear. `json` was never affected, because it does not embed the line.

A line within the cap is emitted **unchanged**, which covers 61.2% of findings measured across
57,790 findings in 1,009 real files (median line 647 bytes). Beyond it the snippet is a window
**centred on the match**, with `...` marking each trimmed edge so a consumer can always tell a
fragment from a whole line. This bounds display only — the finding's own text, line number and
offsets are untouched, so nothing about detection or redaction depends on it.

> **Corrected 2026-08.** Every row of this table previously described the adaptive pool that
> `internal/parallel/resource_monitor.go` and `internal/preprocessors/streaming_processor.go`
> configured — Maximum Workers 32, Minimum Workers 2, a 1GB memory-pressure threshold, 250MB/10MB
> file-size worker scaling, and a 10MB/1KB chunk size and overlap, all marked configurable. That
> stack was never wired into any entry point and was deleted as dead code (`8cf13a6`, `00547f7`),
> and its memory-pressure signal was mathematically unreachable even before removal. The rows
> dated from the project's first commit, so this table never described shipped behaviour.
> `parallel.MaxFileWorkers` is now named rather than an inline literal, and a test reads this
> document, so the number above cannot drift from the code again.

## Common Error Messages

Four surfaces refuse an oversize file, each with its own wording, so the wording tells you *which
gate* stopped it. The two CLI-side messages name the limit that actually refused the file — 500MB
for a video container, 100MB otherwise — so a refused 600MB video reads `max size: 500MB` and not
the 100MB it already cleared.

| Error Message | Emitted by | Solution |
|---------------|------------|----------|
| `file too large (max size: 500MB)` | CLI file discovery, for a video container | Split the file, or extract the metadata-bearing part and scan that |
| `file too large (max size: 100MB)` | CLI file discovery (`cmd/main.go`), every other type | As above |
| `File too large (max: 100MB)` / `(max: 500MB)` | The file router (`internal/router/file_router.go`) | As above |
| `file too large to scan (max size: 100MB)` | Web UI upload (`internal/web/server.go`) — always 100MB, including video | As above, or scan the file with the CLI, which admits video up to 500MB |
| `file too large: <n> bytes (max: 104857600 bytes)` | Plain-text preprocessor (`internal/preprocessors/plaintext_preprocessor.go`) | As above |
| `XML content too large: <n> bytes (max: 10485760)` | An Office XML part over `officelib.MaxXMLSize` | Nothing to configure; the part itself is too large |

A refusal is disclosed, not silent: the file is reported under `files_not_examined` as
`file too large to scan`, and `--fail-on-incomplete` exits 3. See
[Coverage Disclosure](../COVERAGE_DISCLOSURE.md).

> **Corrected 2026-08.** This table previously listed two errors the tool cannot emit:
> `File too large: chunk offset exceeds int32 maximum` ("File exceeds ~214GB") and
> `System under memory pressure` ("Solution: Reduce worker count or batch size"). Neither string
> has ever existed in the code — the first appears only in this document, in every commit since
> the first; the second belonged to the deleted `IsMemoryPressure()`. The advice attached to them
> was unfollowable, since worker count is not adjustable and nothing is chunked. The remaining
> rows were also misattributed: the `104857600` message is the plain-text preprocessor's, not the
> web UI's, and the web UI's own wording was absent.

## Configuration

The file size limits above are compile-time constants; there is no flag, config key or
environment variable that changes them. Raising one means editing `router.MaxFileSize` or
`router.MaxVideoFileSize`, which every gate derives from through `router.MaxSizeForPath`. The
same is true of the worker count and every other row in the performance table.

A per-type ceiling has to be justified per type, not just raised: the question is whether the
file's size is what bounds the work. It is for anything held in memory to be parsed, and it is
not for a container the extractor seeks through. Raising the video ceiling also means keeping
`router.MaxVideoFileSize` at or below the extractor's own `MaxFileSize`, or a file is admitted at
one layer and refused at a deeper one whose message names a limit the operator never saw.

Two runtime levers exist, and they are the only two:

```bash
# Bound total extracted content held in memory across concurrently scanned files.
# The only memory control; there is no cap unless you pass this.
ferret-scan --max-live-bytes 256MB --file ./tree

# Bound concurrent validator work (execguard.DefaultLimiter is sized from this at startup).
# Does not change the file worker pool, which is min(NumCPU, 8) either way.
GOMAXPROCS=2 ferret-scan --file ./tree

# Enable debug logging
export FERRET_DEBUG=1
```

There is no `performance:` section in the configuration file. Config keys such as `max_workers`,
`worker_memory_limit`, `cache_size` or `max_file_size` do not exist; supplying one produces
`Warning: unknown config key "performance" — ignored (check for a typo)` and changes nothing.

## Best Practices

| Scenario | Recommendation |
|----------|----------------|
| **Large Images** | Reduce resolution before processing |
| **Large PDFs** | Split into smaller files |
| **Many Small Files** | Use batch processing for efficiency |
| **Memory Issues** | Pass `--max-live-bytes` (e.g. `256MB`), or scan fewer files per invocation. The worker count itself cannot be reduced |
