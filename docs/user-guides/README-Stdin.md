# Stdin / Streaming Gateway Guide

[← Back to Documentation Index](../README.md)

ferret-scan can read content from standard input via `--stdin` (or the POSIX-style alias `--file -`). This is the entry point for two important use cases:

1. **Shell pipelines**: `git diff | ferret-scan --stdin --pre-commit-mode`
2. **Streaming redaction gateways**: pipe sensitive content in, get cleansed content out — useful for AWS Lambda, gRPC handlers, and any in-process caller.

## Quick start

```bash
# Scan piped content
echo "card 5500-0000-0000-0004 email alice@example.com" | ferret-scan --stdin

# Scan a git diff before committing
git diff | ferret-scan --stdin --pre-commit-mode

# Stream redacted content (the gateway pattern)
cat sensitive.log | ferret-scan --stdin --enable-redaction > clean.log
```

## How it works

When `--stdin` is set, ferret-scan:

1. Reads up to 100 MB from `os.Stdin` into memory.
2. Strips a leading UTF-8 BOM if present.
3. Rejects content with embedded NUL bytes (the heuristic for binary content).
4. Coerces invalid UTF-8 to the replacement rune.
5. Calls `core.ScanContent(content, …)`, which **bypasses the file router entirely** and runs the validator pipeline directly against the in-memory buffer.

Stdin content is always treated as **plain text**. Binary documents (PDF, Office, images) must be written to a file and scanned with `--file <path>`.

## Output policy

| Mode | Stdout | Stderr | `--output <file>` |
|---|---|---|---|
| Scan only | Findings (formatted) | Progress / suppression notices | Findings (file) |
| Scan + redaction (stdout piped/redirected) | **Redacted content** | Findings + progress | **Redacted content**, findings → file |
| Scan + redaction (stdout is a terminal) | **Redacted content** | One-line hint pointing at the pipe shape | **Redacted content**, findings → file |

The split is deliberately Unix-conventional: when redaction is on, stdout is purely the cleansed text so it composes naturally with shell pipes and lambda runtimes that capture stdout. Use `--output <path>` if you also want a structured findings report alongside the redacted stream.

### Interactive vs piped output

When `--enable-redaction` is on with no `--output`, ferret-scan checks whether stdout is a terminal:

- **Stdout is piped/redirected** (`> clean.txt`, `| jq`, etc.): the full findings document streams to stderr and redacted content streams to stdout. This is the canonical pipe shape.
- **Stdout is a terminal** (interactive testing, no redirects): full findings would visually interleave with the redacted line on the user's screen, producing noise. Instead, ferret-scan suppresses the findings document and prints a one-line hint on stderr like `(2 findings detected and redacted; redirect to capture them: '... 2> findings.txt > clean.txt')`.

Same convention as `git diff` (strips colors when piped) and `jq` (compacts when piped, pretty-prints when interactive).

### Canonical pipe shape

When findings stream to stderr alongside redacted content on stdout, human-readable progress lines (`Scan complete: ...`, `Suppressed N findings...`) are **suppressed** so the findings document stays parseable end-to-end. This matters because YAML and JSON parsers reject leading prose lines.

```bash
# JSON
echo "$INPUT" | ferret-scan --stdin --enable-redaction --format json \
  2> findings.json > clean.txt

# YAML
echo "$INPUT" | ferret-scan --stdin --enable-redaction --format yaml \
  2> findings.yaml > clean.txt

# SARIF
echo "$INPUT" | ferret-scan --stdin --enable-redaction --format sarif \
  2> findings.sarif > clean.txt
```

In all three cases `findings.X` parses cleanly without manual cleanup.

When `--output <path>` is set, the findings document goes to the file and stderr is free to carry the usual human-readable progress prose.

## Findings labelling

Every match produced from a stdin scan carries:

- `Match.SourceKind = SourceKindVirtual`
- `Match.Filename = "<stdin>"` (configurable via `--stdin-name`)

Formatters that normalize file paths (SARIF, gitlab-sast) **skip** that normalization for virtual sources, so the synthetic label flows through cleanly.

```bash
# Custom label (useful for stable suppression keys across runs)
git diff | ferret-scan --stdin --stdin-name "<git-diff>" --suppression-file ./.ferret-stdin.yaml
```

## Streaming redaction gateway

The combination `--stdin --enable-redaction` is the gateway pattern. All three plaintext redaction strategies are supported:

| Strategy | Example output |
|---|---|
| `simple` | `card [CREDIT-CARD-REDACTED] email [EMAIL-REDACTED]` |
| `format_preserving` | `card 5500-****-****-0004 email a****@example.com` |
| `synthetic` | `card 5555-7344-3408-4176 email 5c0sq@example.com` |

```bash
# Compose with grep/sed/awk — redacted bytes flow naturally through the pipe
git diff \
  | ferret-scan --stdin --enable-redaction --redaction-strategy synthetic \
  | grep -v password

# Capture findings as JSON while still streaming redacted content
cat input.txt \
  | ferret-scan --stdin --enable-redaction \
                --redaction-strategy format_preserving \
                --format json --output findings.json \
  > clean.txt
```

### Suppression interaction

Suppressed matches **pass through unredacted** — a suppression rule is an explicit "this is fine" override. To enforce redaction on suppressed content, run without `--suppression-file` (or use `--show-suppressed=false`).

## In-process usage (lambda / gRPC)

For Go callers, the recommended path is the public `pkg/redact` package — a stable, safe-by-default API designed for embedding ferret-scan as an in-process library:

```go
import (
    "context"
    "log"

    "github.com/awslabs/ferret-scan/pkg/redact"
)

func handler() {
    // Construct ONCE per process. The Engine reuses validators, the
    // enhanced manager, and the dual-path bridge across every Redact
    // call — per-request setup cost is zero.
    engine, err := redact.NewEngine(redact.EngineOptions{
        Strategy: redact.FormatPreserving,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    res, err := engine.Redact(context.Background(), redact.Request{
        Text:  "card 5500-0000-0000-0004 from alice@example.com",
        Label: "req-abc-123",
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Println(res.Redacted)
    // Audit-safe summary — no payload bytes, no offsets, no substrings.
    // Suitable for CloudWatch / S3 Object Lock without leaking input.
    log.Printf("audit: %+v", res.AuditRecord())
}
```

Key properties:

- **Zero per-call construction**: `NewEngine` builds the validator graph once. The CLI's stdin path rebuilds it on every invocation; for a hot gateway that's roughly an order of magnitude slower than the actual scan.
- **Safe-by-default suppressions**: no constructor loads a suppression file from disk. Suppression rules are passed per-request via `Request.AllowSuppressions` so a misconfigured server can't accidentally let suppressed content through.
- **Payload-free findings**: `Result.Findings()` returns type / line / confidence — no matched substrings. Callers who need the bytes opt in via `Result.FindingsWithMatchText()`.
- **WORM-safe audit shape**: `Result.AuditRecord()` returns counts by type, byte counts, duration, and timestamp. No offsets, no input bytes. Log it directly to CloudWatch / S3 Object Lock.
- **Configurable LogWriter**: `EngineOptions.LogWriter` defaults to `io.Discard` so nothing leaks to stderr by default. Pass `os.Stderr` for dev visibility or wire your structured logger.
- **Validatable check names**: `NewEngine` tolerates unrecognized `EngineOptions.Checks` names — it drops them and only errors when *nothing* is left. A typo in a mixed list (e.g. `{"CREDIT_CARD", "emial"}`) therefore fails *open*: the misspelled validator is silently disabled while the engine still builds. Use `redact.ValidCheckNames()` to validate caller-supplied check names up front and reject anything unknown, so a misconfiguration fails closed at startup instead of leaking that data type at runtime.
- **Thread-safe**: an `Engine` is safe for concurrent use. Internal bridge state (e.g. metrics counters) is mutex-guarded; for high-concurrency workloads, pooling engines (one per worker) avoids lock contention. (The former cross-validator-signals and confidence-calibrator serialization points were removed in v2 Phase 2.)

For other languages (Python, Node, etc.), shell out to the binary with `--stdin --enable-redaction --quiet --no-color` — the `--quiet` flag suppresses progress prose so stderr stays parseable, `--no-color` strips ANSI codes so log sinks render cleanly, and the binary's own `--pre-commit-mode` exit semantics signal whether anything was matched. Avoid `--debug` in production: it enables verbose validator-internal logging that adds latency and noise without helping a gateway caller.

## Lower-level in-process usage

If you need direct access to the scanner pipeline (e.g. to plug ferret-scan into a custom processing graph rather than calling Redact end-to-end), the underlying `core.ScanContent` + `plaintext.RedactString` API remains available:

```go
import (
    "github.com/awslabs/ferret-scan/internal/core"
    "github.com/awslabs/ferret-scan/internal/redactors"
    "github.com/awslabs/ferret-scan/internal/redactors/plaintext"
)

func RedactStringLowLevel(input string) (string, error) {
    // Step 1: scan
    result, err := core.ScanContent(input, core.ContentScanConfig{
        VirtualPath: "<lambda-input>",
        Checks:      []string{"all"},
        // LogWriter routes the internal observer's output. Defaults to
        // os.Stderr when nil; pass io.Discard or a structured logger
        // writer to keep CloudWatch free of progress prose.
    })
    if err != nil {
        return "", err
    }

    // Step 2: redact (pure in-memory; no output manager needed)
    redactor := plaintext.NewPlainTextRedactor(nil, nil)
    redactor.SetPositionCorrelationEnabled(false) // 1:1 mapping for plaintext
    redacted, _, err := redactor.RedactString(input, result.Matches, redactors.RedactionFormatPreserving)
    return redacted, err
}
```

This path has no filesystem dependencies. It works in any environment that can import the `ferret-scan` Go module — Lambda, Fargate, gRPC, sidecar containers, etc. Note that `internal/` packages don't carry the same API stability guarantees as `pkg/redact`; prefer the public package for production code.

## Subprocess usage (non-Go callers)

When calling the binary from Python, Node, Java, etc., the canonical invocation for a gateway is:

```bash
echo "$INPUT" | ferret-scan --stdin --enable-redaction \
    --redaction-strategy format_preserving \
    --quiet --no-color \
    --format json --output /tmp/findings.json
# stdout: redacted content
# /tmp/findings.json: structured findings (no payload by default)
```

Recommended flags for production gateway use:

- `--quiet` — suppress human-readable progress prose so stderr stays parseable.
- `--no-color` — strip ANSI codes so log sinks render cleanly.
- `--enable-redaction` — make redacted content the primary stdout output.
- `--format json` (or `yaml`/`sarif`) + `--output <file>` — capture structured findings without interleaving them with the redacted stream.
- Avoid `--debug` — verbose validator-internal logging that adds latency and noise.

Exit codes follow `--pre-commit-mode` semantics when set: non-zero on findings at or above the configured confidence threshold.

## Limitations

- **Plaintext only**: stdin content is never run through the PDF/Office/image preprocessors. Use `--file` for binary documents.
- **Max size**: 100 MB (matches the file-mode `MaxFileSize`). Larger inputs are rejected with a clear error.
- **No redaction audit log**: `--redaction-audit-log <path>` is silently ignored with a stderr notice. Audit logs require the on-disk index manager. Scan a file if you need them.
- **No directory walk**: `--recursive`, `--exclude`, and `--respect-gitignore` don't apply (no filesystem to walk).
- **No PDF/Office redaction**: only the plaintext redactor runs against stdin content.

## Mutual-exclusion errors

ferret-scan validates flag combinations up-front so you get a clean error before any reading happens:

| Combination | Error |
|---|---|
| `--stdin --file <path>` | `--stdin and --file are mutually exclusive` |
| `--stdin <positional>` | `--stdin does not accept positional file arguments` |
| `--stdin --recursive` | `--stdin does not support --recursive` |
| `--stdin --web` | `--stdin and --web are mutually exclusive` |
| `--stdin` (no pipe) | `--stdin requires content to be piped on standard input` |

`--enable-redaction` and `--redaction-strategy` are **supported** with `--stdin` (they trigger the streaming gateway).

## Exit codes

Stdin mode follows the same exit-code semantics as file mode:

- **Default mode**: always exits `0` regardless of findings (so `cat input | ferret-scan --stdin` doesn't break shell scripts).
- **Pre-commit mode** (`--pre-commit-mode`): exits non-zero on findings at or above the configured confidence threshold. The redacted content is still emitted on stdout — a CI gateway can both produce clean output AND signal upstream that something was matched.

## See also

- [Main README — Reading from stdin](../../README.md#reading-from-stdin)
- [Redaction Guide](README-Redaction.md) — full redaction reference (file mode + strategies)
- [Application Flow](../ferret-application-flow.md) — sequence diagrams including the stdin alternative path
- [Architecture Diagram](../architecture-diagram.md) — Section 7 covers the streaming subsystem
