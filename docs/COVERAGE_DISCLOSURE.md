# Coverage disclosure: files that were not examined

A file the scanner could not read is **not** a file with no findings. This document
records where each output format says so, and the one place it cannot.

## Why this exists

Only reported facts reach the consumer. If a scan cannot open a file and says nothing
about it, a pipeline parsing the output concludes the file is clean — and it may hold
anything. That is the same class of harm as a missed detection, arriving by a
different route.

Measured on a directory holding one findings-bearing `.txt`, one unreadable file and
one `.docx` whose body could not be extracted, the in-band signal on **stdout** was:

| format | before | now |
|---|---|---|
| `text` | in-band summary footer | unchanged |
| `json` | `stats.files_not_examined` | unchanged |
| `yaml` | `filesnotexamined` | unchanged |
| `csv` | **nothing** | stderr only (see below) |
| `junit` | **nothing** | `<testsuite name="not-examined">` |
| `sarif` | **nothing** | `runs[].invocations[].toolExecutionNotifications[]` |
| `gitlab-sast` | **nothing** | `scan.messages[]` |

The human-readable report was always produced for the machine formats — it went to
**stderr**, which pipelines routinely discard.

## The four causes

| cause | meaning | were findings possible? |
|---|---|---|
| `cannot read` | permissions, vanished path, I/O error | nothing about the file is known |
| `cannot parse` | bytes do not match the declared type | no text was recovered |
| `no body text (metadata still scanned)` | opened and parsed, no body text found | **yes** — metadata was scanned and may already have produced findings |
| `coverage cut short` | a budget, size cap or timeout fired | **yes** — the file is partly scanned |

The third and fourth never claim the file was unread. A `.docx` with an empty body but
PII in its author field appears both as findings *and* in this list, and saying its
contents were never read would contradict the same report.

## Per-format details

### gitlab-sast — `scan.messages[]`

A first-class schema field, not an extension. Level is `warn`, whose schema
description is this case exactly: *"a potentially recoverable problem, or a partial
error"*.

```json
"scan": {
  "status": "success",
  "messages": [
    { "level": "warn", "value": "NOT FULLY EXAMINED: 2 file(s) — findings may be missing" },
    { "level": "warn", "value": "NOT EXAMINED (cannot read): /scan/noperm.txt — permission denied" }
  ]
}
```

`status` stays `success`: the scan *succeeded*, its coverage was partial. The enum is
only `success|failure`, so `failure` would claim the analyzer broke. Unexamined files
are never injected into `vulnerabilities[]` — that would put fabricated findings on a
security dashboard.

### sarif — `invocations[].toolExecutionNotifications[]`

The spec's description of this array *is* the semantics: "runtime conditions detected
by the tool during the analysis". Level is `warning` (SARIF's enum is
`none/note/warning/error`).

```json
"invocations": [{
  "executionSuccessful": true,
  "toolExecutionNotifications": [
    { "descriptor": { "id": "ferret-scan/not-examined" },
      "level": "warning",
      "message": { "text": "NOT EXAMINED (cannot read): /scan/noperm.txt — permission denied" } }
  ]
}]
```

> **Note the enums differ.** GitLab uses `warn`; SARIF uses `warning`. Each is invalid
> in the other's schema, and an invalid report is rejected in full — losing every
> finding. They are not interchangeable.

`executionSuccessful` is always `true` for the same reason GitLab's status is
`success`.

**Known limitation:** GitHub's code-scanning UI does not display
`toolExecutionNotifications`, so this disclosure is machine-readable only. The
alternative — emitting unexamined files as `results` — would create dismissable
"alerts" for files that were never read, i.e. fabricated findings. A quiet valid
statement was preferred over a visible false one.

### junit — a separate `not-examined` suite

```xml
<testsuite name="not-examined" tests="2" failures="0" errors="0">
  <testcase name="noperm.txt" classname="not-examined">
    <skipped message="NOT EXAMINED (cannot read): /scan/noperm.txt — permission denied">...</skipped>
  </testcase>
  <system-out>NOT FULLY EXAMINED: 2 file(s) — findings may be missing</system-out>
</testsuite>
```

A separate suite, so the `security-scan` suite's `tests=` attribute keeps meaning
"files examined".

**Valence follows `--fail-on-incomplete`:**

| | element | build verdict |
|---|---|---|
| default | `<skipped>` | unchanged — a disclosure alone never turns a green build red |
| `--fail-on-incomplete` | `<error>` | fails, agreeing with exit code 3 |

Unexamined files are never `<failure>`: a failure means something was found wrong *in*
the file, and reporting "cannot read" that way fabricates a finding.

### csv — stderr only, by design

`csv` keeps this disclosure **out of band**, on stderr, for the same reason the
`--limit` note does: the format is a fixed row grammar with no metadata channel.
Every in-band option corrupts something.

- A leading `# NOT EXAMINED` comment makes Go's `encoding/csv` reject the document on
  field count, and Python's `DictReader` adopt the comment as the only fieldname — so
  every real row parses as garbage.
- A synthetic row with `Type=NOT_EXAMINED` is indistinguishable from a finding to
  every consumer.

**Residual gap, stated plainly:** a `--output report.csv` artifact read away from the
terminal *cannot* tell you coverage was incomplete. If you need machine-readable
coverage data, use `json`, `yaml`, `sarif` or `gitlab-sast`.

## Caps

Machine formats enumerate at most **50** entries and then state the total, so
truncation is never silent:

```
NOT FULLY EXAMINED: 312 file(s) — findings may be missing; 50 listed here, 262 omitted
```

The cap exists because an unbounded list is a denial of service against the consumer
— a tree with thousands of unreadable files would push a SARIF upload toward GitHub's
size-rejection limit, losing the whole report and defeating the point.

## Exit codes

The disclosure is independent of the exit code. Coverage gaps exit `0` by default; add
`--fail-on-incomplete` to exit `3`. That flag is also what switches the JUnit valence,
so one decision governs every channel.

## Testing

`internal/formatters/notexamined_disclosure_test.go` covers all four formats in one
file, because the property is cross-cutting: the regression to catch is *adding a
format without the disclosure*.

**The golden corpus cannot gate this.** Its harness builds `FormatterOptions` without
`Stats` or `NotExamined`, so every golden passes whether the feature works or not. A
green golden run is not evidence here.
