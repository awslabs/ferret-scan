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

### The library and the web UI

Two consumers derived their own, poorer view of the same taxonomy, so the same scan was described
differently depending on where you read it:

| consumer | before | now |
|---|---|---|
| `pkg/scan` | `Incomplete bool` + one prose line | `Result.NotExamined[]` with `{Path, Cause, Detail}` ([#391](https://github.com/awslabs/ferret-scan/issues/391)) |
| web UI `/scan` | `incomplete` + `incomplete_reason` | `not_examined[]` with `{path, cause, detail}` ([#417](https://github.com/awslabs/ferret-scan/issues/417)) |

`Cause` is one of the six strings in the table below, spelled **identically** to what the CLI prints, so
a phrase carried from the browser or a library caller into a grep over CI logs matches. It is empty when
no producer stated a cause, which a consumer should present as unknown rather than guessing one — the
prose classifier it would otherwise fall back to defaults to `coverage cut short`, which claims a file
was partly scanned when it may not have been read at all.

Both fields are omitted when a scan is complete, so a clean scan's output is unchanged.

Why they diverged in the first place: a coverage-loss record carried only prose, and each consumer
recovered the cause by pattern-matching English. Measured against the real producer strings, **8 of 14**
came back with a cause other than the one the producer meant — six of them from a classifier's default
arm. The producer now states the cause ([#432](https://github.com/awslabs/ferret-scan/issues/432),
[#412](https://github.com/awslabs/ferret-scan/issues/412)) and the classifiers remain only as a fallback
for records that carry none.

## The six causes

| cause | meaning | were findings possible? |
|---|---|---|
| `cannot read` | permissions, vanished path, I/O error | nothing about the file is known |
| `cannot parse` | bytes do not match the declared type | no text was recovered |
| `no body text (metadata still scanned)` | opened and parsed, no body text found | **yes** — metadata was scanned and may already have produced findings |
| `coverage cut short` | a budget, size cap or timeout fired | **yes** — the file is partly scanned |
| `symlink not followed` | a link that dangles, loops, names a directory or device, or resolves outside the scanned tree | the target was never read; scan it directly |
| `file too large to scan` | over the size limit, so never opened — and of a type the tool WOULD have processed | no |
| `not a regular file` | the directory entry is a named pipe, socket or device node, or on Windows a junction, mount point or other non-symlink reparse point | the entry was never opened; it is not readable content |

The third and fourth never claim the file was unread. A `.docx` with an empty body but
PII in its author field appears both as findings *and* in this list, and saying its
contents were never read would contradict the same report.

`symlink not followed` (#326), `file too large to scan` (#324) and `not a regular file`
(#485) were added to the code after this table was written and are documented here
retroactively; all three are deliberately distinct from `cannot read`, which would assert
a failure that did not happen — for most of those files the bytes could have been read and
the tool declined.

`not a regular file` is also distinct from `symlink not followed`, and the distinction is
not pedantic: there is no link involved, the entry itself IS the pipe or device. Reporting
it as a symlink would be a true disclosure under a false heading. Before #485 such an entry
reached no counter at all — a directory holding one ordinary file and one named pipe
reported `total_files: 1` and exit 0, byte-for-byte the same accounting as the same
directory without the pipe, and `--fail-on-incomplete` also exited 0.

An **unprocessable** type refused for size is not listed at all. It is a genuine skip: no
finding was ever possible from it, so reporting lost coverage would be reporting a
non-event.

### What `coverage cut short` covers inside a container

A container is partly scanned when one of its parts could not be examined, and the
container's own text was read normally. Four cases reach this cause:

| case | what the operator sees |
|---|---|
| an embedded part over the 50 MB embedded cap | `embedded part "attachment.docx" was not examined: declares N bytes, over the 52428800-byte embedded cap` |
| an embedded part whose bytes could not be extracted | `embedded part "broken.jpg" was not examined: flate: corrupt input before offset 1` |
| an embedded container past the nesting bound (3) | `embedded item "attachment.docx" was not examined: embedded container nesting limit reached` |
| embedded parts past the 4096-part count cap | `195904 embedded part(s) beyond the 4096-part limit were not examined (container declares 200000)` |

The count cap reports **one line for the whole overflow**, not one per part, and states the
container's true total so the number is actionable — a count without the total cannot tell you
whether to raise the cap or to distrust the document. It is deliberately a separate line from the
per-part refusals above, because "never attempted" and "failed to read" send an operator to look
in different places.

The first two used to be **silent** (#374): the part was skipped, the container reported
`No matches found` at exit 0, and `--fail-on-incomplete` also exited 0 — while the same
inner document under the cap reported its SSN at HIGH 100. All three are now `coverage cut
short` rather than `no body text`, because the container's body text *was* read: claiming
otherwise describes a failure that did not happen.

An embedded part of a type nothing can read stays silent on purpose. A line on stderr for
every decorative `.emf` in every slide deck trains operators to ignore the warnings that
matter.

### What `coverage cut short` covers in a video container

Video metadata sits in the `moov` box, which the standards permit anywhere in the file and which
ffmpeg and typical cameras write **last**. The box walk reads only headers and metadata boxes, so a
`moov` at the end of a 99 MB recording is read like one at the start. Six cases stop it early, and
each says so:

| case | what the operator sees |
|---|---|
| no `moov` box in the file | `video metadata may be incomplete: no moov box was found in the file` |
| a box declaring more bytes than the file holds | `video metadata may be incomplete: the "mdat" box at offset N declares more bytes than the file holds, so it was read only to the file's real end` |
| a box smaller than its own header, or an unfollowable structure | `video metadata may be incomplete: the box structure could not be followed past offset N (...)` |
| a `moov` past the 32 MB parse limit | `video metadata may be incomplete: the moov box is N bytes and only the first 33554432 were parsed` |
| a `moov` that could not be read or parsed in full | `video metadata may be incomplete: the moov box at offset N could not be read in full (...)` |
| more than 1,048,576 top-level boxes | `video metadata may be incomplete: the box walk stopped after 1048576 top-level boxes` |

All six were **silent** before #398, and so was the much larger case they sit alongside: the walk
used to stop once it had passed a 10 MB *file offset*, counting the media bytes it skipped without
reading. A camera-default recording over roughly 10 MB therefore reported no metadata at all, at
exit 0, with nothing under `files_not_examined` — and `--fail-on-incomplete` exited 0 too. The same
file with its `moov` moved to the front reported an SSN at HIGH 100.

These are `coverage cut short` rather than `no body text` for the same reason as the container cases
above: some of the file genuinely was read. An over-declared `moov` is clamped to the file's real end
and still yields whatever values are present, so a disclosure here does not mean nothing was found.

A well-formed video never produces any of these lines.

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
