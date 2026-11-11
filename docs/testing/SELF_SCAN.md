<!--
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
-->

# The repository self-scan

ferret-scan scans its own repository, and a HIGH finding that nobody has decided about fails the
scan (#927). This tree is full of values that look sensitive on purpose: test fixtures, regexes,
documentation examples, measured reproductions quoted in comments. The self-scan exists so that every
one of them is a recorded decision, and so that a real leak cannot hide among them.

| File | What it is |
|---|---|
| [`scripts/self-scan.sh`](../../scripts/self-scan.sh) | The scan. `make self-scan` runs it; its header is the contract (flags, exit codes). |
| [`.ferret-scan/selfscan.yaml`](../../.ferret-scan/selfscan.yaml) | The profile: what is excluded and why, and which suppression ledger is read. |
| [`.ferret-scan-suppressions.yaml`](../../.ferret-scan-suppressions.yaml) | The ledger: one reviewed rule per accepted finding, each with its reason. |
| this file | How the three fit together, and what to do with a new HIGH finding. |

Run it the way CI does, and against `main` to see what your branch changed:

```bash
make self-scan
make self-scan SELF_SCAN_ARGS='--base origin/main'
```

## The two gates

Every file the profile does not exclude goes through exactly one gate. Both run at
`--confidence high` with `--fail-on-incomplete` and `--limit 0`, through the profile and the ledger.

| Gate | Files | Checks | Why |
|---|---|---|---|
| shippable | everything that is not `*_test.go`: Go sources, scripts, workflows, configs, docs | all | Anything here ships or is published; a HIGH finding in it is a value someone reads. |
| tests | `*_test.go` | `SECRETS` only | Synthetic personal data in a test is the test's job, and gating it would turn every validator test into a ledger entry. A real credential is never a fixture: a token committed in a test is as live as one in code, so credentials are gated in tests as everywhere else. |

The counts come from each report's `stats` (`.stats.high`), never from `results`, and
`stats.suppressed` is printed beside them, so a suppressed finding is visible as a suppression rather
than as an absence (TM-11). The script exits 0 when no unsuppressed HIGH finding is left, 1 when one is
(in `--mode block`, the default), and 2 when it cannot vouch for the result: a scan failed, a file was
not fully examined, a count was missing or not a number. Exit 2 is fail-closed; it never reads as green.

`--scope tree` (the default) scans the checkout: tracked files plus untracked files git does not
ignore. `--scope changed` scans only the files `--files` lists (one path per line, any extension), or,
without `--files`, the files that differ from the merge base with `--base`. Both scopes go through the
same gates: each gate scans a copy of its files laid out at their repository paths, so the profile's
patterns and the reported file names mean the same thing in both.

`--base REF` builds `REF` too (with `git archive`, as `scripts/corpus-ab.sh` does), runs the same gates
over `REF`'s files with this checkout's profile and ledger, and prints the HIGH findings that are new,
lost and changed against `REF`, by file class. Findings are keyed on
`(file, validator, type, line, sha256(text))`; the text is hashed in memory and shown as 12 hex digits,
never printed. A finding whose line moved is reported as changed, not as lost plus new.

## What the profile excludes, and why

Excluded is not unscanned. After the gates, a report-only pass scans every path the profile excluded,
with every check at MEDIUM and above and no suppressions, and prints the counts by path, so drift in
the corpora stays visible. That pass never fails the run.

| Pattern | Why it is sensitive by construction | HIGH on `main` @ 5fecf59 |
|---|---|---|
| `.git/**` | Version-control metadata, not part of the tree: the commit authors' addresses in the reflogs read as e-mail. | 210, all `BUSINESS`, in the checkout #927 was measured in |
| `build/**` | Output of `make build`; generated and untracked. | 0 |
| `internal/goldencorpus/testdata/**` | The golden snapshots: the recorded output of every golden case, deliberate findings by design. | 1,832 |
| `internal/goldencorpus/corpus.go` | The golden case inputs, in Go source: values chosen to be found. | 91 |
| `internal/scorecorpus/**` | The labelled score corpus: its positive cases are realistic values by design. | 543 |
| `**/testdata/**` | Fixture files under any other `testdata/` directory. | 92 |

A new exclude needs a measured reason in the same form, in the profile and in its pull request. The
profile is not a user config: `config.yaml` at the root is the example users copy, and the profile
changes no validator setting, so the gate sees what a user with no config would see.

Measured on `main` @ 5fecf59 with `--config /dev/null --confidence high`, the tree held 6,222 HIGH
findings outside `.git/` (the 6,432 in #927 counted 210 in `.git/`, because a second `--exclude` flag
replaces the first). The excludes leave 562 in shippable files and, with `--checks SECRETS`, 86 in
tests: those 648 are what the ledger reviewed.

## A new HIGH in your pull request

Every HIGH finding the gate reports is one of three things, and each has one action:

1. **A real value**: a credential, or data about a real person. Remove it from the tree and report it
   (a leaked credential is revoked first; removing it from the tree does not un-publish it). It is
   never suppressed. The first run of this gate found three: a photographer's name and a vendor
   employee's address copied from sample-file metadata into a release note, a guide, a comment and a
   test fixture; #942 replaced them with a role and a synthetic value.
2. **A detector false positive**: the value is not what the check says it is (a place read as a name, a
   regex read as a secret). Fix the validator and add a decoy case to the golden corpus. Until the fix
   lands, add a rule with the reason `detector FP: #NNN`, naming the issue that fixes it; one issue per
   mechanism, not per finding.
3. **A fixture**: the value is synthetic and has to look real where it is (a test input the test asserts
   is reported, a documentation example of what a check reports). Use a reserved value below if the
   check demotes one for that type; otherwise add a rule with the reason `fixture: <why it must look real>`.

`--base origin/main` lists exactly the findings your branch added. A finding that is new in a file you
did not touch comes from a validator change: CI's changed-files scan cannot see it, which is why the
test plan asks for this run ([dimension 15](TEST_PLAN.md#15-self-scan-always)).

## Reserved and published example values

A value from this table is demoted by the current validators, so a fixture or a doc example that uses
it needs no rule. Each was measured alone in a one-line file with the binary built from `main` @ 5fecf59
(`--config /dev/null --confidence all`):

| Type | Value | Measured |
|---|---|---|
| Email | `jane.doe@example.com`, `@example.org`, `@example.net` (RFC 2606) | `BUSINESS` 61, MEDIUM |
| Email | `jane.doe@mail.invalid`, `jane.doe@mail.test` (RFC 2606 top-level domains) | `BUSINESS` 55, LOW |
| Phone (NANP) | `(212) 555-0187`, `+1 212 555 0187`: the 555-0100 to 555-0199 range | `PHONE` 15, LOW |
| SSN | `987-65-4320` to `987-65-4329`, the SSA's advertising range | no finding |
| SSN | area 000 or 666, for example `666-12-3456` | no `SSN` finding |
| AWS access key ID | `AKIAIOSFODNN7EXAMPLE`, the AWS documentation example | `AWS_ACCESS_KEY` 15, LOW |
| Payment card | `4111 1111 1111 1111`, `4242 4242 4242 4242`, `5555 5555 5555 4444`, `3782 822463 10005`, `6011 1111 1111 1117` | 15, LOW |
| IP address | `192.0.2.10`, `198.51.100.7`, `203.0.113.42` (RFC 5737), `2001:db8::10` (RFC 3849) | no finding |
| Person name | `John Doe`, `Jane Doe` | `PERSON_NAME` 66, MEDIUM |

These published examples still read HIGH and are listed in #930, which fixes them; until it lands, a
fixture that uses one needs a `detector FP: #930` rule, so prefer a value from the table above:

- the AWS documentation example secret access key on any line but an `aws_secret_access_key =`
  assignment (on that line it reads `AWS_SECRET_ACCESS_KEY` 15, LOW; on a generic `secret = "…"` line it
  reads `API_KEY_OR_SECRET` 100);
- the documented example TOTP secret on a generic `secret` line (100), Stripe's documented test keys
  (`STRIPE_API_KEY` 100), the jwt.io example token (`JWT_TOKEN` 100), the Google Maps samples key (100);
- the published example IBANs (`IBAN` 100), the widely published example VIN (`VIN` 100), the CMS
  check-digit example NPI (`NPI` 90);
- Ofcom's drama telephone ranges, London and Manchester (`PHONE` 100; the French fiction range gives no
  finding on `main` and reads 100 with the international forms of #920), and the AWS documentation
  account ID inside an ARN (`AWS_ARN` 95; alone it gives no finding).

The values themselves are in #930, so that this page does not need a rule of its own.

## The ledger

Every rule in `.ferret-scan-suppressions.yaml` is enabled, has no expiry, and gives one of three reasons:

- `fixture: <why the value must look real>`;
- `detector FP: #NNN`, where issue NNN fixes the detector and the rule goes when it lands;
- `public: <why the value is legitimately public>`, for the few findings that are neither: a copyright
  holder named in a third-party licence this repository must reproduce, the project's own licence
  notice, the code-of-conduct contact address. A real credential or a real person's private data is
  never a rule (see above).

The first ledger (2026-11-09, `main` at d641fe7) holds 666 rules: 525 `fixture`, 135 `detector FP`
(across #930–#940) and 6 `public`, covering 672 HIGH findings; the gate then reads `HIGH 0`. The v2.6.0
promotion then moved 39 of those findings from `changelog.d/` fragments into `CHANGELOG.md` and the
ledger followed (42 fragment rules out, 39 `CHANGELOG.md` rules in with the same reasons): 663 rules,
522 `fixture`, 135 `detector FP` and 6 `public`.
Rule IDs are not contiguous after a deletion, and the generator numbers a new rule from the highest ID.

A rule matches a finding by its identity hash: the type, the line, the file's basename, the line number,
the surrounding text and the value. Its `metadata` (type, file name, line number, confidence) names the
finding for a reader; leave it as the generator writes it, since re-anchoring reads `line_number`.

### Regenerating and re-anchoring

A rule goes stale when its finding moves: an edit above it shifts its line, or its file is renamed. The
gate then reports the finding again, which is the signal to regenerate:

```bash
scripts/self-scan.sh --regenerate "$TMPDIR/ledger.yaml"
```

The candidate it writes is the current ledger plus a DISABLED rule, with the generator's placeholder
reason, for every HIGH finding of either gate that no rule covers. Every other rule is kept byte for byte,
so the diff shows only what changed. The summary lists three groups:

- **new**: review each one. Give it a reason of one of the two kinds and set `enabled: true`, or, for a
  real value, delete the rule and remove the value.
- **rewritten**: rules the binary re-anchored to the finding they moved with (once #918 is merged; it
  pairs a stale rule with its moved finding one to one), or migrated to the current hash formula. Their
  reasons are unchanged; check that each still fits.
- **stale**: rules no finding matched. Without re-anchoring, a moved finding appears as a stale rule
  plus a new one: copy the reason across and delete the stale rule. A stale rule whose finding is gone
  (the value was removed, or a detector fix landed) is deleted.

Then copy the candidate over the ledger and run `make self-scan` until it is green. Generation runs twice
on purpose: in one pass, a second finding on the same line can take over a rule just written for the
first (the generator migrates a rule it matched through an older hash formula), and the second pass adds
the rule the first finding lacks.

A release moves every line of `CHANGELOG.md` (`scripts/promote-changelog.sh` inserts the new section
below `[Unreleased]`), so the release pull request regenerates the ledger for the rules that sit in it.

## CI

`.github/workflows/ferret-scan.yml` runs this script in block mode: on a pull request over the files
the PR changes (`--scope changed --files …`, any extension), and over the whole tree on a push to
`main` and on a manual run with `scan_scope: full-repository` (`--scope tree`; the dispatch default,
`changed-files`, scans the last commit's files). The script's exit is the gate: 1 for a HIGH finding the
ledger does not cover, 2 for a scan that failed or did not fully examine a file, both red. The
workflow reads `summary.env` for the job summary and the pull-request comment, which show HIGH,
suppressed and not-examined counts and point here; `cmd/self_scan_workflow_test.go` pins that contract
and runs the workflow's steps against a checkout with a HIGH fixture in each mode. A copy of the
workflow in another repository needs the script and a profile of its own (`docs/TEAM_SETUP_GUIDE.md`).

## In the test plan

Dimension 15 of [TEST_PLAN.md](TEST_PLAN.md#15-self-scan-always) asks for this run before every pull
request, and its Applicability table lists 15 in every row, docs included.

## Known limits

- The profile lives under `.ferret-scan/`, which `.gitignore` ignores (`.ferret-*`). The profile is
  tracked, so edits to it are seen; a new file under `.ferret-scan/` needs `git add -f`.
- A rule names a file by its basename, so a rule for `README.md:14` also suppresses an identical finding
  on line 14 of another `README.md` with the same line and context. The context makes that rare; it is
  the identity the suppression format has.
