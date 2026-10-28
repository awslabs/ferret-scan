### 🐛 Bug Fixes

- **redaction (overlapping findings):** two findings on one line whose values share bytes are now one
  write over their union, in every writer, so no part of either survives and which one is written no
  longer depends on input order ([#773](https://github.com/awslabs/ferret-scan/issues/773)). Each writer
  applied findings one at a time, locating each by its text in content an earlier write had already
  changed, so the second of two crossing values was skipped: `Residence: 77 August Lane, Boise ID 83702`
  (an address and two names) came out as `Residence: 77 August *********** ID 83702` from `.txt`,
  `--stdin`, `pkg/scan` and `pkg/redact`, as `**************, Boise ID 83702` from `.docx`, and as
  `77 ***********, Boise ID 83702` from legacy `.doc`/`.xls`/`.ppt`, which had no overlap pass at all and
  leaked containment too (`Located at 100 ****************** Blvd`) -- each at exit 0, with an audit log
  reporting `failed_redactions: 0`. For the same bytes reported twice (`PASSPORT` and `SSN` on one
  9-digit number) the writer's sort tied and `sort.Slice` broke the tie by algorithm, which changes at 13
  elements: `Passport number: 512010001` kept its last four digits (`*****0001`) or not depending on how
  many unrelated findings the file held. A group now renders by one rule: a contained finding collapses
  into the widest, as before, except that no original letter or digit inside a contained SECRETS finding
  is copied; the same bytes take the highest-confidence finding's label and keep a character only if
  every finding on them would; crossing findings are masked whole under `format_preserving` and take the
  highest-confidence placeholder under `simple`. Measured over the repository's 1,717 tracked files
  (11,451 findings): of 87 same-span pairs whose types disagree on the last four digits, 32 kept them and
  now 0 do; of 22 crossing pairs, 21 left part of a value in cleartext and now 0 do. Findings,
  recall/precision and suppression hashes are unchanged. A group that cannot be located refuses the file
  instead of writing part of it, and the audit log records one entry per group with every member's type
  in `member_types`. The `secrets_uri_userinfo_email_overlap` snapshot now masks the password's first
  character, which the email's mask used to keep.
