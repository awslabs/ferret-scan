### 🐛 Bug Fixes

- **suppressions (loader):** the loader ignored every key it did not know, so an expiry spelled
  `expries_at`, `expiresAt`, `expires`, `expiry`, `expire_at`, `expires_on` or `expiration`, or
  nested under `metadata:`, turned a lapsed rule into a permanent one: on two findings, 2 reported
  and pre-commit exit 1 with `expires_at` became 0 reported, exit 0 and no expiry warning with each of
  the other eight. A rule carrying a key this version does not recognise, or a `metadata` key named
  like a rule key, is now kept but not applied, and a file whose `version` is not `"1.0"` applies no
  rules; all eight now report 2 findings at exit 1 and name the rule, the key and its line on stderr,
  under `--quiet` and pre-commit mode too. Shapes that cannot widen a suppressor are named and load as
  before: an unknown top-level key (`rule:` or `suppressions:` instead of `rules:` now says "0 rules
  loaded … rules belong under "rules:""), a missing, non-hex or upper-case `hash`, an `id` two rules
  share. The committed 245-rule baseline, generated files and the examples in
  `docs/suppression-system.md` and `docs/PRE_COMMIT_INTEGRATION.md` name nothing
  ([#866](https://github.com/awslabs/ferret-scan/issues/866)).
- **suppressions (save):** every save marshalled the in-memory struct, deleting all comments and
  unknown keys: one `--generate-suppressions` run removed this repository's 33-line baseline header,
  and regenerating a file with a misspelled expiry deleted the misspelling, making the rule permanent.
  Saves now patch the file they loaded, rewriting only changed fields: regenerating the baseline
  changes only `last_seen_at` lines and appends new rules, and its header survives byte for byte
  ([#866](https://github.com/awslabs/ferret-scan/issues/866)).
- **suppressions (expiry warning):** the lapsed-rule count was per match call, so under
  `--enable-redaction` (which matches each finding twice) two findings were reported as
  "4 finding(s)", and a manager whose index was built lazily never counted. Each finding now counts
  once, and not at all when a live rule still suppresses it: the redaction run reads "2 finding(s)"
  ([#866](https://github.com/awslabs/ferret-scan/issues/866)).
