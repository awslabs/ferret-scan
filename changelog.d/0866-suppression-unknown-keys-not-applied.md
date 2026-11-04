### ⚠️ Breaking Changes

- **suppressions:** a suppression rule that carries a key other than `id`, `hash`, `reason`,
  `enabled`, `created_by`, `created_at`, `last_seen_at`, `expires_at`, `reviewed_by`, `reviewed_at`
  and `metadata`, or a `metadata` key with one of those names, no longer suppresses, and a file whose
  `version` is not `"1.0"` suppresses nothing; each case is named on stderr with its line. Before,
  such a rule applied with the key silently ignored, which made a misspelled expiry permanent
  ([#866](https://github.com/awslabs/ferret-scan/issues/866)). To migrate, move a custom rule key
  under `metadata:` (under a name that is not a rule key), correct a misspelled one, and set
  `version: "1.0"`. No finding hash changes, and a file the tool generated is unaffected.
