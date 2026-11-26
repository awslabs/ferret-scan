### ⚡ Performance

- **Output / memory:** the five document-level context values no longer ride on every finding's `metadata`:
  `context_domain`, `context_doctype`, `context_confidence`, `semantic_context` (written by both document
  bridges) and `context_doc_type` (the secrets validator's second spelling of the document type). They were
  the same value for every finding of a file. The document context is still computed and still drives the
  confidence adjustment; only the per-finding copy is gone. 60,000-line input, 120,000 findings, peak RSS
  minimum of 3: text 557 -> 410 MB (-26.4%), json 1222 -> 804 MB (-34.2%), sarif 1953 -> 1592 MB (-18.5%);
  output size json 126.7 -> 91.4 MB (-27.8%), sarif 244.0 -> 201.8 MB (-17.3%), text unchanged. On the 639-file
  public corpus json is 20.0 -> 15.4 MB (-23.3%), yaml -23.6%, sarif -12.3%, and findings are 0 new, 0 lost,
  0 changed. The per-finding retention budget in `finding_retention_test.go` drops from 1200 to 1100 B
  (590-630 B measured). Fixes [#621](https://github.com/awslabs/ferret-scan/issues/621).
  ⚠ Four undocumented per-finding `metadata` keys (`context_domain`, `context_doctype`, `context_confidence`,
  `semantic_context`) and `context_doc_type` are gone from `json`, `yaml` and `sarif` output; a consumer
  keyed on them sees them missing. The values remain in the document context, not in the report.
