### 🐛 Bug Fixes

- **cli (`--stdin --generate-suppressions`):** on the `--stdin --enable-redaction` gateway, whose stderr
  is the findings document, `--generate-suppressions` no longer writes its "Updated suppression rules: …"
  lines ahead of that document ([#887](https://github.com/awslabs/ferret-scan/issues/887)). Measured on
  main with `--format json` and two findings: stderr began with that line and did not parse as JSON, and
  with no finding it held a bare "No findings to generate suppression rules for" where the gateway
  otherwise writes nothing; now stderr is the JSON document (or empty), as `2> findings.json` expects,
  and the rule file is written as before. Everywhere stderr is a human channel the lines are unchanged,
  and a failure to write the rule file is still printed. The generating run's findings,
  `stats.suppressed`, exit code and rules were already those of `--file` and are unchanged.
