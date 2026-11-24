### 📚 Documentation

- **CREDIT_CARD rule text, `--quiet` help, doc leftovers:** the CREDIT_CARD rule description now says that a
  number a payment processor publishes as a test card is still reported and redacted but capped at 15 (LOW),
  in `docs/checks.md` and in the SARIF rule's `help` text; the `--quiet` line of `--help` matches the help
  page (it also withholds the suppression, exclusion and config-provenance notes); the phone check's help
  lists the French national form; the threat model, `docs/suppression-system.md`, `docs/configuration.md` and
  the passport README no longer carry statements that #1056, #1002, #1072 and #992 made false.
  ⚠ The SARIF `help.text` of the `CREDIT_CARD` rule (and of the card-brand rules that inherit it) gains one
  sentence, and the `--quiet` flag's usage string changes; no finding, score or exit code changes
  ([#883](https://github.com/awslabs/ferret-scan/issues/883), [#933](https://github.com/awslabs/ferret-scan/issues/933)).
