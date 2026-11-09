### ✅ Tests

- **surfaces (web UI, container):** the web UI and the container are held to the CLI's contract.
  `go test ./internal/web/` now posts all 97 golden-corpus inputs to `/scan` and compares the
  findings with the corpus's own scan (94 identical, 3 differing only in the Incomplete flag of a
  1 ns validator budget the web does not take), compares `/export` with the CLI formatter for every
  format and both switches (identical except three recorded losses: `/export` drops the explanation
  in json, yaml, sarif and gitlab-sast, the context keywords in verbose sarif, and the text
  formatter's verbose validation block), holds the export menu to `formatters.List()`, and fails
  when any of the 41 flags read from the built binary has no recorded web decision (15 with a web
  equivalent, 18 CLI-only, 8 undecided). `make surface-parity` runs the same inputs through the
  host CLI, the host web UI on 127.0.0.1, the container CLI and the container web UI published on
  127.0.0.1 only: on `main` all four report the same 391 findings, the container's redacted copies
  keep no reported value, and the run takes 59 s. `scripts/pr-checklist.sh` prints a surfaces line
  that is never N/A for a production change, and `docker-multiarch.yml` runs the container half on
  the smoke image ([#907](https://github.com/awslabs/ferret-scan/issues/907)).
