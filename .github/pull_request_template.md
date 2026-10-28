## What

<!-- What changes for someone running ferret-scan, and why. -->

## Verification

<!-- How you know it works: tests added, commands run, before/after output. -->

## Checklist

- [ ] `make test` and `make build` pass
- [ ] **CHANGELOG:** a fragment `changelog.d/NNNN-slug.md` ([format](https://github.com/awslabs/ferret-scan/blob/main/changelog.d/README.md)) if this changes what a release ships — or the `no-changelog` label if nothing user-visible changed ([CONTRIBUTING](https://github.com/awslabs/ferret-scan/blob/main/CONTRIBUTING.md#changelog-entries)). Do not edit `## [Unreleased]` in `CHANGELOG.md`. The `CHANGELOG` check reports on this.
- [ ] Golden corpus regenerated and the diff explained, if detection, scoring, output or redaction changed
- [ ] `Closes #N` for any issue this resolves
