# Conventional Commits

This repository follows [Conventional Commits](https://www.conventionalcommits.org/).
The format is not cosmetic: `scripts/check-commit-format.sh` validates it, and the
release tooling derives the next version number from the commit types on `main`
(see [SEMANTIC_RELEASE.md](SEMANTIC_RELEASE.md) and
[AUTOMATED_VERSIONING.md](AUTOMATED_VERSIONING.md)). A malformed subject line can
therefore ship the wrong version, not just read oddly.

## Format

```text
type(scope)!: description

[optional body]

[optional footer(s)]
```

- **type** — required, lowercase, from the list below.
- **scope** — optional, in parentheses. Use the package or validator the change
  touches (`validators`, `formatters`, `router`, `redactors`, `preprocessors`,
  `suppressions`, `config`, `golden`, `brew`), or a specific validator
  (`passport`, `medicalid`, `ssn`, `dob`, `creditcard`, `otp`, `personname`,
  `socialmedia`). Multiple scopes are comma-separated: `fix(phone,driverslicense):`.
- **!** — optional, marks a breaking change. Pair it with a `BREAKING CHANGE:`
  footer explaining the migration.
- **description** — required, imperative mood, no trailing period.

## Types

The validator accepts exactly these eleven:

| Type | Meaning | Version bump |
|---|---|---|
| `feat` | A new feature | **minor** |
| `fix` | A bug fix | patch |
| `perf` | A performance improvement | patch |
| `revert` | Reverts a previous commit | patch |
| `refactor` | Restructuring with no behavior change | patch |
| `build` | Build system or dependencies | patch |
| `docs` | Documentation only | patch (for README scope) |
| `test` | Tests only | none |
| `style` | Formatting only, no logic change | none |
| `ci` | CI configuration | none |
| `chore` | Maintenance that fits nothing above | none |

A `!` or a `BREAKING CHANGE:` footer forces a **major** bump regardless of type.

## Examples

Drawn from this repository's history:

```text
fix(passport): treat a CSV column header as context for its column's values
feat(passport): detect MRZ line 2 and verify its ICAO check digits
perf(preprocessors): hoist line offsets out of the mapping loop
test(golden): add PASSPORT and VIN cases, and lock the cross-line leak
docs(goldencorpus): correct two stale claims about what the harness normalizes
build: test the UNION of open PRs, not just each PR against main
fix(phone,driverslicense): stop a nearby keyword deleting a real finding
```

A breaking change:

```text
feat!: redesign configuration file structure

BREAKING CHANGE: Configuration file format has changed. See the migration guide.
```

## Writing the description

This project scans for sensitive data, so a commit that changes detection is a
commit that changes what leaks. Two conventions follow from that:

- **Say what changed in behavior, not which function you edited.** "stop a nearby
  keyword deleting a real finding" tells a reviewer what was broken;
  "update phone validator" does not.
- **Never put a real matched value in a commit message.** Use a synthetic example
  or describe the shape. The same rule applies to PR titles and bodies.

## Checking before you push

```bash
./scripts/check-commit-format.sh              # the last commit
./scripts/check-commit-format.sh HEAD~5..HEAD # a range
```

The script prints a verdict per commit. Note that it reports problems but exits 0,
so read the output rather than relying on the exit status.
