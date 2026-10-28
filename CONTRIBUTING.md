# Contributing Guidelines

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.

## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check [existing open](https://github.com/awslabs/ferret-scan/issues), or [recently closed](https://github.com/awslabs/ferret-scan/issues?utf8=%E2%9C%93&q=is%3Aissue%20is%3Aclosed%20), issues to make sure somebody else hasn't already
reported the issue. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used (`ferret-scan --version`)
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

**Do not include real sensitive data (credentials, SSNs, credit card numbers, personal information) in issues or pull
requests.** When reporting a detection bug, use synthetic test values (e.g. documentation IP ranges, invalid-checksum
card numbers) that reproduce the shape of the problem.

## Contributing via Pull Requests

Contributions via pull requests are much appreciated. Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Ensure local tests pass (`make test`; `make build` must also succeed).
4. Add a release-note fragment under [changelog.d/](changelog.d/) if your change affects what a release ships — see [CHANGELOG entries](#changelog-entries). Do not edit `CHANGELOG.md` for it.
5. Commit to your fork using clear commit messages, following the [Conventional Commits](docs/CONVENTIONAL_COMMITS.md) format used by this repository.
6. Send us a pull request, answering any default questions in the pull request interface.
7. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

GitHub provides additional documentation on [forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).

### Notes for detection/validator changes

Detection behavior is locked by a golden-file regression corpus (`internal/goldencorpus/`). If your change intentionally
alters detection, confidence scoring, output formats, or redaction, regenerate the snapshots with
`UPDATE_GOLDEN=1 go test ./internal/goldencorpus/...` and include the resulting diff in your pull request — an
unexplained golden diff will be treated as a regression. Test fixtures must use only synthetic values.

### CHANGELOG entries

[CHANGELOG.md](CHANGELOG.md) is hand-written prose, and the release notes are built from it. Each
pull request writes its entry as a file of its own under [changelog.d/](changelog.d/); when a release
tag is pushed, every fragment there is rendered into a dated section of `CHANGELOG.md`, line for
line, and removed. An entry left out of a PR is therefore left out of the release. Entries used to
be added under `## [Unreleased]` directly, and every PR edited the same lines there, so any two open
PRs conflicted ([#821](https://github.com/awslabs/ferret-scan/issues/821)).

A pull request **needs a fragment** when it changes what a release ships: any non-test Go file
under `cmd/` or `pkg/` or in a package they import, a file those packages embed,
`go.mod`, `.go-version`, the pre-commit hook definitions (`.pre-commit-hooks.yaml` and the root
`pyproject.toml` stub), or the PyPI wrapper (`python-package/ferret_scan/`, its `pyproject.toml`,
`setup.py` and `MANIFEST.in`) — or when its title is marked breaking (`feat!:`, `fix(scope)!:`).
Tests, docs, CI, the runtime config files and test-support packages need none. The `CHANGELOG`
check computes the Go part from the import graph and tells you which of your files triggered it.

Name the file `changelog.d/NNNN-slug.md`: NNNN is the issue number zero-padded to four digits, the
slug is lowercase kebab-case (`changelog.d/0800-otp-lowercase-word-not-base32.md`). Its content is
exactly the entry you would have written under `[Unreleased]`: one heading from the canonical list
in [changelog.d/README.md](changelog.d/README.md), a blank line, then `- ` bullets with continuation
lines indented two spaces, and nothing else. `make changelog-preview` prints the section your
fragment will land in. The check validates every fragment a PR adds or edits, and fails a PR that
adds an entry under `## [Unreleased]` in `CHANGELOG.md` itself.

Write for the person upgrading: what changed in behaviour, and what they should do about it. If a
required PR genuinely has nothing user-visible — a pure refactor, say — add the `no-changelog` label
instead; that records the decision on the PR. Dependabot PRs are exempt.

## Finding contributions to work on

Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any ['help wanted'](https://github.com/awslabs/ferret-scan/labels/help%20wanted) issues is a great place to start.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact
opensource-codeofconduct@amazon.com with any additional questions or comments.

## Security issue notifications

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.

## Licensing

See the [LICENSE](LICENSE.txt) file for our project's licensing. We will ask you to confirm the licensing of your contribution.
