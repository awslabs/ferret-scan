# GitLab CI/CD Setup

How this repository's own GitLab pipeline is organised, and how to reproduce its checks locally.

> **If you want to run ferret-scan inside *your* pipeline** — as a security scanner producing GitLab
> SAST reports — that is a different task. See [GitLab Integration](../GITLAB_INTEGRATION.md) and
> [GitLab Security Scanner Setup](GITLAB_SECURITY_SCANNER_SETUP.md).

## Source of truth

[`.gitlab-ci.yml`](../../.gitlab-ci.yml) is the only authoritative description of the pipeline.

**This page deliberately does not list the jobs, stages or image versions.** An earlier revision did,
and every one of those lists drifted out of date — it documented a job matrix and a set of GitLab
Ultimate features that the pipeline had never contained, which is worse than documenting nothing
because a reader cannot tell an aspiration from a fact. To see what runs, read `.gitlab-ci.yml`: the
`stages:` list at the top gives the order, and each top-level key below it is a job.

## Reproducing CI checks locally

The pipeline runs the same `make` targets you can run on a workstation, so a red pipeline is almost
always reproducible before you push:

```bash
make test-unit          # fast tests, no external dependencies
make test-integration   # end-to-end workflows
make test-race          # race detector
make test-coverage      # coverage profile
```

`scripts/run-tests.sh` is the underlying runner if you want to select suites directly:

```bash
./scripts/run-tests.sh -t unit -v   # one suite, verbose
./scripts/run-tests.sh              # everything
```

These targets set `FERRET_TEST_MODE` themselves. Exporting it by hand changes nothing: it is read only
by `tests/helpers`, no production code consults it, and it enables no service mocking.

## Go version

The pipeline does not pin a Go version of its own. [`.go-version`](../../.go-version) is the single
source of truth, and `make sync-go-version` propagates it into `.gitlab-ci.yml`, `go.mod` and the
`Dockerfile`; `make check-go-version` verifies every pin still agrees and checks the Dockerfile digest
against the registry. Never hardcode a version here or in any other document — see
[Go Version Management](../GO_VERSION_MANAGEMENT.md).

## Variables and caching

Pipeline variables are declared in the `variables:` block of `.gitlab-ci.yml`. Two things are worth
knowing because they are easy to assume wrongly:

- **There are no AWS credentials or endpoints in the pipeline.** No `AWS_*` variable is set anywhere in
  the CI configuration, and no job requires cloud access.
- **The cache is deliberately conservative**, scoped to the Go module cache rather than every build
  artifact, because the runner storage budget is small. If you add a job, do not widen the cache
  without checking that budget.

## What this pipeline does *not* include

Listed because the absence is a design decision rather than an oversight, and because a previous
version of this page claimed all of them:

| Not configured | Note |
|---|---|
| GitLab Pages | No documentation or coverage site is published. |
| Coverage visualisation and badges | Coverage is produced locally by `make test-coverage`; no `coverage:` regex or report artifact is wired up. |
| Code quality reports | No Code Climate artifact, so merge requests show no code-quality widget. |
| JUnit test reports | Test results appear in job logs only. |
| Benchmark jobs | Performance work is done locally; see the testing docs. |
| License scanning | Approved-licence *variables* are set, but no licence-scanning job is enabled, so nothing evaluates them yet. |
| Container image publishing | The image build is a **commented-out** Kaniko component. Its path is instance-specific, and leaving it uncommented with a placeholder makes the whole file fail to parse — which would stop the security jobs from running. A `docker` stage is declared but currently has no jobs. Uncomment and set the component path for your instance to enable it. |

Security scanning *is* enabled: `.gitlab-ci.yml` includes GitLab's SAST, Secret Detection and
Dependency Scanning templates alongside the repository's own scanning jobs. Which jobs those templates
expand to depends on your GitLab tier and instance configuration, which is another reason not to
enumerate them here.

## Related

- [GitLab Integration](../GITLAB_INTEGRATION.md) — using ferret-scan as a scanner in any pipeline
- [GitLab Security Scanner Setup](GITLAB_SECURITY_SCANNER_SETUP.md) — SAST report wiring
- [Go Version Management](../GO_VERSION_MANAGEMENT.md) — how the toolchain pins stay in sync
- [Test Plan](../testing/TEST_PLAN.md) — what the suites cover
