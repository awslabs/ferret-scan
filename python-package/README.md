# ferret-scan

<div align="center">
  <img src="https://raw.githubusercontent.com/awslabs/ferret-scan/main/docs/images/ferret-scan-logo.png" alt="ferret-scan" width="200"/>
</div>

The PyPI distribution of [ferret-scan](https://github.com/awslabs/ferret-scan): find and redact
sensitive data (PII, secrets, IP markers) in files and streams, with context-aware confidence
scoring and format-preserving redaction. `pip install` gives you the `ferret-scan` command and a
pre-commit hook. The package is a thin wrapper: on first run it downloads the native binary for
your platform from the GitHub release that matches the installed package version and caches it
inside the package directory; every argument is passed straight through.

**The GitHub repository is the reference for everything:**
[README](https://github.com/awslabs/ferret-scan#readme) ·
[Documentation](https://github.com/awslabs/ferret-scan/blob/main/docs/README.md) ·
[Changelog](https://github.com/awslabs/ferret-scan/blob/main/CHANGELOG.md) ·
[Issues](https://github.com/awslabs/ferret-scan/issues)

## Install

```bash
pip install ferret-scan
ferret-scan --version
```

Python 3.7+. Linux, macOS and Windows on x86_64 and ARM64. The first run needs network access to
github.com for the binary download; after that it runs offline.

## Use

```bash
ferret-scan --file secrets.env                                        # values are hidden by default
ferret-scan --file ./src --recursive --checks SECRETS,CREDIT_CARD
ferret-scan --file . --recursive --format sarif --output ferret.sarif --quiet
echo "card 5500-0000-0000-0004 from jordan@example.com" | ferret-scan --stdin --enable-redaction
```

Output formats: `text`, `json`, `csv`, `yaml`, `junit`, `gitlab-sast`, `sarif`. All options:
`ferret-scan --help`, or the documentation index above.

## Pre-commit hook

```yaml
repos:
  - repo: https://github.com/awslabs/ferret-scan
    rev: v2.6.2
    hooks:
      - id: ferret-scan
```

`ferret-scan` is the only hook id the repository defines. pre-commit installs this package into its
own environment, so you do not need to `pip install` it for the hook. The hook runs
`--pre-commit-mode --profile precommit --respect-gitignore` on the staged files whose extensions it
knows and blocks the commit on findings. `args:` replaces that list, so repeat it when you add to it:

```yaml
      - id: ferret-scan
        args: [--pre-commit-mode, --profile, precommit, --respect-gitignore, --confidence, high]
```

More: <https://github.com/awslabs/ferret-scan/blob/main/docs/PRE_COMMIT_INTEGRATION.md>

## Exit codes

`0` the scan ran (findings do not change it; read them from the output) · `1` the run failed ·
`3` with `--fail-on-incomplete`, the run did not fully do what was asked. `--pre-commit-mode` maps
findings onto the exit code instead. Full table: <https://github.com/awslabs/ferret-scan#exit-codes>

## License

Apache-2.0. See [LICENSE](https://github.com/awslabs/ferret-scan/blob/main/LICENSE.txt).
