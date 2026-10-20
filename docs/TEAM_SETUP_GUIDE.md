# Ferret Scan Team Setup Guide

This guide walks you through setting up Ferret Scan for your entire team, covering local development, pre-commit hooks, and CI/CD integration.

## Quick Team Setup (5 minutes)

### 1. **Repository Setup**

```bash
# Clone or navigate to your repository
cd your-repository

# Set up team configuration
./scripts/setup-team-config.sh
# Choose: 1=Startup, 2=Enterprise, 3=Financial, 4=Custom

# Set up pre-commit hooks
./scripts/setup-pre-commit.sh
# Choose: 1=Strict, 2=Balanced, 3=Advisory, 4=Secrets, 5=Custom

# Set up GitHub Actions
mkdir -p .github/workflows
cp .github/workflows/ferret-scan.yml .github/workflows/

# Commit team configuration
git add .ferret-scan.yaml .pre-commit-config.yaml .github/workflows/ferret-scan.yml
git commit -m "Add Ferret Scan team security configuration"
git push
```

### 2. **Team Member Setup**

Each team member runs:
```bash
# Install pre-commit (if not already installed)
pip install pre-commit
# or: brew install pre-commit

# Install the hooks
pre-commit install

# Test the setup
echo "Test credit card: 4111-1111-1111-1111" > test.txt
git add test.txt
git commit -m "Test commit"  # Should be blocked
rm test.txt
```

## Detailed Configuration

### Configuration Files Overview

| File | Purpose | Location | Commit? |
|------|---------|----------|---------|
| `.ferret-scan.yaml` | Team security policies | Repository root | ✅ Yes |
| `.ferret-scan-suppressions.yaml` | Team suppressions | Repository root | ❌ No (in .gitignore) |
| `.pre-commit-config.yaml` | Pre-commit hook config | Repository root | ✅ Yes |
| `.github/workflows/ferret-scan.yml` | CI/CD integration | `.github/workflows/` | ✅ Yes |

### Team Configuration Types

#### Startup/Development Team
```yaml
# .ferret-scan.yaml - Balanced security with productivity
defaults:
  confidence_levels: high,medium
  checks: CREDIT_CARD,SECRETS,SSN,EMAIL,PHONE
  verbose: false

profiles:
  precommit:
    confidence_levels: high
    checks: CREDIT_CARD,SECRETS,SSN
    quiet: true
```

#### Enterprise/Security-Focused
```yaml
# .ferret-scan.yaml - High security standards
defaults:
  confidence_levels: high,medium,low
  checks: all
  verbose: true

profiles:
  precommit:
    confidence_levels: high,medium
    checks: all
    verbose: true
```

#### Financial Services
```yaml
# .ferret-scan.yaml - Compliance-focused
defaults:
  checks: CREDIT_CARD,SSN,EMAIL,PHONE,SECRETS,PASSPORT
  verbose: true

profiles:
  pci-compliance:
    checks: CREDIT_CARD,SECRETS
    show_match: false  # Don't log actual card numbers
```

## Pre-commit Hook Strategies

Which findings are looked for, and at which confidence, are **command-line flags**. The
only environment variable that changes what the hook does to your commit is
`FERRET_PRECOMMIT_EXIT_ON`, and it takes exactly `high`, `medium`, `low` or `none`:
a misspelled or differently cased value fails the hook with a message naming the
variable instead of quietly leaving the gate at `high`.

### Strategy 1: Strict Security (Recommended for Production)
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        entry: ./bin/ferret-scan --pre-commit-mode --confidence high,medium --checks all
        language: system
        files: '\.(py|js|ts|go|java|json|yaml|yml|env)$'
        env:
          FERRET_PRECOMMIT_EXIT_ON: "high"  # Block only on high confidence
```

### Strategy 2: Balanced Approach (Good for Most Teams)

Same as Strategy 1, applied to a wider set of files. `high` is the default value of
`FERRET_PRECOMMIT_EXIT_ON`, so the `env:` block can be omitted entirely:

```yaml
      - id: ferret-scan
        entry: ./bin/ferret-scan --pre-commit-mode --confidence high,medium --checks all
        language: system
```

### Strategy 3: Advisory Mode (Learning/Adoption Phase)
```yaml
      - id: ferret-scan
        entry: ./bin/ferret-scan --pre-commit-mode --confidence high --checks all
        language: system
        env:
          FERRET_PRECOMMIT_EXIT_ON: "none"  # Report, never block
```

`none` is the only value that genuinely stops the hook failing. Accepted values are
`high`, `medium`, `low` and `none`; anything else is ignored and the default `high`
stands.

> **The report still ends with "High confidence issues found - commit blocked for
> security." even under `none`.** That line is unconditional; the exit code is what
> pre-commit acts on, and with `FERRET_PRECOMMIT_EXIT_ON=none` it is 0, so the commit
> proceeds. Measured on a file with one HIGH finding: `none` exits 0, `high` exits 1.

## GitHub Actions Integration

### Workflow Configuration

The GitHub Actions workflow:
- Scans only changed files in PRs (performance optimization), and the whole repository on a push to `main`/`master`
- Counts HIGH and MEDIUM findings from each report's `stats` block, which `--limit` does not cap
- Posts the counts as a PR comment and job summary that name the gate mode. "No sensitive data detected" appears only when ferret-scan exited 0, every file was fully examined, at least one file was scanned and both counts are 0
- Uploads the JSON reports and ferret-scan's stderr as the `ferret-scan-results` build artifact (findings are not published to the GitHub Security tab)
- Ends with a gate step whose handling of HIGH findings is set by `GATE_MODE` (below)
- Uses your team's `.ferret-scan.yaml` configuration

### Gate mode (`GATE_MODE`)

The last step, **Gate on scan result and high confidence findings**, runs whenever a scan ran and
fails closed in both modes: it fails the check when a count is missing or not an integer, when
ferret-scan exited non-zero (the scans pass `--fail-on-incomplete`, so a file it could not fully
examine exits 3), or when `GATE_MODE` is anything but `block` or `report`. Only HIGH findings depend
on the mode:

| `GATE_MODE` | HIGH findings > 0 |
|---|---|
| `block` (template default) | fail the check |
| `report` | are counted and shown in the log, PR comment and job summary; the check passes |

The workflow sets it at the top:

```yaml
env:
  GATE_MODE: ${{ github.repository == 'awslabs/ferret-scan' && 'report' || 'block' }}
```

so a copy in any other repository runs `block`. Replace the expression with `report` to adopt the
workflow without failing on findings your repository already carries, then switch to `block`.

ferret-scan's own repository runs `report`, for its PR scan and its post-merge push scan. Its source
and test corpora carry deliberate HIGH findings, so `block` would fail most of its runs (40 of the 56
PR runs that scanned files from 2026-09-14 to 2026-10-13, 27 of 56 even with
`internal/goldencorpus/`, `internal/scorecorpus/` and `testdata/` excluded), and its committed
suppression baseline has expired ([#696](https://github.com/awslabs/ferret-scan/issues/696)). The
push scan runs after the merge, so in `block` mode it turns the merged commit's check red rather than
stopping anything.

> **Copies of this workflow made before [#767](https://github.com/awslabs/ferret-scan/issues/767)
> never blocked anything.** They compared each finding's `confidence` with the string `"HIGH"`, but
> `confidence` is the numeric score (the band is `confidence_level`), so every run counted 0, skipped
> the gate and commented "No sensitive data detected". An existing copy stays that way until you
> re-copy the workflow, and a re-copied `block` workflow can turn your CI red on HIGH findings your
> repository already carries: run it in `report` mode first if you are not sure.

### Repository Permissions Setup

1. **Go to Settings → Actions → General**
2. **Set Workflow permissions:**
   - ✅ "Read and write permissions"
   - ✅ "Allow GitHub Actions to create and approve pull requests"

### Branch Protection Rules

Add Ferret Scan as a required check:

1. **Go to Settings → Branches**
2. **Add rule for main/master branch:**
   - ✅ "Require status checks to pass"
   - ✅ Select "Sensitive Data Detection" (the job of the "Ferret Scan Security Check" workflow)

In `block` mode a HIGH finding then blocks the merge; in `report` mode only a failed or incomplete
scan does.

## Suppression Management

### Team Suppressions Strategy

```bash
# Generate initial suppressions for existing code
ferret-scan --file . --recursive --generate-suppressions

# Review and enable appropriate suppressions
vim .ferret-scan-suppressions.yaml

# Keep suppressions local (don't commit)
echo ".ferret-scan-suppressions.yaml" >> .gitignore
```

### Suppression File Structure
```yaml
# .ferret-scan-suppressions.yaml
version: "1.0"
suppressions:
  - id: "test-data-suppression"
    pattern: "4111-1111-1111-1111"
    reason: "Test credit card number in documentation"
    enabled: true
    created_at: "2024-01-15T10:30:00Z"

  - id: "example-email-suppression"
    pattern: "user@example.com"
    reason: "Example email in code comments"
    enabled: true
```

## Team Adoption Strategy

### Phase 1: Introduction (Week 1)
- Set up configuration files
- Deploy in advisory mode (`FERRET_PRECOMMIT_EXIT_ON: "none"`)
- Let team see what sensitive data looks like
- Generate suppressions for existing false positives

### Phase 2: Gradual Enforcement (Week 2-3)
- Switch to balanced mode (`FERRET_PRECOMMIT_EXIT_ON: "high"`)
- Block only high-confidence findings
- Train team on bypass procedures (`git commit --no-verify`)
- Refine suppressions based on feedback

### Phase 3: Full Enforcement (Week 4+)
- Consider stricter settings if appropriate
- Regular suppression review meetings
- Monitor GitHub Actions results
- Continuous improvement based on findings

## Troubleshooting

### Common Issues

**1. "Too many false positives"**
```bash
# Generate suppressions for existing code
ferret-scan --file . --recursive --generate-suppressions

# Or reduce sensitivity: in .pre-commit-config.yaml, narrow the entry's
# --confidence flag (there is no FERRET_CONFIDENCE variable)
#   entry: ./bin/ferret-scan --pre-commit-mode --confidence high
```

**2. "Scans are too slow"**
```bash
# Reduce file scope
files: '\.(py|js|go)$'  # Only critical files

# Or exclude large directories
exclude: '(node_modules/|vendor/|\.git/)'
```

**3. "GitHub Actions failing"**
- Check repository permissions (Settings → Actions → General)
- Verify workflow file is in `.github/workflows/`
- Check if `.ferret-scan.yaml` has syntax errors

**4. "Pre-commit hooks not running"**
```bash
# Reinstall hooks
pre-commit uninstall
pre-commit install

# Test manually
pre-commit run ferret-scan --all-files
```

### Debug Mode

Enable debug output for troubleshooting:

```yaml
# In .pre-commit-config.yaml
env:
  FERRET_DEBUG: "1"
```

## Team Training

### Developer Education Topics

1. **What is sensitive data?**
   - Credit card numbers, SSNs, API keys
   - Email addresses in certain contexts
   - Internal URLs and system information

2. **When to bypass the hook:**
   ```bash
   # Only when absolutely necessary
   git commit --no-verify
   ```

3. **How to handle findings:**
   - Remove actual sensitive data
   - Add suppressions for false positives
   - Use placeholder data in examples

4. **Suppression best practices:**
   - Be specific with patterns
   - Include clear reasons
   - Regular review and cleanup

### Team Meeting Agenda Template

**Ferret Scan Review Meeting (Monthly)**
1. Review recent findings and trends
2. Discuss new suppressions needed
3. Update team configuration if needed
4. Share lessons learned
5. Plan improvements

## Metrics and Monitoring

### Key Metrics to Track

- Number of findings per week/month
- False positive rate
- Time to resolution for findings
- Team adoption rate (% of commits scanned)

### GitHub Actions Insights

Monitor in GitHub:
- Actions → Ferret Scan Security Check
- View trends in findings over time
- Check for recurring issues

### Continuous Improvement

- Monthly review of suppressions
- Quarterly review of configuration
- Annual security policy updates
- Regular tool updates

## Advanced Configuration

### Custom Validator Configuration

```yaml
# .ferret-scan.yaml
validators:
  intellectual_property:
    # Disable specific IP sub-types (e.g., copyright notices on all source files)
    # Valid values: copyright, patent, trademark, trade_secret, internal_url
    # disabled_types:
    #   - copyright

    internal_urls:
      - "http[s]?:\\/\\/.*\\.yourcompany\\.com"
      - "http[s]?:\\/\\/intranet\\.yourcompany\\.com"

  social_media:
    platform_patterns:
      linkedin:
        - "https?://linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

### Environment-Specific Profiles

```yaml
# .ferret-scan.yaml
profiles:
  development:
    confidence_levels: high
    checks: CREDIT_CARD,SECRETS

  staging:
    confidence_levels: high,medium
    checks: CREDIT_CARD,SECRETS,SSN,EMAIL

  production:
    confidence_levels: all
    checks: all
    verbose: true
```

## Support and Resources

- **Documentation:** `docs/PRE_COMMIT_INTEGRATION.md`
- **Examples:** `.pre-commit-config-examples.yaml`
- **Team Setup:** `./scripts/setup-team-config.sh`
- **Pre-commit Setup:** `./scripts/setup-pre-commit.sh`
- **GitHub Workflows:** `.github/workflows/ferret-scan*.yml`

For additional help, see the main README.md or create an issue in the repository.
