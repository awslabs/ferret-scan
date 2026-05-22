# GitHub Actions workflow conventions

## Action pinning

External `uses:` references in this directory are **pinned to a full commit
SHA** with a trailing version comment, not to a floating tag like `@v6`.

```yaml
# correct — pinned to immutable commit, version comment for dependabot
- uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

# wrong — floating tag is mutable and trusts the upstream maintainer's
# account security plus GitHub's tag-rewrite controls
- uses: actions/checkout@v6
```

### Why

These workflows run with elevated privileges (`contents: write`,
`packages: write`, `id-token: write` for PyPI trusted publishing and AWS
OIDC). A compromised third-party action with floating-tag trust can read
secrets, exfiltrate the GitHub token, push to `main`, or publish a tampered
package — without any code change in this repo.

SHA pinning shifts the trust model from "tag mutability + maintainer account
security" to "git's content-addressing + reviewable update PRs."

### How upgrades happen

[Dependabot is configured](../dependabot.yml) for the `github-actions`
ecosystem and **understands this format**. Each Monday it opens grouped PRs
for minor + patch updates and per-action PRs for majors. Each PR updates
both the SHA and the version comment together; review surface is the same as
any other dependency PR.

### Adding a new action

1. Find the action's latest release tag.
2. Resolve it to the underlying commit SHA:
   ```bash
   gh api /repos/<owner>/<action>/git/refs/tags/<tag> \
     --jq '.object.sha, .object.type'
   # If type is "tag" (annotated), dereference:
   gh api /repos/<owner>/<action>/git/tags/<tag-object-sha> \
     --jq '.object.sha'
   ```
3. Use `uses: <owner>/<action>@<commit-sha> # <version>` in the workflow.
4. Verify the action manifest resolves at that ref:
   ```bash
   gh api "/repos/<owner>/<action>/contents/action.yml?ref=<sha>"
   ```

### Verifying drift

```bash
# Should return nothing. Matches floating @vN or @vN.N.N references on
# external actions (i.e. SHA-less pins). Local workflow_call refs (./...)
# and SHA-pinned refs with version comments are correctly excluded.
# README.md is excluded because it documents the wrong-pattern example.
grep -rE 'uses: [^@]+@v[0-9]+(\.[0-9]+)*$' .github/workflows/ \
  --exclude=README.md
```
