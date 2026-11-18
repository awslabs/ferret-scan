### 🐛 Bug Fixes

- **suppressions (generated rules):** `--generate-suppressions` no longer moves a rule it wrote for one
  finding onto another finding of the same run. When a finding with no recorded context and a copy of
  it that records its line were reported together (the secrets validator's one-line PEM findings before
  #979), the copy's empty-context compatibility hash equalled the first finding's hash, generation
  "migrated" the first finding's rule to the copy, and the first finding was reported again on the next
  run: 36 of 36 such PEM findings measured on 2fb4719. A rule whose hash is a current finding's own
  identity is now never migrated
  ([#981](https://github.com/awslabs/ferret-scan/issues/981)).
