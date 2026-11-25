### 🐛 Bug Fixes

- **gitlab-sast, vulnerability id:** the `id` of each vulnerability is now a hash of the path the report
  prints in `location.file` (relative to the scan root, `../` stripped), the line and the check type. It
  hashed the absolute scanned path, so one finding got a different id in every checkout directory
  (`ferret-f557c13aa6628998` and `ferret-f708e9a7630d037d` for one file in two directories), and a different
  one again from the web UI's export of the same content. The CLI id is now stable across checkout
  locations and equals the web's for the same upload name. ⚠ Every gitlab-sast id changes once, at this
  release: GitLab triage state keyed on an old id (dismissals, linked issues) detaches from its finding,
  which shows as new until it is triaged again. Findings, lines and types are unchanged
  ([#1017](https://github.com/awslabs/ferret-scan/issues/1017)).
