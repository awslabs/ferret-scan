### 🚀 Features

- **sarif (finding identity fingerprint):** every SARIF result, suppressed results included, now
  carries the finding's identity under `partialFingerprints`, as `ferretFindingIdentity/v1`: a SHA-256
  over the current suppression-hash formula's identity composite with the line number left out, so the
  value survives edits that only move the finding to another line. An external suppression store or
  report differ keyed on it keeps matching a moved finding instead of resurrecting it. Everything else
  that is identity participates (type, trimmed line text, file basename, context windows, matched
  value); confidence stays out, as for rule hashes. Identical repeated lines share one fingerprint
  (combine it with the result's location to tell copies apart). The value is an unsalted digest
  emitted for every finding, so a report carrying it can be tested offline against candidate values
  for low-entropy types: treat a SARIF report with the sensitivity of its findings. There is no
  opt-out. A formula change adds `ferretFindingIdentity/v2` beside the `/v1` key rather than changing
  its meaning. Designed and first implemented by @nikmeiser
  ([#983](https://github.com/awslabs/ferret-scan/issues/983)).
