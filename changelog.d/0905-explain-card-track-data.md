### 🐛 Bug Fixes

- **explain (`--explain`):** a `CARD_TRACK_DATA` finding's rationale and drafted suppression reason
  now read "Flagged as card track data" and "Placeholder/example: card track data …" instead of
  "a card track data" ([#905](https://github.com/awslabs/ferret-scan/issues/905)).
  `CARD_SECURITY_CODE` keeps "a card security code". Findings, scores and exit codes are unchanged.
