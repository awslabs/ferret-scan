### 🐛 Bug Fixes

- **personname (comma lists):** in a comma-separated list, the last word of one item and the next
  item are no longer reported together as a `Surname, Given` name. Measured on main @ 3aa380e with
  `--config /dev/null --confidence all --checks PERSON_NAME` over `internal/validators/personname/`,
  11 comma-form spans taken across a list comma (8 at HIGH, 93-100) are gone. The span was what
  redaction rewrote, so it masked the tail of one name and all of the next and left the rest of the
  first in clear; each name in a list is now reported, and redacted, on its own. `Surname, Given`
  written alone keeps its score, and so does a two-item list of single words, which reads the same
  ([#936](https://github.com/awslabs/ferret-scan/issues/936)).
