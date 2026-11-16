### 🐛 Bug Fixes

- **personname (comma lists):** in a comma-separated list, the last word of one item and the next
  item are no longer reported together as a `Surname, Given` name. Measured on main @ 3aa380e with
  `--config /dev/null --confidence all --checks PERSON_NAME` over `internal/validators/personname/`,
  11 comma-form spans taken across a list comma (8 at HIGH, 93-100) are gone. The span was what
  redaction rewrote, so it masked the tail of one name and all of the next and left the rest of the
  first in clear; each name in a list is now reported, and redacted, on its own. `Surname, Given`
  written alone keeps its score, and so does a two-item list of single words, which reads the same.
  The inverted first author of a reference list (`Griffith, Rachel, Stephen Redding and Helen
  Simpson.`) keeps its score too: a list whose next item is a person written `Given Surname` is a
  list of people, not of places. Measured on the 639-file public corpus against main: 37 list spans
  gone, every one a place, office or role read as a name; 3 real names newly reported on their own;
  2 real-name occurrences no longer covered, both the given name after a Spanish double surname
  (`Martín Jiménez, Jesús`: `Martín Jiménez` is still reported). A list in which every author is
  inverted cannot be told from a list of single words by shape, and only its last item is reported
  ([#936](https://github.com/awslabs/ferret-scan/issues/936)).
