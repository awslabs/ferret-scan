### 🐛 Bug Fixes

- **personname (places and fragments):** a place whose last word is a surname, the tail of a place
  name read by the comma pattern, and a pair of short all-caps syllables the name data does not know
  are no longer reported as `PERSON_NAME`. Measured on main @ 2fb4719 with `--config /dev/null`, this
  repository's own files reported `Hong Kong` at 100, `Middle East` and `Flushing Meadows` at 91,
  `La Paz` at 91, `NEM MIN` and `EI LUO` at 92, and the second word of one city plus the next city as
  `Surname, Given` at 99, each at HIGH. A whole-phrase list (keyed on the entire value, like the
  font-family list, so no word of it is silenced in a real name) takes the measured places; the comma
  pattern no longer starts inside a place after a toponym prefix the name data does not know; and an
  all-caps candidate made only of syllables of three letters or fewer needs every syllable to be in
  the name data. The new golden decoy case reads 10 findings (4 HIGH) on main and none on the branch;
  the names that share a word or a shape with these values keep their confidence. A street name read
  as a person is not part of this change ([#935](https://github.com/awslabs/ferret-scan/issues/935)).
