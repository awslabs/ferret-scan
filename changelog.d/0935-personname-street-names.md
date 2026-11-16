### 🐛 Bug Fixes

- **personname (street names):** the words of a numbered street (a house number, one to four
  Title-Case words and a street type such as Lane or Blvd) and a street type followed by a town that
  the comma pattern read as `Surname, Given` are no longer reported as `PERSON_NAME`. Measured on
  main @ 3aa380e with `--config /dev/null --confidence all`, four street lines quoted from this
  repository's own comments reported 6 `PERSON_NAME` findings at 67-93 (4 HIGH); the branch
  reports none, and `US_STREET_ADDRESS` still reports both streets, so the bytes stay redacted when
  both checks run. A person whose surname is a street type keeps their confidence when no house
  number is in front of the name or the given name is one the name data knows
  ([#935](https://github.com/awslabs/ferret-scan/issues/935)).
