### 📚 Documentation

- **help (`--help PHONE`), phone README:** the Reasonable Length factor no longer says only "Must be
  7-15 digits". It says that a leading `+` counts toward the 15, and names the E.164 gate a `+` or
  `00` number is also held to since the international forms were added for
  [#889](https://github.com/awslabs/ferret-scan/issues/889): an unassigned country code or more
  than 15 digits caps the number at 15, and so does a national length its code's plan does not
  allow unless phone evidence is on the line. The phone README lists the gate's ceiling and the
  ceiling for a number after a word that is not a phone label beside the two it had.
