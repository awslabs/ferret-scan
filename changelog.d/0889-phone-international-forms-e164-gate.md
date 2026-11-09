### 🐛 Bug Fixes

- **phone (international display forms, `tel:` and vCard values, truncated spans, the `00` form):**
  an international number is reported whole in the forms it is displayed in and the contexts it is
  written in, and the `+`/`00` forms are checked against the ITU-T E.164 code list. Of the issue's
  58 shapes main reported nothing for 40 (`+33 1 99 00 47 18`, `+44 (0)20 7946 0372`,
  `(+44) 20 7946 0948`, `+7 (495) 101-10-24`, `+49 30/23125417`, `Tel:+44 ...`, `phone=+44...`,
  `<a href="tel:+44...">`, `TEL;TYPE=work,voice:+44 ...`, `Tel:(297) 201-0011`, `(020) 7946 0372`)
  and the wrong span for 14 (`297 201 0052` for `+1 297 201 0052`, `888-201-0055` for
  `1-888-201-0055`, `297-201-0056` for `297-201-0056 ext 27`, `0033 1 99 00` for
  `0033 1 99 00 47 18`); each of the 58 is now one finding covering the whole number, bare, after
  `Phone: ` and in a sentence. On the issue's redaction set (ten labelled lines, a vCard 3.0/4.0
  file, an HTML page) `simple` left 50 of 78 digit groups and 10 whole values in cleartext, now
  none; `format_preserving` left 91 of 150 digits beyond each value's last four, now none. A
  generated table of the 215 assigned calling codes and their national lengths (`e164_codes.go`,
  from libphonenumber v9.0.43) gates the forms: a number whose code is not assigned or that has
  more than 15 digits, and one whose national length the plan does not allow when nothing on its
  line names a phone, is reported at LOW 15 instead of up to 100, never dropped, so it is still
  redacted. That bounds the `00` form: of 440 `00`-led order numbers of 5 to 26 digits, 340 were
  reported and the 120 carrying more than the 15 digits E.164 allows scored 70; all 120 now score
  15, as do `row,00421337,active`, `000104.66`, `+553 274 123 784` and `+16 338 705 681`. On a
  1,140-line decoy set (monotonic clock readings, coordinates, signed amounts, diff rows, hex
  dumps) MEDIUM/HIGH lines fall from 257 to 94. The country of a number read this way comes from
  the code table (`IT` for `+39 310 ...`, not `US/CA`). Over this repository, the Go standard
  library and the Go module cache (30,573 files): 0 findings lost, 20 new (all phone numbers, in
  documentation, comments and `tel:` fixtures), 149 widened to the whole number, 1,132 lowered to
  LOW 15 or below, each a `00`/`+` value that fails the gate with no phone word on its line
  (zero-padded and hex machine numbers, Unicode code points, ISO 6709 coordinates, test values).
  The golden corpus's `call +1 449-87-4100` keeps its 100: nine digits after `+1` is a length NANP
  does not have, and a phone word on the line outweighs the length table for a value already
  reported ([#889](https://github.com/awslabs/ferret-scan/issues/889)).
