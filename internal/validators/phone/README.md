# Phone Validator

Detects phone numbers in scanned content across US/Canada, UK, European, and
international formats, with various separators (spaces, dashes, dots, parentheses).

## What it detects

- US/Canada domestic and international (`(555) 123-4567`, `+1 555 123 4567`)
- US/Canada toll-free (800, 833, 844, 855, 866, 877, 888)
- UK domestic and international (`0207 123 4567`, `+44 207 123 4567`)
- European and global mobile formats (`+33 1 42 34 56 78`, `+49 30 12345678`)
- Extensions (`ext`, `extension`, `x` + 1-6 digits)

## Validation pipeline

1. **Regex match** - Recognized domestic / international phone patterns
2. **Structural gate** - A match glued to an identifier (`i-`, `ami-`, a trailing letter or
   colon, an ARN) is not reported
3. **Value checks** - Length, test numbers, sequential / repeating digits, timestamps,
   country format: each lowers the base score (none removes a finding)
4. **Context** - Phone evidence on the match's line raises the score, negative words lower it

Which matches are reported is decided by the arithmetic the validator used before #882, so
redaction rewrites the same values it always did; the evidence below moves only the score.

## How a match is scored

Base 100, then:

| Signal | Effect |
|--------|--------|
| Each phone word on the line (`phone`, `tel`, `mobile`, `cell`, `fax`, `call`, `sms`, `msisdn`, ...) | +15 |
| Each phone phrase (`phone number`, `contact no`, `direct line`, `emergency contact`, ...; also `phoneNumber`, `mobile_no`) | +15 |
| A phone label on the value (`Office: ...`, `"work": "..."`) | +15 |
| A CSV/TSV column header that names a phone | +15 |
| The match is a formatted toll-free number (`1-800-...`, `(888) ...`) | +15 |
| No evidence at all | -20 |
| Each negative word on the line (`test`, `example`, `serial`, `sku`, `card`, ...) | -35 |
| The country check passes / fails | +5 / -10 |
| A ten-digit number the North American plan cannot assign (area or exchange code 0XX/1XX, area N11) | 0, and not labelled US/CA |
| `+` form with 10 or more digits | +10 |
| Timestamp-shaped bare run | -60 |
| SSN shape / card fragment / invalid (`0000...`, mostly zeros, under 7 digits) | -50 / -60 / -70 |
| Known test number / fewer than 7 or more than 15 digits (a leading `+` counts as one) / non-phone characters | -20 / -15 / -10 |
| Sequential / repeating digits | -15 / -15 |

Words count only as whole words, in any case, outside the match: `string` is not `ring`, `hotel`
is not `tel`, and the `800` inside a digit run is not a toll-free code. The context adjustment
stays within -80 and +40. A match whose structural gate fails takes -100, unless it is a whole
quoted string that something names a phone (`{"phone": "2972010001"}`).

A phone label does not make every ten-digit value a finding. Whether a match is reported is still
decided as before #882 (see the pipeline above), and there a match that fails the structural gate,
as a quoted run does, is reported on its base score alone, before any keyword counts (above 100,
or above 85 on a delimiter-rich line). `{"phone": "2972010001"}` passes, but a bare run in the
Unix-timestamp range (1000000000 to 2147483647) takes -60 from its base first, so
`{"phone": "2022872112"}` is not reported. Unquoted, `Phone: 2022872112` reports at 60, and
`Phone: 202-287-2112`, which is not a bare run, at 100.

Ceilings apply after everything else and are published as `confidence_ceiling`, so the
document-level +20 a CSV receives cannot lift them:

- 85 for a match nothing corroborates (no evidence above and not written in the `+` form);
- 15 for a reserved fictional number (555-0100 to 555-0199);
- 15 for a number in the `+`, `00` or `(+` form that the E.164 gate refuses, with
  `valid_country=false`: its country code is unassigned, it has more than 15 digits, it writes a
  `(0)` its code's plan does not use, or its national length is not one the plan allows. Phone
  evidence on the line outweighs the last of these alone, never the others. The gate adds no
  finding: a number it refuses is reported, at 15, only when one of the validator's patterns
  reports it anyway;
- 15 for a number after `:` or `=` that follows a word that is not a phone label, with
  `validation_checks.phone_label_recognized=false`.

## Usage

```bash
ferret-scan --file contacts.csv --checks PHONE
ferret-scan --file customer-records.txt --checks PHONE --confidence high
ferret-scan --file support-logs.json --checks PHONE --verbose
```
