# VIN Validator

Detects Vehicle Identification Numbers (VINs) in scanned content.

## What it detects

- 17-character alphanumeric VINs (ISO 3779 / SAE J853)
- Excludes characters I, O, Q per VIN standard
- Verifies the check digit at position 9 using the weighted transliteration algorithm. The check
  digit is compulsory only in North America and China, so elsewhere a failed check digit does not
  reject a VIN on its own (see the pipeline below)

## Validation pipeline

1. **Regex match** - 17 alphanumeric characters (A-H, J-N, P-R, S-Z, 0-9)
2. **Early rejection** - All-repeating characters, known test patterns
3. **Check digit validation** - Mod-11 weighted checksum (position 9). What a failure means depends
   on the region, the VIN's first character:
   - **Compulsory** (`1`-`5` and `7`: North America; `H` and `L`: China): a failed check digit
     rejects the VIN. The New Zealand WMIs in `7A`-`7E` are held to this rule too (a known limit).
   - **Optional** (every other region): a VIN without a valid check digit is kept when its WMI is a
     known manufacturer prefix, or when the document labels it as a VIN. The label must be one of
     a fixed, code-defined list (`VIN`, `VINs`, `VIN number`, `vehicle identification number`,
     `chassis number`/`no`, `frame number`, `Fahrgestellnummer`, `numéro de châssis`,
     `numero di telaio`, `número de bastidor`, and their `_`/`-`/camelCase spellings) placed
     - right beside the value with only separators between (`VIN: x`, `vin=x`, `"vin": "x"`,
       `(VIN x)`, `Chassis no. x`, `x (VIN)`),
     - as the header of the value's column in a delimited table of three or more columns, or
     - alone on the line above a value that begins its line.

     The bare word `vin` counts only written as `VIN` or as a key (`vin:`, `vin=`, `"vin"`), since
     it is also French for wine. A labelled value must still look like a VIN: it does not start
     with `0`, holds a digit, is not all hex digits and is not mixed case.

   A passing check digit is not enough for a digit run: 15 or more digits, no letter in positions
   2-8 and no known WMI (a chat permalink segment such as `p1762292269161789`, a 17-digit timestamp
   or numeric ID). About 1 in 11 of those pass the check digit by coincidence, so a pass does not
   admit them.
4. **Encoded data filter** - Rejects matches embedded in hex dumps or longer tokens
5. **Confidence scoring** - Base confidence + WMI lookup + model year + context keywords

Known limits of the label rule: a VIN without a valid check digit is not reported when nothing
labels it, when the label follows it in prose (`x is the vehicle identification number`), for the
second and later values of a list (`VINs: x, y`), when the label is markup (`<VIN>x</VIN>`), or in
a two-column CSV, which is too narrow to be told apart from prose.

## Confidence factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Format | 65% base | Valid 17-char VIN format |
| Check digit | +20% / -10% | Position 9 check digit passes / fails (optional region only) |
| Known WMI | +10% | Recognized manufacturer prefix |
| Model year | +5% | Valid year code at position 10 |
| VIN label | +25% | Only for a VIN that a label admitted without a check digit or known WMI |
| Context | +/-50% max | Keyword analysis of surrounding text, VIN label included |

## Usage

```bash
ferret-scan --file vehicle-records.txt --checks VIN
ferret-scan --file fleet-data.csv --checks VIN --confidence high
```
