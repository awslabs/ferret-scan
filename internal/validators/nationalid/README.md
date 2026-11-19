# nationalid

The `NATIONAL_ID` check (#884 Part B): national identification numbers no other check covers.

| Type | Number | Printed forms | Check |
|---|---|---|---|
| `BR_CPF` | Brazil, Cadastro de Pessoas Físicas | `XXX.XXX.XXX-XX`, `XXXXXXXXX-XX`, 11 digits | two mod-11 digits; repdigits rejected |
| `CL_RUT` | Chile, Rol Único Tributario / Nacional | `XX.XXX.XXX-D`, `XXXXXXXX-D`, `XXXXXXXXD`, 8 or 9 symbols bare | mod-11 verifier, 0-9 or K |
| `AR_CUIL` | Argentina, CUIL and personal CUIT | `20/23/24/27-XXXXXXXX-X`, 11 digits | mod-11; remainder 10 never issued |
| `CA_SIN` | Canada, Social Insurance Number | `XXX-XXX-XXX`, `XXX XXX XXX`, 9 digits | Luhn; leading 0 and 8 rejected |
| `MX_CURP` | Mexico, Clave Única de Registro de Población | 18 characters | date, sex, state, consonants, check digit |
| `MX_RFC` | Mexico, Registro Federal de Contribuyentes (a company's 12 characters, a person's 13) | 12 or 13 characters, ASCII | date that exists; the SAT's verifier over a 37-symbol table (`rfcCheck`) |

Every row is tier B: a value is reported only when its own label (`CPF`, `RUT`, `RUN`, `CUIL`,
`CUIT`, `SIN`, `NAS`, `CURP`, `RFC`, or the long form, accents optional) sits before it on the same
line. Between the label and the value may stand separators and up to two filler words: `nº`, `n°`,
`no.`, `nro`, `núm.`, `número`, `number`, `is`, `es`, `é` (#1021: `Our Social Insurance Number is
123 456 782`). An acronym that is also a word (`sin`, `run`, `NAS`, `RFC`) counts only in capitals or
before a colon or ordinal sign; `NAS` only before one.

| The value | Confidence | Metadata |
|---|---|---|
| label, shape and check digit pass | 95 for a long form or a label with `:`/`nº`, 90 for a bare capitalised acronym | `check_digit_valid=true` |
| label and shape pass, the check digit fails | 40 (LOW) | `checksum_valid=false`, `confidence_ceiling=40` |
| the SAT's generic RFC (`XAXX010101000`, `XEXX010101000`) under an RFC label | 15 (LOW) | `checksum_valid`, `confidence_ceiling=15` |

The shape is the structural rule that no check digit is part of: the length and alphabet, an existing
date (CURP, RFC), an issued prefix (CUIL, SIN), a leading digit that is not 0 (RUT, SIN). A value
that fails it is not reported. The synthetic redaction replacement is written to fail the shape (a CURP
or RFC month of 00, a leading 0 in a RUT or SIN), or, for a CPF, to start with 000, which a LOW report
skips (`isSyntheticShape`), so a redacted copy never re-detects.

Not covered (see #884): entity numbers (CNPJ, CUIT 30/33/34, EIN), numbers with no check digit (DNI,
cédula, RG), a label that heads a column or stands on the line above, an RFC whose letters include Ñ,
and a value with no label. The no-label shapes were measured on 225 MB of Portuguese and Spanish
Wikipedia text and are not promoted: see the pull request that added this paragraph.
