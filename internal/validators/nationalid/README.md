# nationalid

The `NATIONAL_ID` check (#884 Part B): national identification numbers no other check covers.

| Type | Number | Printed forms | Check |
|---|---|---|---|
| `BR_CPF` | Brazil, Cadastro de Pessoas Físicas | `XXX.XXX.XXX-XX`, `XXXXXXXXX-XX`, 11 digits | two mod-11 digits; repdigits rejected |
| `CL_RUT` | Chile, Rol Único Tributario / Nacional | `XX.XXX.XXX-D`, `XXXXXXXX-D` | mod-11 verifier, 0-9 or K |
| `AR_CUIL` | Argentina, CUIL and personal CUIT | `20/23/24/27-XXXXXXXX-X`, 11 digits | mod-11; remainder 10 never issued |
| `CA_SIN` | Canada, Social Insurance Number | `XXX-XXX-XXX`, `XXX XXX XXX`, 9 digits | Luhn; leading 0 and 8 rejected |
| `MX_CURP` | Mexico, Clave Única de Registro de Población | 18 characters | date, sex, state, consonants, check digit |

Every row is tier B: a value is reported only when its own label (`CPF`, `RUT`, `RUN`, `CUIL`,
`CUIT`, `SIN`, `NAS`, `CURP`, or the long form, accents optional) sits right before it on the same
line, with only separators or `nº`/`n°`/`no.`/`número` between. An acronym that is also a word
(`sin`, `run`, `NAS`) counts only in capitals or before a colon or ordinal sign; `NAS` only before
one. Confidence is 95 for a long form or a label with `:`/`nº`, 90 for a bare capitalised acronym.

A labelled value whose check fails is not reported, which is what lets the synthetic redaction write
a value of the same shape that fails the check and never re-detects.

Not covered (see #884): MX RFC, entity numbers (CNPJ, CUIT 30/33/34, EIN), numbers with no check
digit (DNI, cédula, RG), and a label that heads a column or stands on the line above.
