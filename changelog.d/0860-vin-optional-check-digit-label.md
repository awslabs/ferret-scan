### 🐛 Bug Fixes

- **vin (optional check digit):** a VIN from a region where the ISO 3779 position-9 check digit is
  optional is reported when the document labels it as a VIN, even when its check digit fails and
  its manufacturer prefix (WMI) is not one of the 26 non-North-American prefixes the validator
  knows ([#860](https://github.com/awslabs/ferret-scan/issues/860)). The check-digit gate dropped
  such a VIN before context was scored, so `VIN: WVGZZZ5NZRA000502` (VW SUV) or
  `VIN: VF1RJA00ZRA000506` (Renault) reported nothing at exit 0, also under `--pre-commit-mode`,
  and `--enable-redaction` left them in cleartext. A failed check digit is now a hard reject only
  where it is compulsory: North America (`1`–`5` and `7`, which the old test missed) and China (`H`,
  `L`, also missed). Elsewhere the VIN is kept when a VIN label from a fixed list sits beside it
  with only separators between (`VIN: x`, `vin=x`, `"vin": "x"`, `(VIN x)`, `Chassis no. x`,
  `Fahrgestellnummer: x`), heads its CSV column, or stands alone on the line above it, and the
  value looks like a VIN (no leading `0`, a digit, not all hex, not mixed case); the bare word `vin`
  counts only as `VIN` or as a key, since it is French for wine. Measured main vs this branch with
  one synthetic VIN per WMI in the public list (Wikipedia revision 1378888660), position 9 `Z` or a
  wrong digit, `VIN: <v>`: exempt regions 26 → 871 of 878 (the seven New Zealand `7A` WMIs stay
  unreported, a documented limit); China and `7F`–`7Z` 0 of 146 before and after; unlabelled 26 of
  878 before and after. A 12-row EU fleet CSV: 4 → 12 of 12 VINs reported, and 8 → 0 left in
  cleartext by `--enable-redaction`. **New findings only:** all 2,152 findings main emits on the
  sweep keep their type, text, line and confidence, so no suppression rule moves; four 3,300-line
  decoy corpora (unlabelled tokens, `make … model <token>`, a second token after a VIN,
  `Commande de vin <token>`) report exactly what main reports, and on `VIN: <token>` lines the
  rise (80 → 290) is all random uppercase tokens the label calls a VIN. `--pre-commit-mode` now
  exits 1 on a file holding such a VIN (was 0).
