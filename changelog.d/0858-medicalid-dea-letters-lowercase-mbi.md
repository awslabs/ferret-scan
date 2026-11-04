### 🐛 Bug Fixes

- **medicalid (DEA registrant letters, lowercase MBIs):** a checksum-valid DEA number with any of
  the 18 registrant letters, or the `9` business-address form, and a lowercase or mixed-case
  Medicare MBI are now reported and redacted
  ([#858](https://github.com/awslabs/ferret-scan/issues/858)). The DEA pattern and checksum accepted
  only `A/B/C/D/F/G/M` plus a letter, so `DEA registration number: XR1234563` (11 of the 18 letters,
  `X` included) and `B97654329` reported nothing; the MBI pattern was uppercase-only although CMS
  converts a lowercase MBI to uppercase, so `Medicare MBI: 1ac2de3fg45` reported nothing. Both
  stayed in cleartext under `--enable-redaction` at exit 0. The new forms are gated: a newer letter
  or a `9` needs DEA context (on the line, a label line above, or the column header), and a
  lowercase MBI a Medicare-specific label (`medicare`, `mbi`, `hicn` or a compound key); measured
  ungated, 79 of 800 patent numbers and 16 of 3,000 passport numbers became DEA findings. The
  provider, DEA and Medicare context now also reads camelCase keys and the column header, so
  `{"deaNumber": ...}` scores 85 (was 55), `{"providerNpi": ...}` 80 (was 40), and a DEA number in
  a `dea_number` CSV column 100 on every row (was 75 after the first). The member-ID veto now asks
  the specific subtype's decision, so `Member ID: XR1234563` stays an INSURANCE_MEMBER_ID. One
  narrow retype: a lowercase MBI or newer-letter DEA number on a line that carries both a member-ID
  label and Medicare or DEA context moves from INSURANCE_MEMBER_ID to the specific type, as its
  uppercase or legacy sibling already did; `Type` is part of the suppression hash, so a rule
  written for the old finding stops matching. Measured with `--checks MEDICAL_ID` on 25,495 real
  files (Go toolchain sources and module cache): 1 finding added (a ferret v2.5.3 test fixture
  asserting the bug), 0 lost, 0 retyped, 0 rescored; no existing golden snapshot moved.
