### 🐛 Bug Fixes

- **vin (digit runs):** a chat permalink segment of `p` and 16 digits
  (`…/archives/C01ABCDEF/p1762292269161789`), a 17-digit timestamp or a 17-digit numeric ID is no
  longer reported as a VIN when its check digit happens to pass
  ([#803](https://github.com/awslabs/ferret-scan/issues/803)). A passing ISO 3779 position-9 check
  digit, which about 1 in 11 of all 17-character tokens has by chance, admitted the candidate with
  no further test, so these scored 90 HIGH (75 MEDIUM beside a negative keyword such as `example`).
  A candidate with 15 or more digits, no letter in positions 2–8 and no known WMI is now rejected
  even when its check digit passes. Measured main vs branch: the issue's line 75 → none; the
  permalink under a workspace host, with a thread query, in a tab-separated row and bare, and a
  17-digit timestamp and ID, 90 → none. A VIN in a URL query or as a URL path segment, the NA and
  EU fixtures (100) and both edges of the 15-digit threshold (90) report unchanged; no golden
  snapshot and no `make score` figure moves.
