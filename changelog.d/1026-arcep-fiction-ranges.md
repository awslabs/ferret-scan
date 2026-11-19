### 🐛 Bug Fixes

- **phone:** the six blocks of 10,000 numbers ARCEP reserves for audiovisual works (`01 99 00`,
  `02 61 91`, `03 53 01`, `04 65 71`, `05 36 49` and `06 39 98`, each followed by any four digits) are
  held at LOW 15 with the ceiling published, as NANP's `555-0100`..`0199` and Ofcom's drama blocks are.
  Written `+33 1 99 00 47 18`, `+33199004718`, `0033 1 99 00 47 18`, `+33 (0)1 99 00 47 18` or
  nationally without spaces (`0199004718`), the first and last number of each block read `PHONE` 100
  HIGH and now read 15 LOW; every one is still reported, so still redacted. A number one digit outside
  a block keeps its 100. ([#1026](https://github.com/awslabs/ferret-scan/issues/1026))
