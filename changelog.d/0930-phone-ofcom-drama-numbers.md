### 🐛 Bug Fixes

- **phone:** numbers in Ofcom's TV and radio drama blocks (London `020 7946 0xxx`, the no-area
  `01632 960xxx` and mobile `07700 900xxx`, nationally or as `+44`/`0044`, `(0)` included) are held at
  LOW 15 with the ceiling published, as NANP's `555-0100`..`0199` already is. On a labelled line each
  of 15 forms read `PHONE` 100 HIGH and now reads 15 LOW; every one is still reported, so still
  redacted. A number one digit outside each block keeps its 100. Manchester's `0161 496 0xxx` and the
  other Ofcom blocks are not capped yet. ([#930](https://github.com/awslabs/ferret-scan/issues/930))
