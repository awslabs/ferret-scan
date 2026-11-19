### 🐛 Bug Fixes

- **phone:** the sixteen other blocks of 1,000 numbers Ofcom reserves for TV and radio drama are held at
  LOW 15 with the ceiling published, as the four already held are: `0113`, `0114`, `0115`, `0116`,
  `0117`, `0118`, `0121`, `0131`, `0141` and `0151` `496 0000`-`0999`, `0191 498 0xxx`,
  `028 9649 6xxx`, `029 2018 0xxx`, `0808 157 0xxx`, `0909 879 0xxx` and `0306 999 0xxx`, nationally or
  as `+44`/`0044`. On a labelled line the first and last number of each block read `PHONE` 100 HIGH and
  now read 15 LOW; every one is still reported, so still redacted. A number one digit outside a block
  keeps its 100. ⚠ Northern Ireland's block is `028 9649 6xxx`, as Ofcom's page lists it; the
  `028 9018 0xxx` block that older copies of the table give is not held.
  ([#1019](https://github.com/awslabs/ferret-scan/issues/1019))
