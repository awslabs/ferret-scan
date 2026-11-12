### 📚 Documentation

- **help (`--help CREDIT_CARD`, `--help PHONE`), validator READMEs:** the credit-card page now
  describes `CARD_TRACK_DATA` (Track 1, Track 2, URL-encoded Track 2, EMV tag 57) and
  `CARD_SECURITY_CODE` (labelled CVV2/CVC2/CID): what each matches, how it is scored and how each
  strategy redacts it ([#905](https://github.com/awslabs/ferret-scan/issues/905)). It no longer lists
  a `PRIVATE_LABEL_CARD` type, which nothing emits (a card starting with 8 is reported as
  `CREDIT_CARD`), or JCB prefixes 2131 and 1800, which are not typed as JCB. The phone page names the
  international display forms, `tel:` URIs and vCard `TEL` values added for
  [#889](https://github.com/awslabs/ferret-scan/issues/889), and both the page and the phone README
  list Ofcom's three drama ranges beside NANP's 555-0100 to 555-0199 as reserved numbers held at 15.
