### 🚀 Features

- **creditcard (card track data and security codes):** magnetic-stripe Track 1 and Track 2 data
  (ISO/IEC 7813, a URL-encoded Track 2 included), EMV Track 2 Equivalent Data (tag 57, bare or
  inside TLV hex) and a labelled card security code (`CVV: 123`, `cvv=123`, `"cvv": "123"`,
  `CID 1234`) are now reported and redacted
  ([#905](https://github.com/awslabs/ferret-scan/issues/905)). On the issue's 40 synthetic files
  main reported no Track 1, tag 57 or URL-encoded Track 2 at all, PAN included, ended each Track 2
  finding at its `=` and reported none of the 11 labelled codes, so `--enable-redaction` left 15 of
  36 PANs, all 27 expiry and service codes, all 11 cardholder names and all 11 codes in cleartext. A
  frame is now reported whole, beside its PAN, under the PAN's card type with `card_frame`
  (`track1`, `track2`, `emv57`) in its metadata, scored as its PAN plus one card word (100 on the
  issue's files). A code is a `CREDIT_CARD` finding with `card_frame: security_code` whose text runs
  from its label to its last digit, at the confidence of the best card within three lines, or 40
  with none in reach; `cid`, `csc`, `cvn` and `security code` are reported only with a card in
  reach. Under `simple` none of those values survive; under `format_preserving` no PAN, expiry,
  service-code or code digit does, but the card mask still keeps a Track 1 name and a frame's last
  four digits until the frame has a type of its own. Every finding main reports is unchanged, byte
  for byte, and the issue's decoys (`CID 1234 called at 09:14`, `csc : 2014-09-25`,
  `<cid:1234@mail.invalid>`, `cvn := 123`) report nothing.
