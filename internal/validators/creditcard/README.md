# Credit Card Validator

The Credit Card Validator detects credit card numbers in text content using pattern matching, validation algorithms, and contextual analysis, with automatic identification of specific credit card types for better categorization.

## Supported Card Types

The validator automatically detects and categorizes the following credit card types in the TYPE column:

| Type | Pattern | Description |
|------|---------|-------------|
| **VISA** | 4xxx-xxxx-xxxx-xxxx | Cards starting with 4 |
| **MASTERCARD** | 5xxx-xxxx-xxxx-xxxx | Cards starting with 51-55 or 2221-2720 |
| **AMERICAN_EXPRESS** | 3xxx-xxxxxx-xxxxx | Cards starting with 34 or 37 |
| **DISCOVER** | 6xxx-xxxx-xxxx-xxxx | Cards starting with 6011, 65, or 644-649 |
| **DINERS_CLUB** | 3xxx-xxxxxx-xxxx | Cards starting with 30, 36, or 38 |
| **JCB** | 35xx-xxxx-xxxx-xxxx | Cards starting with 35 |
| **UNIONPAY** | 62xx-xxxx-xxxx-xxxx | Cards starting with 62 |
| **MAESTRO** | 5xxx-xxxx-xxxx-xxxx | Cards starting with 50 or 56-58 |
| **CREDIT_CARD** | Various | Generic type for unrecognized patterns, including cards starting with 8 (private label/regional) |

Two more types are not card brands: **CARD_TRACK_DATA** (a whole magnetic-stripe track or EMV tag 57
value) and **CARD_SECURITY_CODE** (a labelled CVV2/CVC2/CID). See
[Card track data and security codes](#card-track-data-and-security-codes).

## Detection Capabilities

- **Multiple Format Support**: Detects credit cards in various formats:
  - Dash-separated: `4532-0151-1283-0366`
  - Space-separated: `4532 0151 1283 0366`
  - No separators: `4532015112830366`
  - Mixed formats: `4532-0151 1283-0366`
- **XML/HTML Context**: Properly detects cards within XML/HTML tags: `<creditCard>4532-0151-1283-0366</creditCard>`
- **Quoted Strings**: Enhanced detection within quoted contexts: `"card": "4532-0151-1283-0366"`
- **All Card Lengths**: Supports 14-digit (Diners), 15-digit (Amex), and 16-digit cards
- **Luhn Validation**: Uses Luhn algorithm to reduce false positives
- **Card Type Detection**: Identifies card type based on IIN (Issuer Identification Number) ranges
- **Context Analysis**: Analyzes surrounding context to improve confidence scoring
- **Test Number Recognition**: Reports test-pattern literals, repeating shapes and the card numbers payment processors publish for their sandboxes at LOW (at most 15), and never drops them

## Confidence Scoring

The validator assigns confidence scores based on multiple factors:

- **HIGH** (90-100%): Valid card number passing Luhn check with correct length and IIN range for a known card type, and either written in card groups or named as a card (see below)
- **MEDIUM** (60-89%): Valid number passing Luhn check but with uncertain card type or unusual context, or a bare digit run that nothing names as a card
- **LOW** (0-59%): Number with credit card-like pattern but failing validation checks or in contexts suggesting test data

### Bare runs need a card label to reach HIGH

A bare digit run (no space or dash between groups) on a line with no keyword at all is capped at
**75 (MEDIUM)**. Its digits alone (known vendor prefix, no repetition, seven or more distinct
digits) used to score 95 HIGH, and one random run in ten passes Luhn, so request counters and
row counts were reported as confirmed cards (#802). Any one of these clears the ceiling and
leaves the score unchanged:

- a positive card keyword on the line (`card: 4532015112830366`, `visa 4532015112830366`);
- the same word inside an identifier on the line: `cardNumber`, `CreditCard`, `card_number`;
- the same word in the header of the value's column in a CSV/TSV export (`card_number`, `cardNumber`);
- group separators: `4532 0151 1283 0366`, `4532-0151-1283-0366`.

A held value is still reported and still redacted. It carries `confidence_ceiling: 75` in its
metadata, which the document bridge applies again after its context adjustment, so a document
classified as tabular or financial cannot lift it back to HIGH. A line with a negative keyword
(`order id`, `hash`, `test`, ...) is unaffected: it already scores the value at the bottom of LOW.

### Published test numbers are capped at LOW

The card numbers that Adyen, Authorize.net, Braintree, Checkout.com, Square and Stripe print on
their own sandbox testing pages are listed in `published_test_pans.go`, each block citing its page
and the date it was read. A listed value is reported at **at most 15 (LOW)** with
`not_test: false`, wherever it appears: on a `Card number:` line, in a JSON fixture, a CSV row or a
test constant. It is capped, not dropped, so it is still reported and still redacted, and its
`confidence_ceiling: 15` stops a document-level adjustment from lifting it. Measured over the 492
listed values on `Card number:` lines, 386 scored 100 HIGH before this cap and none do now (#883),
so `--profile precommit` passes a fixture that holds only published test numbers and still blocks
one that also holds a real-shaped card.

The lookup is an exact match on the value's digits: a card with the same prefix, or with one digit
changed, keeps its score. Only numbers a processor or card network publishes on its own testing
page are listed, never numbers that are merely common in tutorials or generator output.

The same published ceiling now holds the test-pattern literals (`4111111111111111`, ...) and
repeating shapes (`6011111111111117`), which a CSV export used to lift from 15 to 35.

## Card track data and security codes

PCI DSS v4.0 Requirements 3.3.1.1 and 3.3.1.2 forbid keeping a card's full track data or its
security code after authorisation, so both are reported under their own types (#905; up to
v2.6.0 they were reported under the PAN's brand type and `CREDIT_CARD` with `metadata.card_frame`).
`--checks CREDIT_CARD` reports both.

**`CARD_TRACK_DATA`** is one of three frames, each with the PAN first:

| Frame | Shape | `card_frame` |
|-------|-------|--------------|
| ISO/IEC 7813 Track 1 | `%B<PAN>^SURNAME/GIVEN^YYMM<service code><discretionary>?` | `track1` |
| ISO/IEC 7813 Track 2 | `;<PAN>=YYMM<service code><discretionary>?`, also URL-encoded (`%3B`, `%3D`, `%3F`) | `track2` |
| EMV tag 57 (Track 2 Equivalent Data) | `<PAN>DYYMM<service code><discretionary>[F]`, bare or inside a TLV | `emv57` |

The sentinels are optional. The finding's text is the whole frame, from its first byte to its
last, so redaction removes the expiry, service code, discretionary data and Track 1's cardholder
name together with the PAN. `metadata.card_type` names the PAN's brand. The PAN is also reported
on its own under its brand type. A frame needs a Luhn-valid PAN of a valid length, a month from
01 to 12, a valid service code and at most the format's length (79 characters for Track 1, 40 for
Track 2, 38 nibbles for tag 57); when one of the last three fails, only the PAN is reported. A
service code starting with 9 (a test card) holds both findings at LOW.

**`CARD_SECURITY_CODE`** is a three- or four-digit value after a label on the same line
(`CVV: 123`, `cvv=123`, `"cvv": "123"`, `CID 1234`); the text runs from the label to the last
digit, so the label is masked with the value, and `card_frame` is `security_code`.

- With a card on the same line or within 3 lines, the code takes that card's confidence.
- An unambiguous label (`cvv`, `cvv2`, `cvc`, `cvc2`, `ccv`, `cav2`, `card security code`,
  `card verification value/code/number`) with no card in reach is reported at 40 (LOW).
- A context-only label (`cid`, `csc`, `cvn`, `cvn2`, `security code`) also names a caller ID, a
  MIME Content-ID or a date, so it is reported only with a card in reach.
- Digits with no label (a CSV `cvv` column, `PAN|12/28|123`) are not reported.

Redaction, measured on a Track 2, a Track 1 and `cvv: 123` beside a card:

| Strategy | Track data | Security code |
|----------|------------|---------------|
| `simple` | `[CARD_TRACK_DATA-REDACTED]` | `[CARD_SECURITY_CODE-REDACTED]` |
| `format_preserving` | every byte `*` (name and sentinels included) | every byte `*` (label included) |
| `synthetic` | a fake frame of the same shape whose PAN fails the Luhn check, with a fake name | a random string |

A suppression rule written in v2.6.0 for a frame or code finding hashed the old type and no
longer matches; regenerate it.

## Implementation Details

The validator uses an optimized multi-step process:

1. **Enhanced Pattern Matching**: Uses comprehensive regex patterns to identify potential credit card numbers in multiple formats:
   - Dash-separated patterns: `\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}`
   - Space-only patterns: `\d{4}\s\d{4}\s\d{4}\s\d{4}`
   - No-separator patterns: `\d{16}`, `\d{15}`, `\d{14}`
   - XML/HTML boundary support: `(?:^|[\s\t,;|"'(){}[\]<>])`

2. **Luhn Algorithm Validation**: Filters out mathematically invalid numbers to reduce false positives

3. **Efficient BIN Range Checking**: Uses optimized range lookup instead of massive maps for card type identification

4. **Context Analysis**: Analyzes surrounding text with positive/negative keyword detection:
   - Positive keywords: "credit", "card", "payment", "visa", "mastercard"
   - Negative keywords: "account", "id", "serial", "tracking", "reference"

5. **Test Number Detection**: Caps test-pattern literals, repeating shapes and processor-published test numbers at 15 (LOW), and publishes the cap as `confidence_ceiling`

6. **Performance Optimizations**:
   - Early filtering by length and format
   - Pre-compiled regex patterns
   - Efficient BIN range lookup (600x faster validator creation)

## Format Support Examples

The validator now supports credit cards in various contexts:

```text
<!-- XML/HTML Context -->
<creditCard>4532-0151-1283-0366</creditCard>
<input value="5425-2334-3010-9903">

<!-- JSON Context -->
{
  "visa": "4532015112830366",
  "mastercard": "5425 2334 3010 9903"
}

<!-- CSV Context -->
Name,Card,Expiry
John,"4532-0151-1283-0366",12/25

<!-- Tabular Data -->
Name            Card                    Expiry
John Smith      4532-0151-1283-0366     12/25
Jane Doe        5425 2334 3010 9903     06/26
```

## Usage Examples

```go
// Create a new credit card validator
validator := creditcard.NewValidator()

// Validate already-extracted content (the scan pipeline reads/preprocesses the
// file once and passes the text in; the second arg is the original path, used
// only for reporting/context).
content, _ := os.ReadFile("path/to/file.txt")
matches, err := validator.ValidateContent(string(content), "path/to/file.txt")
if err != nil {
    log.Fatalf("Error validating content: %v", err)
}

// Process matches
for _, match := range matches {
    fmt.Printf("Found credit card: %s (Type: %s, Confidence: %.2f)\n",
        match.Text, match.Type, match.Confidence)

    // Access additional metadata
    if cardType, ok := match.Metadata["card_type"].(string); ok {
        fmt.Printf("  Card Type: %s\n", cardType)
    }
    if vendor, ok := match.Metadata["vendor"].(string); ok {
        fmt.Printf("  Vendor: %s\n", vendor)
    }
}
```

## Example Output

The validator detects credit cards in various formats and provides detailed type information:

```
LEVEL    VALIDATOR    TYPE                 CONF%    LINE       MATCH               FILE
---------------------------------------------------------------------------------------------
[HIGH  ] creditcard   VISA                  100.00% line     1 4532-0151-1283-0366 document.txt
[HIGH  ] creditcard   VISA                  100.00% line     2 4532 0151 1283 0366 document.txt
[MEDIUM] creditcard   VISA                   75.00% line     3 4532015112830366    document.txt
[HIGH  ] creditcard   MASTERCARD            100.00% line     4 5425-2334-3010-9903 document.txt
[LOW   ] creditcard   AMERICAN_EXPRESS       15.00% line     5 3782-8224-6310-005  document.txt
[LOW   ] creditcard   VISA                   15.00% line     6 4000-0000-0000-0002 document.txt
```

**Key Features:**
- **Multiple Formats**: Same card detected in dash, space, and no-separator formats
- **Card Labels**: The no-separator form on line 3 has no card word on its line, so it is held to MEDIUM 75 (see "Bare runs need a card label to reach HIGH")
- **Test Numbers**: The Amex on line 5 and the Visa on line 6 are numbers payment processors publish for testing, so both are LOW 15 (see "Published test numbers are capped at LOW")
- **Accurate Typing**: Precise card type identification (VISA, MASTERCARD, etc.)
- **Confidence Scoring**: High confidence for real cards, low for test patterns
- **Context Awareness**: Confidence adjusted based on surrounding text

This comprehensive detection makes it easier to identify and handle different credit card formats according to your specific security requirements.
