# Enhanced Email Validator

The Enhanced Email Validator detects email addresses and automatically identifies specific email providers for better categorization and handling.

## Advanced Detection and Classification

### Email Provider Detection

The validator automatically identifies specific email providers and displays them in the TYPE column:

#### **Major Consumer Email Providers**
- **GMAIL** - Gmail and Google Mail addresses (`gmail.com`, `googlemail.com`)
- **GOOGLE_WORKSPACE** - Google Workspace/G Suite business emails (`google.com`)
- **OUTLOOK** - Microsoft consumer email services (`outlook.com`, `hotmail.com`, `live.com`, `msn.com`)
- **MICROSOFT_365** - Microsoft 365 business emails (`microsoft.com`)
- **YAHOO** - Yahoo Mail addresses (all international variants: `yahoo.com`, `yahoo.co.uk`, etc.)
- **ICLOUD** - Apple consumer email services (`icloud.com`, `me.com`, `mac.com`)
- **APPLE_CORPORATE** - Apple corporate emails (`apple.com`)

#### **Secure Email Providers**
- **PROTONMAIL** - ProtonMail secure email addresses (`protonmail.com`, `proton.me`, `pm.me`)
- **TUTANOTA** - Tutanota secure email addresses (`tutanota.com`, `tutanota.de`, `tutamail.com`, `tuta.io`)
- **FASTMAIL** - FastMail addresses (`fastmail.com`, `fastmail.fm`)

#### **Business and Enterprise Providers**
- **ZOHO** - Zoho Mail addresses (`zoho.com`, `zohomail.com`)
- **YANDEX** - Yandex Mail addresses (`yandex.com`, `yandex.ru`)
- **MAIL_RU** - Mail.ru and related Russian email services
- **AOL** - AOL Mail addresses (`aol.com`)
- **SALESFORCE** - Salesforce corporate emails
- **SLACK** - Slack corporate emails
- **ATLASSIAN** - Atlassian corporate emails
- **GITHUB** - GitHub corporate emails
- **GITLAB** - GitLab corporate emails

#### **Institutional Email Types**
- **EDUCATIONAL** - Educational institution emails (`.edu`, `.ac.uk`, `.edu.au`, etc.)
- **GOVERNMENT** - Government emails (`.gov`, `.mil`, `.gov.uk`, etc.)
- **BUSINESS** - Corporate/business domain emails (automatically detected)

#### **Special Categories**
- **DISPOSABLE** - Temporary/disposable email services (40+ known providers)
- **EMAIL** - Generic email addresses (fallback for unrecognized domains)

## Detection Methods

### 1. Pattern Matching
Uses RFC-compliant regex patterns to identify valid email address formats:
```
\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b
```

### 2. Domain Analysis
Analyzes the domain portion to determine the email provider type:
- Exact domain matching for major providers
- TLD-based classification for institutional emails
- Pattern analysis for business domains
- Disposable email service detection

### 3. Contextual Analysis
Analyzes surrounding text for email-related keywords:

**Positive Keywords** (increase confidence):
- email, e-mail, contact, mailto, address, recipient, sender
- from, to, cc, bcc, reply, subscribe, unsubscribe
- notification, alert, newsletter, support, info, admin

**Negative Keywords** (decrease confidence):
- test, example, fake, mock, sample, dummy, placeholder
- demo, template, tutorial, documentation, readme

### 4. Validation Checks
Performs comprehensive validation:
- **Valid Format** (30% weight) - RFC compliance
- **Valid Domain** (20% weight) - Domain structure validation
- **Valid TLD** (15% weight) - Top-level domain recognition
- **Not Test Email** (20% weight) - Test pattern detection
- **Reasonable Length** (10% weight) - Length limits (6-254 characters)
- **No Consecutive Dots** (5% weight) - Format validation

## Confidence Scoring

### High Confidence (90-100%)
- Government and institutional emails
- Well-formed business emails with context
- Major provider emails with supporting keywords

### Medium Confidence (60-89%)
- Major consumer email providers
- Business emails without strong context
- Educational emails

### Low Confidence (40-59%)
- Secure email providers (often flagged as test data)
- Emails with negative context keywords
- Unusual but valid formats

## Examples

### Input:
```
Contact us at:
- Support: support@company.com
- Sales: sales@gmail.com
- Admin: admin@university.edu
- Government: contact@agency.gov
- Temp: user@10minutemail.com
```

### Output:
```
[HIGH  ] email        GOVERNMENT     100.00% line 4 contact@agency.gov
[HIGH  ] email        BUSINESS        95.00% line 2 support@company.com
[MEDIUM] email        GMAIL           85.00% line 3 sales@gmail.com
[MEDIUM] email        EDUCATIONAL     75.00% line 4 admin@university.edu
[MEDIUM] email        DISPOSABLE      65.00% line 5 user@10minutemail.com
```

## Integration

The Email Validator integrates seamlessly with:
- **Redaction System** - Supports all redaction strategies (simple, format-preserving, synthetic)
- **Context Analysis** - Uses document context for improved accuracy
- **Metadata Extraction** - Provides detailed email component analysis
- **Suppression System** - Supports email-specific suppression rules

## Configuration

The validator supports configuration through the standard Ferret Scan configuration system:

```yaml
validators:
  email:
    enabled: true
    confidence_threshold: 60
    context_analysis: true
    provider_detection: true
```

## Performance

- **Fast Pattern Matching** - Pre-compiled regex for optimal performance
- **Efficient Domain Lookup** - Hash-based provider identification
- **Context Caching** - Optimized context analysis
- **Memory Efficient** - Minimal memory footprint per validation

The Enhanced Email Validator provides comprehensive email detection with intelligent provider classification, making it easier to handle different types of email addresses appropriately in your data processing workflows.
