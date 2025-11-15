# Social Media Validator Configuration Examples

This document provides configuration examples for common use cases of the Social Media Validator.

## Basic Configuration

### Minimal Configuration
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        - "(?i)@[a-zA-Z0-9_]{1,15}\\b"
      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
```

### Comprehensive Configuration
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?linkedin\\.com/pub/[a-zA-Z0-9_/-]+"

      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        - "(?i)@[a-zA-Z0-9_]{1,15}\\b"

      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
        - "(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io"

      facebook:
        - "(?i)https?://(?:www\\.)?(facebook|fb)\\.com/[a-zA-Z0-9._-]+"
        - "(?i)https?://(?:www\\.)?facebook\\.com/profile\\.php\\?id=\\d+"

      instagram:
        - "(?i)https?://(?:www\\.)?instagram\\.com/[a-zA-Z0-9_.]+/"
        - "(?i)https?://(?:www\\.)?instagr\\.am/[a-zA-Z0-9_.]+/"

      youtube:
        - "(?i)https?://(?:www\\.)?youtube\\.com/(?:user|c|channel)/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?youtube\\.com/@[a-zA-Z0-9_-]+"

      tiktok:
        - "(?i)https?://(?:www\\.)?tiktok\\.com/@[a-zA-Z0-9_.]+/"
        - "(?i)https?://(?:www\\.)?tiktok\\.com/t/[a-zA-Z0-9]+"

    positive_keywords:
      - "profile"
      - "social media"
      - "follow me"
      - "connect with me"
      - "find me on"

    negative_keywords:
      - "example"
      - "test"
      - "placeholder"
      - "demo"
      - "sample"

    platform_keywords:
      linkedin:
        - "professional"
        - "career"
        - "network"
        - "business"
      twitter:
        - "tweet"
        - "follow"
        - "retweet"
      github:
        - "repository"
        - "code"
        - "project"
        - "commit"
```

## Use Case Specific Configurations

### Corporate Environment - Professional Platforms Only
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+"

      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
        - "(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io"

    positive_keywords:
      - "professional"
      - "business"
      - "work"
      - "career"
      - "portfolio"

    negative_keywords:
      - "example"
      - "test"
      - "demo"
      - "sample"
      - "placeholder"

    platform_keywords:
      linkedin:
        - "professional"
        - "career"
        - "network"
        - "business"
        - "work"
        - "job"
      github:
        - "repository"
        - "code"
        - "project"
        - "commit"
        - "pull request"
        - "open source"
```

### Educational Institution - Academic Focus
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+"

      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
        - "(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io"

      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        - "(?i)@[a-zA-Z0-9_]{1,15}\\b"

      youtube:
        - "(?i)https?://(?:www\\.)?youtube\\.com/(?:user|c|channel)/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?youtube\\.com/@[a-zA-Z0-9_-]+"

    positive_keywords:
      - "research"
      - "academic"
      - "professor"
      - "student"
      - "university"
      - "education"

    negative_keywords:
      - "example"
      - "test"
      - "demo"
      - "sample"
      - "placeholder"

    platform_keywords:
      linkedin:
        - "academic"
        - "research"
        - "professor"
        - "university"
      github:
        - "research"
        - "academic"
        - "project"
        - "paper"
      twitter:
        - "academic"
        - "research"
        - "conference"
      youtube:
        - "lecture"
        - "education"
        - "tutorial"
        - "academic"
```

### Marketing Agency - All Platforms
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+"

      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        - "(?i)@[a-zA-Z0-9_]{1,15}\\b"

      facebook:
        - "(?i)https?://(?:www\\.)?(facebook|fb)\\.com/[a-zA-Z0-9._-]+"
        - "(?i)https?://(?:www\\.)?facebook\\.com/profile\\.php\\?id=\\d+"

      instagram:
        - "(?i)https?://(?:www\\.)?instagram\\.com/[a-zA-Z0-9_.]+/"
        - "(?i)https?://(?:www\\.)?instagr\\.am/[a-zA-Z0-9_.]+/"

      youtube:
        - "(?i)https?://(?:www\\.)?youtube\\.com/(?:user|c|channel)/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?youtube\\.com/@[a-zA-Z0-9_-]+"

      tiktok:
        - "(?i)https?://(?:www\\.)?tiktok\\.com/@[a-zA-Z0-9_.]+/"
        - "(?i)https?://(?:www\\.)?tiktok\\.com/t/[a-zA-Z0-9]+"

      discord:
        - "(?i)https?://(?:www\\.)?discord\\.gg/[a-zA-Z0-9]+"
        - "(?i)discord\\.com/users/\\d+"

      reddit:
        - "(?i)https?://(?:www\\.)?reddit\\.com/u(?:ser)?/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?reddit\\.com/r/[a-zA-Z0-9_]+"

    positive_keywords:
      - "social media"
      - "marketing"
      - "campaign"
      - "brand"
      - "influencer"
      - "content"

    negative_keywords:
      - "example"
      - "test"
      - "demo"
      - "sample"
      - "placeholder"

    platform_keywords:
      linkedin:
        - "professional"
        - "business"
        - "b2b"
        - "networking"
      twitter:
        - "tweet"
        - "hashtag"
        - "viral"
        - "trending"
      facebook:
        - "page"
        - "post"
        - "share"
        - "like"
      instagram:
        - "photo"
        - "story"
        - "reel"
        - "hashtag"
      youtube:
        - "video"
        - "channel"
        - "subscribe"
        - "content"
      tiktok:
        - "video"
        - "viral"
        - "trend"
        - "dance"
```

### Security-Focused - High Confidence Only
```yaml
validators:
  social_media:
    platform_patterns:
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]{3,30}"
        - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]{2,50}"

      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]{1,39}(?:/[a-zA-Z0-9_.-]{1,100})?"
        - "(?i)https?://[a-zA-Z0-9_-]{1,39}\\.github\\.io"

      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]{1,15}"

    positive_keywords:
      - "profile"
      - "account"
      - "handle"
      - "username"

    negative_keywords:
      - "example"
      - "test"
      - "demo"
      - "sample"
      - "placeholder"
      - "fake"
      - "mock"
      - "template"
      - "dummy"

    # Stricter platform keywords for higher confidence
    platform_keywords:
      linkedin:
        - "linkedin profile"
        - "professional profile"
        - "business profile"
      github:
        - "github profile"
        - "github repository"
        - "source code"
      twitter:
        - "twitter profile"
        - "twitter handle"
        - "twitter account"
```

## Profile-Based Configurations

### Development Team Profile
```yaml
profiles:
  dev-team:
    format: json
    confidence_levels: high,medium
    checks: SOCIAL_MEDIA
    verbose: true
    recursive: true
    description: "Development team social media scan focusing on GitHub and professional platforms"
    validators:
      social_media:
        platform_patterns:
          github:
            - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
            - "(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io"
          linkedin:
            - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
          twitter:
            - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        platform_keywords:
          github:
            - "repository"
            - "code"
            - "project"
            - "developer"
            - "programming"
          linkedin:
            - "developer"
            - "engineer"
            - "programmer"
            - "software"
          twitter:
            - "developer"
            - "coding"
            - "tech"
```

### HR Department Profile
```yaml
profiles:
  hr-scan:
    format: csv
    confidence_levels: all
    checks: SOCIAL_MEDIA
    verbose: true
    recursive: true
    description: "HR department social media scan for employee background checks"
    validators:
      social_media:
        platform_patterns:
          linkedin:
            - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
          facebook:
            - "(?i)https?://(?:www\\.)?(facebook|fb)\\.com/[a-zA-Z0-9._-]+"
          twitter:
            - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
          instagram:
            - "(?i)https?://(?:www\\.)?instagram\\.com/[a-zA-Z0-9_.]+/"
        positive_keywords:
          - "employee"
          - "staff"
          - "team member"
          - "colleague"
          - "work"
        negative_keywords:
          - "example"
          - "test"
          - "demo"
          - "sample"
```

## Command Line Usage Examples

### Basic Usage with Configuration
```bash
# Use default social media configuration
ferret-scan --file resume.pdf --checks SOCIAL_MEDIA

# Use specific profile
ferret-scan --config ferret.yaml --profile dev-team --file codebase/

# High confidence only
ferret-scan --file document.txt --checks SOCIAL_MEDIA --confidence high
```

### Advanced Usage
```bash
# Comprehensive scan with verbose output
ferret-scan --config ferret.yaml --file documents/ --recursive \
           --checks SOCIAL_MEDIA --verbose --format json \
           --output social-media-findings.json

# Debug mode for troubleshooting
ferret-scan --file document.txt --checks SOCIAL_MEDIA --debug --verbose

# Marketing agency scan
ferret-scan --config ferret.yaml --profile marketing-agency \
           --file campaign-materials/ --recursive
```

## Troubleshooting Configuration Issues

### Common Configuration Problems

1. **Invalid Regex Patterns**
   ```yaml
   # ❌ Wrong - unescaped dots
   - "https://linkedin.com/in/[a-zA-Z0-9_-]+"

   # ✅ Correct - escaped dots
   - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
   ```

2. **Missing Platform Patterns**
   ```yaml
   # ❌ Wrong - empty platform_patterns
   validators:
     social_media:
       platform_patterns: {}

   # ✅ Correct - at least one platform configured
   validators:
     social_media:
       platform_patterns:
         linkedin:
           - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
   ```

3. **Overly Broad Patterns**
   ```yaml
   # ❌ Wrong - too broad, will match everything
   - ".*linkedin.*"

   # ✅ Correct - specific pattern
   - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
   ```

### Testing Configuration
```bash
# Test configuration with debug output
ferret-scan --config ferret.yaml --file test-social-media.txt \
           --checks SOCIAL_MEDIA --debug --verbose

# Validate patterns with a known test file
ferret-scan --file tests/testdata/samples/social-media-comprehensive.txt \
           --checks SOCIAL_MEDIA --verbose
```

### Configuration Validation
The validator will log warnings for:
- Invalid regex patterns that fail to compile
- Empty platform_patterns configuration
- Missing social_media configuration section

Enable debug logging to see detailed configuration status:
```bash
export FERRET_DEBUG=1
ferret-scan --file document.txt --checks SOCIAL_MEDIA
```
