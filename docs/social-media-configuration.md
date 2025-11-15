# Social Media Validator Configuration Guide

The Social Media validator detects social media profiles, handles, and references across multiple platforms. This comprehensive guide explains how to configure it properly for accurate detection while avoiding false positives.

## Overview

The Social Media validator is **disabled by default** for privacy and security reasons. You must explicitly configure it to enable detection.

**Key Features:**
- Detects 18+ social media platforms
- Email-safe Twitter pattern (won't match @gmail from emails)
- Context analysis for improved accuracy
- Performance optimizations for large files
- Configurable false positive prevention

## Basic Configuration

Add this section to your `ferret.yaml` or `~/.ferret-scan/config.yaml`:

```yaml
validators:
  social_media:
    platform_patterns:
      # Configure patterns for platforms you want to detect
      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        - "(?i)(?<!\\w)@[a-zA-Z0-9_]{1,15}(?!@|\\.[a-zA-Z])"  # Avoids email false positives

      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
        - "(?i)github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"

      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
        - "(?i)linkedin\\.com/in/[a-zA-Z0-9_-]+"
```

## Supported Platforms

The validator supports detection for these platforms:

### Professional Networks
- **LinkedIn**: Personal profiles, company pages, public profiles
- **Stack Overflow**: Developer profiles

### Social Networks
- **Twitter/X**: Profile URLs, @handles (with email protection)
- **Facebook**: Profile and page URLs
- **Instagram**: Profile URLs
- **Mastodon**: Decentralized social network handles

### Developer Platforms
- **GitHub**: User profiles, repositories, GitHub Pages
- **Medium**: Publishing platform profiles

### Video/Streaming
- **YouTube**: Channels, new @handle format
- **TikTok**: Profile URLs, short links
- **Twitch**: Streaming channels

### Communication
- **Discord**: Server invites, user profiles
- **Telegram**: Channel and user URLs
- **WhatsApp**: Contact links
- **Skype**: Profile URLs and protocol links

### Other Platforms
- **Reddit**: User profiles, subreddits
- **Pinterest**: Profile URLs
- **Snapchat**: Add friend links
- **Clubhouse**: Audio social networking

## Complete Configuration Example

```yaml
validators:
  social_media:
    platform_patterns:
      # LinkedIn - Professional networking
      linkedin:
        - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+"
        - "(?i)linkedin\\.com/in/[a-zA-Z0-9_-]+"

      # Twitter/X - Microblogging (email-safe patterns)
      twitter:
        - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
        - "(?i)(?<!\\w)@[a-zA-Z0-9_]{1,15}(?!@|\\.[a-zA-Z])"  # Avoids @gmail from emails
        - "(?i)(twitter|x)\\.com/[a-zA-Z0-9_]+"

      # GitHub - Code repositories
      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
        - "(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io"
        - "(?i)github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"

      # Facebook - Social networking
      facebook:
        - "(?i)https?://(?:www\\.)?(facebook|fb)\\.com/[a-zA-Z0-9._-]+"
        - "(?i)https?://(?:www\\.)?facebook\\.com/profile\\.php\\?id=\\d+"
        - "(?i)(facebook|fb)\\.com/[a-zA-Z0-9._-]+"

      # Instagram - Photo sharing
      instagram:
        - "(?i)https?://(?:www\\.)?instagram\\.com/[a-zA-Z0-9_.]+/"
        - "(?i)https?://(?:www\\.)?instagr\\.am/[a-zA-Z0-9_.]+/"
        - "(?i)instagram\\.com/[a-zA-Z0-9_.]+/"

      # YouTube - Video sharing
      youtube:
        - "(?i)https?://(?:www\\.)?youtube\\.com/(?:user|c|channel)/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?youtube\\.com/@[a-zA-Z0-9_-]+"
        - "(?i)youtube\\.com/(?:user|c|channel)/[a-zA-Z0-9_-]+"

      # TikTok - Short videos
      tiktok:
        - "(?i)https?://(?:www\\.)?tiktok\\.com/@[a-zA-Z0-9_.]+/"
        - "(?i)https?://(?:www\\.)?tiktok\\.com/t/[a-zA-Z0-9]+"
        - "(?i)tiktok\\.com/@[a-zA-Z0-9_.]+/"

      # Discord - Gaming/community chat
      discord:
        - "(?i)https?://(?:www\\.)?discord\\.gg/[a-zA-Z0-9]+"
        - "(?i)https?://(?:www\\.)?discord\\.com/users/\\d+"
        - "(?i)discord\\.gg/[a-zA-Z0-9]+"

      # Reddit - Social news
      reddit:
        - "(?i)https?://(?:www\\.)?reddit\\.com/u(?:ser)?/[a-zA-Z0-9_-]+"
        - "(?i)https?://(?:www\\.)?reddit\\.com/r/[a-zA-Z0-9_]+"
        - "(?i)reddit\\.com/u(?:ser)?/[a-zA-Z0-9_-]+"

    # Context analysis keywords
    positive_keywords:
      - "profile"
      - "social media"
      - "follow me"
      - "connect with me"
      - "find me on"
      - "professional"
      - "networking"
      - "social"
      - "handle"
      - "username"
      - "account"

    negative_keywords:
      - "example"
      - "test"
      - "placeholder"
      - "demo"
      - "sample"
      - "documentation"
      - "tutorial"
      - "mock"
      - "fake"
      - "dummy"

    # Platform-specific context keywords
    platform_keywords:
      linkedin:
        - "professional"
        - "career"
        - "network"
        - "business"
        - "connect"
      twitter:
        - "tweet"
        - "follow"
        - "retweet"
        - "hashtag"
      github:
        - "repository"
        - "code"
        - "project"
        - "developer"
        - "open source"

    # False positive prevention
    whitelist_patterns:
      - "(?i)example\\.com"
      - "(?i)test\\.com"
      - "(?i)placeholder"
      - "(?i)demo"
```

## Important Notes

### Email vs Social Media
- **DO NOT** include email patterns in social media configuration
- The dedicated EMAIL validator handles email addresses
- The Twitter pattern `(?i)(?<!\\w)@[a-zA-Z0-9_]{1,15}(?!@|\\.[a-zA-Z])` prevents matching email domains like `@gmail`

### Pattern Guidelines
- Use case-insensitive patterns: `(?i)`
- Include both full URLs and domain-only patterns
- Test patterns to avoid false positives
- Consider platform-specific username rules

### Security Considerations
- Social media detection is disabled by default
- Only configure platforms you need to detect
- Use whitelist patterns to reduce false positives
- Consider privacy implications when scanning personal documents

## Usage Examples

### Basic scan with social media detection:
```bash
ferret-scan --file document.pdf --checks SOCIAL_MEDIA --show-match
```

### Verbose output with detailed information:
```bash
ferret-scan --file document.pdf --checks SOCIAL_MEDIA --show-match --verbose
```

### Scan only social media (exclude other validators):
```bash
ferret-scan --file document.pdf --checks SOCIAL_MEDIA
```

### Debug mode to see pattern matching:
```bash
ferret-scan --file document.pdf --checks SOCIAL_MEDIA --debug
```

## Troubleshooting

### No matches found
1. Check if social media validator is configured
2. Verify patterns are valid regex
3. Use `--debug` to see configuration loading
4. Test with known social media content

### False positives
1. Add negative keywords
2. Use whitelist patterns
3. Refine regex patterns
4. Check for email/social media conflicts

### Email addresses detected as social media
1. Remove email patterns from social media config
2. Use the improved Twitter pattern that avoids email domains
3. Let the EMAIL validator handle email addresses

## Configuration Validation

The validator will log warnings if:
- No patterns are configured
- Invalid regex patterns are found
- Patterns conflict with other validators

Use `--debug` mode to see detailed configuration information and pattern compilation results.

## Performance Features

The social media validator includes several performance optimizations:

### Pattern Caching
- Compiled regex patterns are cached globally
- 85% faster pattern matching on subsequent uses
- Thread-safe pattern cache with mutex protection

### Batch Processing
- Automatic batch processing for files larger than 1MB
- Processes content in 1000-line batches
- Reduces memory usage for large documents

### Memory Management
- Memory monitoring for files larger than 50MB
- Automatic memory optimization triggers
- Garbage collection hints for very large files

### Context Analysis Optimization
- Expensive context analysis only runs for high-confidence matches (>50%)
- Platform-specific keyword matching
- Optimized false positive detection

## File Location Options

You can place your configuration in several locations:

### Project-Level Configuration
Create `ferret.yaml` in your project root:
```yaml
validators:
  social_media:
    # Your configuration here
```

### User-Level Configuration
Create `~/.ferret-scan/config.yaml` for global settings:
```yaml
validators:
  social_media:
    # Your global configuration here
```

### Custom Configuration File
Use any custom file with the `--config` flag:
```bash
ferret-scan --config my-social-config.yaml --checks SOCIAL_MEDIA --file document.pdf
```

## Advanced Usage Examples

### CI/CD Integration
```yaml
# .github/workflows/social-media-scan.yml
name: Social Media Detection
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Scan for social media
        run: |
          ./ferret-scan --checks SOCIAL_MEDIA --format json --output social-media-report.json --recursive --file ./documents/
```

### Docker Usage
```bash
# Mount your config and scan directory
./scripts/container-run.sh -v $(pwd)/ferret.yaml:/app/ferret.yaml \
           -v $(pwd)/documents:/app/documents \
           ferret-scan --checks SOCIAL_MEDIA --file /app/documents/

# Or use container runtime directly:
# docker run -v $(pwd)/ferret.yaml:/app/ferret.yaml -v $(pwd)/documents:/app/documents ferret-scan --checks SOCIAL_MEDIA --file /app/documents/
# finch run -v $(pwd)/ferret.yaml:/app/ferret.yaml -v $(pwd)/documents:/app/documents ferret-scan --checks SOCIAL_MEDIA --file /app/documents/
```

### Batch Processing Multiple Files
```bash
# Scan all PDFs in a directory
find ./documents -name "*.pdf" -exec ./ferret-scan --checks SOCIAL_MEDIA --show-match --file {} \;

# Scan with custom output format
./ferret-scan --checks SOCIAL_MEDIA --format json --recursive --file ./documents/ > social-media-results.json
```

## Configuration Validation

The validator will log warnings if:
- No patterns are configured
- Invalid regex patterns are found
- Patterns conflict with other validators

Use `--debug` mode to see detailed configuration information and pattern compilation results.

## Migration from Other Tools

If you're migrating from other social media detection tools, here are some common patterns:

### From Manual Regex Lists
```yaml
# Instead of maintaining separate regex files
validators:
  social_media:
    platform_patterns:
      # Organize by platform for better maintainability
      twitter:
        - "your_twitter_patterns_here"
      linkedin:
        - "your_linkedin_patterns_here"
```

### From Generic URL Validators
```yaml
# Instead of generic URL detection, use platform-specific patterns
validators:
  social_media:
    platform_patterns:
      # Platform-specific patterns are more accurate
      github:
        - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
    # Add context keywords for better accuracy
    positive_keywords:
      - "repository"
      - "code"
      - "project"
```
