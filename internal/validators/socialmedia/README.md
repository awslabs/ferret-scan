# Social Media Validator

The Social Media Validator detects social media profiles, usernames, and handles across major platforms including LinkedIn, Twitter/X, Facebook, Instagram, GitHub, TikTok, YouTube, and others.

## Overview

This validator follows the established Ferret Scan validator architecture patterns and provides:

- **Platform-specific detection**: Separate pattern groups for each social media platform
- **Configuration-driven patterns**: Customizable through ferret.yaml configuration
- **Contextual analysis**: Uses positive/negative keywords and platform-specific context
- **Confidence scoring**: Multi-factor validation with platform-specific rules
- **False positive prevention**: Excludes test data, examples, and placeholder content
- **Profile clustering**: Groups related social media matches for enhanced accuracy

## Supported Platforms

### Primary Platforms
- **LinkedIn**: Profile URLs, company pages, public profile URLs
- **Twitter/X**: Handles (@username), profile URLs, mobile variants  
- **Facebook**: Profile URLs, numeric IDs, page formats
- **GitHub**: Username URLs, repository URLs, GitHub Pages domains
- **Instagram**: Profile URLs, handle references
- **YouTube**: Channel URLs, user URLs, handle formats
- **TikTok**: Handle formats, short URLs

### Additional Platforms
- **Discord**: Server invites, user references
- **Reddit**: User profiles, subreddit references
- **Snapchat**: Username references
- **Other platforms**: Extensible through configuration

## Detection Capabilities

### URL Pattern Detection
- Detects full social media URLs with proper validation
- Validates platform-specific URL formats and requirements
- Handles various URL schemes (http/https, www/non-www, mobile variants)

### Handle Detection
- Identifies @username patterns with platform-specific validation
- Validates username format rules for each platform
- Contextual analysis to distinguish social media handles from other @ references

### Profile Clustering
- Groups related social media profiles found together
- Boosts confidence for profiles that appear to belong to the same person
- Reconstructs fragmented social media references

## Confidence Scoring Methodology

The validator uses a multi-factor confidence scoring system:

### Base Confidence Factors (100% total)
1. **Platform Pattern Validation (35%)**: Validates URL format and username rules
2. **Contextual Keywords (25%)**: Analyzes surrounding text for social media terminology
3. **Platform-Specific Context (15%)**: Checks for platform-specific keywords
4. **False Positive Prevention (15%)**: Excludes test data and examples
5. **Profile Clustering (10%)**: Boosts confidence for related profiles

### Contextual Adjustments
- **Positive keywords**: +5% each (up to +25% total)
- **Platform-specific keywords**: +8% each (higher weight)
- **Negative keywords**: -15% each (up to -50% total)
- **Profile clustering**: +10% for related profiles

### Confidence Levels
- **HIGH (90-100%)**: Very likely to be actual social media references
- **MEDIUM (60-89%)**: Possibly social media references
- **LOW (0-59%)**: Likely false positives or test data

## Configuration

### Basic Configuration
```yaml
validators:
  social_media:
    # Enable/disable specific platforms
    enabled_platforms:
      - "linkedin"
      - "twitter" 
      - "github"
      - "facebook"
      - "instagram"
      - "youtube"
      - "tiktok"
```

### Custom Pattern Configuration
```yaml
validators:
  social_media:
    # Platform-specific pattern groups
    linkedin_patterns:
      - "(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+"
      - "(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+"
      - "(?i)https?://(?:www\\.)?linkedin\\.com/pub/[a-zA-Z0-9_/-]+"
    
    twitter_patterns:
      - "(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+"
      - "(?i)@[a-zA-Z0-9_]{1,15}\\b"
    
    github_patterns:
      - "(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?"
      - "(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io"
```

### Contextual Analysis Configuration
```yaml
validators:
  social_media:
    # Custom positive/negative keywords
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
    
    # Platform-specific context keywords
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

## Usage Examples

### Basic Usage
```bash
# Scan for social media references
ferret-scan --file document.txt --checks SOCIAL_MEDIA

# High confidence only
ferret-scan --file document.txt --checks SOCIAL_MEDIA --confidence high

# Verbose output with details
ferret-scan --file document.txt --checks SOCIAL_MEDIA --verbose
```

### With Configuration
```bash
# Use custom configuration
ferret-scan --config ferret.yaml --file document.txt --checks SOCIAL_MEDIA

# Use specific profile
ferret-scan --config ferret.yaml --profile social-media --file document.txt
```

### Output Formats
```bash
# JSON output
ferret-scan --file document.txt --checks SOCIAL_MEDIA --format json

# CSV output
ferret-scan --file document.txt --checks SOCIAL_MEDIA --format csv --output results.csv
```

## Implementation Details

### Architecture
- **Package**: `internal/validators/socialmedia/`
- **Interfaces**: Implements `detector.Validator` and `help.HelpProvider`
- **Configuration**: Integrates with existing config system
- **Observability**: Uses standard observability framework

### Performance Optimizations
- Compiled regex patterns cached in memory
- Line-by-line processing for memory efficiency
- Early termination for low-confidence matches
- Batch processing optimizations

### Error Handling
- Graceful degradation for invalid patterns
- Comprehensive logging for troubleshooting
- Fallback to default patterns if configuration fails
- Memory management for large files

## Testing

The validator includes comprehensive test coverage:

### Unit Tests
- Pattern matching accuracy for each platform
- Configuration loading and validation
- Confidence scoring algorithms
- Contextual analysis functionality
- Error handling scenarios

### Integration Tests
- End-to-end validation with real social media content
- Configuration file parsing and application
- Performance testing with large files
- Cross-platform pattern validation

## Security Considerations

- No logging of actual social media handles in production
- Memory scrubbing for sensitive matches
- Secure handling of configuration data
- Pattern validation to prevent ReDoS attacks

## Troubleshooting

### Common Issues

1. **No matches found**: Check if patterns are configured correctly
2. **Too many false positives**: Adjust negative keywords or confidence thresholds
3. **Missing platform**: Add platform-specific patterns to configuration
4. **Performance issues**: Review regex patterns for efficiency

### Debug Mode
```bash
# Enable debug logging
ferret-scan --file document.txt --checks SOCIAL_MEDIA --debug
```

### Configuration Validation
```bash
# Test configuration
ferret-scan --config ferret.yaml --file test.txt --checks SOCIAL_MEDIA --verbose
```

## Contributing

When extending the Social Media Validator:

1. Follow the established validator architecture patterns
2. Add comprehensive test coverage for new platforms
3. Update documentation and help text
4. Ensure backward compatibility
5. Follow security best practices

## Related Documentation

- [Main README](../../../README.md)
- [Configuration Guide](../../../docs/configuration.md)
- [Validator Creation Guide](../../../docs/development/creating_validators.md)
- [Architecture Documentation](../../../docs/architecture-diagram.md)