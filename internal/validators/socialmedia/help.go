// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about this check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	// Create a new CheckInfo struct
	info := help.CheckInfo{}

	// Set basic information
	info.Name = "SOCIAL_MEDIA"
	info.ShortDescription = "Detects social media profiles, usernames, and handles across major platforms"
	info.DetailedDescription = `This validator detects social media references across major platforms including:
- LinkedIn profile URLs and handles (@username, linkedin.com/in/username)
- Twitter/X handles and profile URLs (@username, twitter.com/username, x.com/username)
- Facebook profile URLs and references (facebook.com/username, fb.com/username)
- GitHub usernames and repository URLs (github.com/username, github.io domains)
- Instagram handles and profile URLs (instagram.com/username, @username)
- YouTube channel URLs and handles (youtube.com/@username, youtube.com/c/channel)
- TikTok handles and profile URLs (tiktok.com/@username)
- Additional platforms (Discord, Reddit, Snapchat, etc.)

The validator uses configuration-driven pattern matching with platform-specific categorization
and contextual analysis to determine the likelihood that detected patterns represent actual
social media references. It includes false positive prevention to avoid flagging test data,
examples, and non-social-media content.

IMPORTANT: Social media detection patterns can be customized through ferret.yaml configuration.
The validator includes sensible defaults but can be tailored to organizational needs.`

	// Set patterns with detailed platform-specific descriptions
	info.Patterns = []string{
		"LinkedIn profile URLs (linkedin.com/in/username, linkedin.com/company/name, linkedin.com/pub/name)",
		"Twitter/X handles and URLs (@username with 1-15 characters, twitter.com/username, x.com/username)",
		"Facebook profile URLs (facebook.com/username, fb.com/username, facebook.com/profile.php?id=numeric)",
		"GitHub usernames and repositories (github.com/username, github.com/username/repo, username.github.io)",
		"Instagram handles and URLs (instagram.com/username, instagr.am/username, @username with 1-30 characters)",
		"YouTube channel URLs (youtube.com/@username, youtube.com/c/channel, youtube.com/user/username)",
		"TikTok handles and URLs (tiktok.com/@username, tiktok.com/t/shortcode)",
		"Discord server invites and user references (discord.gg/invite, discord.com/users/userid)",
		"Reddit user profiles and subreddits (reddit.com/u/username, reddit.com/r/subreddit)",
		"Additional platforms (Snapchat, Pinterest, Twitch, and other social media services)",
	}

	// Set supported formats with detailed validation rules
	info.SupportedFormats = []string{
		"LinkedIn: Profile URLs (/in/username), company pages (/company/name), public profiles (/pub/name) - 3-100 character usernames",
		"Twitter/X: Handles (@username with 1-15 alphanumeric/underscore chars), profile URLs (twitter.com, x.com), mobile variants",
		"Facebook: Profile URLs (facebook.com/username, fb.com/username), numeric IDs (profile.php?id=), page formats - 5-50 character usernames",
		"GitHub: Username URLs (github.com/username), repository URLs (github.com/user/repo), GitHub Pages (user.github.io) - 1-39 character usernames",
		"Instagram: Profile URLs (instagram.com/username, instagr.am/username), handle references (@username) - 1-30 character usernames with dots/underscores",
		"YouTube: Channel URLs (youtube.com/@username, /c/channel, /user/username), handle formats - alphanumeric with hyphens/underscores",
		"TikTok: Handle formats (tiktok.com/@username), short URLs (tiktok.com/t/code) - alphanumeric usernames with dots/underscores",
		"Discord: Server invites (discord.gg/invite), user references (discord.com/users/userid) - alphanumeric invite codes and numeric user IDs",
		"Reddit: User profiles (reddit.com/u/username), subreddit references (reddit.com/r/subreddit) - alphanumeric usernames with underscores/hyphens",
		"Additional platforms: Snapchat, Pinterest, Twitch with platform-specific username validation rules",
	}

	// Set confidence factors with detailed platform-specific information
	info.ConfidenceFactors = []help.ConfidenceFactor{
		{
			Name:        "Platform Pattern Validation",
			Description: "Validates URL format and username rules for specific platforms (LinkedIn: 3-100 chars, Twitter: 1-15 chars, GitHub: 1-39 chars, Instagram: 1-30 chars)",
			Weight:      35,
		},
		{
			Name:        "Contextual Keywords",
			Description: "Analyzes surrounding text for social media and platform-specific terminology (profile, social media, follow me, connect with me)",
			Weight:      25,
		},
		{
			Name:        "Platform-Specific Context",
			Description: "Checks for platform-specific keywords (LinkedIn: professional/career, Twitter: tweet/follow, GitHub: repository/code, Instagram: photo/story)",
			Weight:      15,
		},
		{
			Name:        "False Positive Prevention",
			Description: "Excludes test data, examples, placeholder content, and documentation patterns using negative keyword filtering",
			Weight:      15,
		},
		{
			Name:        "Profile Clustering",
			Description: "Boosts confidence for related social media profiles found together (same user across platforms, fragmented references)",
			Weight:      10,
		},
	}

	// Set keywords
	info.PositiveKeywords = v.positiveKeywords
	info.NegativeKeywords = v.negativeKeywords

	// Set configuration information with comprehensive examples
	info.ConfigurationInfo = "Social media detection can be customized through ferret.yaml configuration.\n\n" +
		"IMPORTANT: The validator includes sensible defaults and will work without configuration.\n" +
		"Custom patterns allow for organization-specific social media detection needs.\n\n" +
		"Configuration file example with all supported platforms:\n" +
		"```\n" +
		"validators:\n" +
		"  social_media:\n" +
		"    # Platform-specific pattern groups (all optional)\n" +
		"    linkedin_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?linkedin\\.com/in/[a-zA-Z0-9_-]+\"  # Profile URLs\n" +
		"      - \"(?i)https?://(?:www\\.)?linkedin\\.com/company/[a-zA-Z0-9_-]+\"  # Company pages\n" +
		"      - \"(?i)https?://(?:www\\.)?linkedin\\.com/pub/[a-zA-Z0-9_/-]+\"  # Public profiles\n" +
		"    \n" +
		"    twitter_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?(twitter|x)\\.com/[a-zA-Z0-9_]+\"  # Profile URLs\n" +
		"      - \"(?i)@[a-zA-Z0-9_]{1,15}\\\\b\"  # Handles (1-15 chars)\n" +
		"    \n" +
		"    github_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?github\\.com/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)?\"  # User/repo URLs\n" +
		"      - \"(?i)https?://[a-zA-Z0-9_-]+\\.github\\.io\"  # GitHub Pages\n" +
		"    \n" +
		"    facebook_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?(facebook|fb)\\.com/[a-zA-Z0-9._-]+\"  # Profile URLs\n" +
		"      - \"(?i)https?://(?:www\\.)?facebook\\.com/profile\\.php\\\\?id=\\\\d+\"  # Numeric IDs\n" +
		"    \n" +
		"    instagram_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?instagram\\.com/[a-zA-Z0-9_.]+/\"  # Profile URLs\n" +
		"      - \"(?i)https?://(?:www\\.)?instagr\\.am/[a-zA-Z0-9_.]+/\"  # Short URLs\n" +
		"    \n" +
		"    youtube_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?youtube\\.com/(?:user|c|channel)/[a-zA-Z0-9_-]+\"  # Channel URLs\n" +
		"      - \"(?i)https?://(?:www\\.)?youtube\\.com/@[a-zA-Z0-9_-]+\"  # Handle format\n" +
		"    \n" +
		"    tiktok_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?tiktok\\.com/@[a-zA-Z0-9_.]+/\"  # Profile URLs\n" +
		"      - \"(?i)https?://(?:www\\.)?tiktok\\.com/t/[a-zA-Z0-9]+\"  # Short URLs\n" +
		"    \n" +
		"    discord_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?discord\\.gg/[a-zA-Z0-9]+\"  # Server invites\n" +
		"      - \"(?i)discord\\.com/users/\\\\d+\"  # User references\n" +
		"    \n" +
		"    reddit_patterns:\n" +
		"      - \"(?i)https?://(?:www\\.)?reddit\\.com/u(?:ser)?/[a-zA-Z0-9_-]+\"  # User profiles\n" +
		"      - \"(?i)https?://(?:www\\.)?reddit\\.com/r/[a-zA-Z0-9_]+\"  # Subreddits\n" +
		"    \n" +
		"    # Custom positive/negative keywords for contextual analysis\n" +
		"    positive_keywords:\n" +
		"      - \"profile\"\n" +
		"      - \"social media\"\n" +
		"      - \"follow me\"\n" +
		"      - \"connect with me\"\n" +
		"      - \"find me on\"\n" +
		"      - \"social network\"\n" +
		"    \n" +
		"    negative_keywords:\n" +
		"      - \"example\"\n" +
		"      - \"test\"\n" +
		"      - \"placeholder\"\n" +
		"      - \"demo\"\n" +
		"      - \"sample\"\n" +
		"      - \"tutorial\"\n" +
		"      - \"documentation\"\n" +
		"    \n" +
		"    # Platform-specific context keywords (boost confidence when found near matches)\n" +
		"    platform_keywords:\n" +
		"      linkedin:\n" +
		"        - \"professional\"\n" +
		"        - \"career\"\n" +
		"        - \"network\"\n" +
		"        - \"business\"\n" +
		"        - \"employment\"\n" +
		"      twitter:\n" +
		"        - \"tweet\"\n" +
		"        - \"follow\"\n" +
		"        - \"retweet\"\n" +
		"        - \"hashtag\"\n" +
		"        - \"mention\"\n" +
		"      github:\n" +
		"        - \"repository\"\n" +
		"        - \"code\"\n" +
		"        - \"project\"\n" +
		"        - \"commit\"\n" +
		"        - \"developer\"\n" +
		"      facebook:\n" +
		"        - \"post\"\n" +
		"        - \"share\"\n" +
		"        - \"like\"\n" +
		"        - \"friend\"\n" +
		"        - \"page\"\n" +
		"      instagram:\n" +
		"        - \"photo\"\n" +
		"        - \"story\"\n" +
		"        - \"reel\"\n" +
		"        - \"hashtag\"\n" +
		"        - \"filter\"\n" +
		"      youtube:\n" +
		"        - \"video\"\n" +
		"        - \"channel\"\n" +
		"        - \"subscribe\"\n" +
		"        - \"playlist\"\n" +
		"        - \"creator\"\n" +
		"      tiktok:\n" +
		"        - \"video\"\n" +
		"        - \"viral\"\n" +
		"        - \"trend\"\n" +
		"        - \"creator\"\n" +
		"        - \"content\"\n" +
		"    \n" +
		"    # Whitelist patterns to exclude known false positives (optional)\n" +
		"    whitelist_patterns:\n" +
		"      - \"(?i)example\\.com\"  # Exclude example domains\n" +
		"      - \"(?i)test.*social\"  # Exclude test social media references\n" +
		"```\n\n" +
		"Usage examples:\n" +
		"- Create a ferret.yaml file in your current directory\n" +
		"- Run ferret-scan with the --config flag: ferret-scan --config ferret.yaml --file document.txt\n" +
		"- Use a specific profile: ferret-scan --config ferret.yaml --profile social-media --file document.txt\n" +
		"- Enable only specific platforms by including only their pattern groups\n" +
		"- Disable platforms by omitting their pattern groups from the configuration\n\n" +
		"Platform-specific confidence factors:\n" +
		"- LinkedIn: High confidence for /in/, /company/, /pub/ URLs with valid usernames (3-100 chars)\n" +
		"- Twitter/X: High confidence for @handles (1-15 chars) and profile URLs\n" +
		"- GitHub: High confidence for user/repo URLs and .github.io domains (1-39 char usernames)\n" +
		"- Facebook: Medium-high confidence for profile URLs and numeric IDs (5-50 char usernames)\n" +
		"- Instagram: Medium-high confidence for profile URLs with valid usernames (1-30 chars)\n" +
		"- YouTube: Medium confidence for channel URLs and handle formats\n" +
		"- TikTok: Medium confidence for @handles and profile URLs\n" +
		"- Discord/Reddit: Medium confidence for server invites and user profiles\n\n" +
		"The validator automatically applies platform-specific validation rules and contextual analysis\n" +
		"to minimize false positives while maintaining high detection accuracy."

	// Set examples with comprehensive usage scenarios
	info.Examples = []string{
		"ferret-scan --file document.txt --checks SOCIAL_MEDIA",
		"ferret-scan --file document.txt --checks SOCIAL_MEDIA --confidence high",
		"ferret-scan --file resume.pdf --verbose --checks SOCIAL_MEDIA",
		"ferret-scan --file social-media-content.txt --checks SOCIAL_MEDIA --format json",
		"ferret-scan --config ferret.yaml --file document.txt --checks SOCIAL_MEDIA",
		"ferret-scan --config ferret.yaml --profile social-media --file document.txt",
		"ferret-scan --file documents/ --recursive --checks SOCIAL_MEDIA --debug",
		"ferret-scan --file presentation.pptx --checks SOCIAL_MEDIA --show-match",
		"ferret-scan --file marketing-materials/ --recursive --checks SOCIAL_MEDIA --format csv --output social-media-findings.csv",
		"ferret-scan --file employee-handbook.pdf --checks SOCIAL_MEDIA --confidence medium,high --verbose",
		"ferret-scan --file social-posts.txt --checks SOCIAL_MEDIA --enable-redaction --redaction-strategy simple",
		"ferret-scan --file company-docs/ --recursive --checks SOCIAL_MEDIA --suppression-file .social-media-suppressions.yaml",
	}

	return info
}
