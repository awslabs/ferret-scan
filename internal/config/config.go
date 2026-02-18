// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"ferret-scan/internal/paths"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Default settings
	Defaults struct {
		Format              string   `yaml:"format"`
		ConfidenceLevels    string   `yaml:"confidence_levels"`
		Checks              string   `yaml:"checks"`
		Verbose             bool     `yaml:"verbose"`
		Debug               bool     `yaml:"debug"`
		NoColor             bool     `yaml:"no_color"`
		Recursive           bool     `yaml:"recursive"`
		EnablePreprocessors bool     `yaml:"enable_preprocessors"`
		ExcludePatterns     []string `yaml:"exclude_patterns"`
	} `yaml:"defaults"`

	// Global validator configurations
	Validators map[string]map[string]interface{} `yaml:"validators"`

	// Preprocessor configurations
	Preprocessors struct {
		TextExtraction struct {
			Enabled bool     `yaml:"enabled"`
			Types   []string `yaml:"types"`
		} `yaml:"text_extraction"`
		// GENAI_DISABLED: Textract configuration struct for AWS Textract OCR service
		// Textract struct {
		// 	Enabled bool   `yaml:"enabled"`
		// 	Region  string `yaml:"region"`
		// } `yaml:"textract"`
	} `yaml:"preprocessors"`

	// Redaction configurations
	Redaction struct {
		Enabled     bool   `yaml:"enabled"`
		OutputDir   string `yaml:"output_dir"`
		Strategy    string `yaml:"strategy"`
		IndexFile   string `yaml:"index_file"`
		MemoryScrub bool   `yaml:"memory_scrub"`
		AuditTrail  bool   `yaml:"audit_trail"`
		Strategies  struct {
			Simple struct {
				Replacement string `yaml:"replacement"`
			} `yaml:"simple"`
			FormatPreserving struct {
				PreserveLength bool `yaml:"preserve_length"`
				PreserveFormat bool `yaml:"preserve_format"`
			} `yaml:"format_preserving"`
			Synthetic struct {
				Secure bool `yaml:"secure"`
			} `yaml:"synthetic"`
		} `yaml:"strategies"`
	} `yaml:"redaction"`

	// Platform-specific configurations
	Platform *PlatformConfig `yaml:"platform,omitempty"`

	// Profiles for different scanning scenarios
	Profiles map[string]Profile `yaml:"profiles"`
}

// PlatformConfig holds platform-specific configuration settings
type PlatformConfig struct {
	// Windows-specific configuration
	Windows *WindowsConfig `yaml:"windows,omitempty"`
	// Unix-specific configuration (Linux, macOS, etc.)
	Unix *UnixConfig `yaml:"unix,omitempty"`
}

// WindowsConfig holds Windows-specific configuration settings
type WindowsConfig struct {
	UseAppData        bool   `yaml:"use_appdata"`         // Use APPDATA directory for configuration
	SystemWideInstall bool   `yaml:"system_wide_install"` // Install system-wide vs user-specific
	CreateShortcuts   bool   `yaml:"create_shortcuts"`    // Create desktop/start menu shortcuts
	AddToPath         bool   `yaml:"add_to_path"`         // Add to PATH environment variable
	ConfigDir         string `yaml:"config_dir"`          // Override default config directory
	TempDir           string `yaml:"temp_dir"`            // Override default temp directory
	LongPathSupport   bool   `yaml:"long_path_support"`   // Enable long path support (>260 chars)
}

// UnixConfig holds Unix-specific configuration settings
type UnixConfig struct {
	UseXDG    bool   `yaml:"use_xdg"`    // Use XDG Base Directory specification
	ConfigDir string `yaml:"config_dir"` // Override default config directory
	TempDir   string `yaml:"temp_dir"`   // Override default temp directory
}

// Profile represents a scanning profile with specific settings
type Profile struct {
	Format              string   `yaml:"format"`
	ConfidenceLevels    string   `yaml:"confidence_levels"`
	Checks              string   `yaml:"checks"`
	Verbose             bool     `yaml:"verbose"`
	Debug               bool     `yaml:"debug"`
	NoColor             bool     `yaml:"no_color"`
	Recursive           bool     `yaml:"recursive"`
	EnablePreprocessors bool     `yaml:"enable_preprocessors"`
	ExcludePatterns     []string `yaml:"exclude_patterns"`
	// GENAI_DISABLED: GenAI enablement flag for profiles
	// EnableGenAI         bool                              `yaml:"enable_genai"`
	// GENAI_DISABLED: Cost estimation only mode flag
	// EstimateOnly        bool                              `yaml:"estimate_only"`
	Description string                            `yaml:"description"`
	Validators  map[string]map[string]interface{} `yaml:"validators"`
	// Redaction settings for this profile
	Redaction struct {
		Enabled   bool   `yaml:"enabled"`
		OutputDir string `yaml:"output_dir"`
		Strategy  string `yaml:"strategy"`
		IndexFile string `yaml:"index_file"`
	} `yaml:"redaction"`
	// Platform-specific settings for this profile
	Platform *PlatformConfig `yaml:"platform,omitempty"`
}

// LoadConfig loads configuration from the specified file path
func LoadConfig(configPath string) (*Config, error) {
	// Default configuration
	config := &Config{
		Profiles:   make(map[string]Profile),
		Validators: make(map[string]map[string]interface{}),
	}

	// Set default values
	config.Defaults.Format = "text"
	config.Defaults.ConfidenceLevels = "all"
	config.Defaults.Checks = "all"
	config.Defaults.Verbose = false
	config.Defaults.Debug = false
	config.Defaults.NoColor = false
	config.Defaults.Recursive = false
	config.Defaults.EnablePreprocessors = true

	// Set default preprocessor values
	config.Preprocessors.TextExtraction.Enabled = true
	config.Preprocessors.TextExtraction.Types = []string{"pdf", "office"}
	// GENAI_DISABLED: Textract default configuration values
	// config.Preprocessors.Textract.Enabled = false // Disabled by default, requires --enable-genai
	// config.Preprocessors.Textract.Region = "us-east-1"

	// Set default redaction values with platform-aware paths
	config.Redaction.Enabled = false
	config.Redaction.OutputDir = normalizePlatformPath("./redacted")
	config.Redaction.Strategy = "format_preserving"
	config.Redaction.IndexFile = ""
	config.Redaction.MemoryScrub = true
	config.Redaction.AuditTrail = true
	config.Redaction.Strategies.Simple.Replacement = "[HIDDEN]"
	config.Redaction.Strategies.FormatPreserving.PreserveLength = true
	config.Redaction.Strategies.FormatPreserving.PreserveFormat = true
	config.Redaction.Strategies.Synthetic.Secure = true

	// Set platform-specific defaults
	config.Platform = getDefaultPlatformConfig()

	// Add default pre-commit profile with platform-aware paths
	config.Profiles["precommit"] = Profile{
		Format:              "text",
		ConfidenceLevels:    "high,medium",
		Checks:              "CREDIT_CARD,SECRETS,SSN,EMAIL,PHONE,IP_ADDRESS",
		Verbose:             false,
		Debug:               false,
		NoColor:             true,
		Recursive:           false,
		EnablePreprocessors: true,
		Description:         "Optimized for pre-commit hooks with concise output and essential checks",
		Validators:          make(map[string]map[string]interface{}),
		Redaction: struct {
			Enabled   bool   `yaml:"enabled"`
			OutputDir string `yaml:"output_dir"`
			Strategy  string `yaml:"strategy"`
			IndexFile string `yaml:"index_file"`
		}{
			Enabled:   false,
			OutputDir: normalizePlatformPath("./redacted"),
			Strategy:  "format_preserving",
			IndexFile: "",
		},
	}

	// If no config file specified, return default config
	if configPath == "" {
		return config, nil
	}

	// Read config file
	cleanPath := filepath.Clean(configPath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Store default values before unmarshaling
	defaultEnablePreprocessors := config.Defaults.EnablePreprocessors
	defaultTextExtractionEnabled := config.Preprocessors.TextExtraction.Enabled

	// Parse YAML
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	// Restore defaults if not explicitly set in config file
	// This handles the case where YAML unmarshaling sets bool fields to false
	// when they're not present in the config file
	if !containsField(data, "defaults", "enable_preprocessors") {
		config.Defaults.EnablePreprocessors = defaultEnablePreprocessors
	}
	if !containsField(data, "preprocessors", "text_extraction", "enabled") {
		config.Preprocessors.TextExtraction.Enabled = defaultTextExtractionEnabled
	}

	// Apply platform-specific defaults and path normalization
	ApplyPlatformDefaults(config)

	// Validate the configuration
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// FindConfigFile looks for a configuration file in standard locations using platform-aware paths
func FindConfigFile() string {
	// Check current directory first - prioritize config.yaml
	if fileExists("config.yaml") {
		return "config.yaml"
	}
	if fileExists("ferret.yaml") {
		return "ferret.yaml"
	}
	if fileExists("ferret.yml") {
		return "ferret.yml"
	}

	// Check for .ferret-scan.yaml in current directory (project-specific config)
	if fileExists(".ferret-scan.yaml") {
		return ".ferret-scan.yaml"
	}
	if fileExists(".ferret-scan.yml") {
		return ".ferret-scan.yml"
	}

	// Check standard location using platform-aware paths
	standardConfig := paths.GetConfigFile()
	if fileExists(standardConfig) {
		return standardConfig
	}

	// Check platform-specific locations
	if runtime.GOOS == "windows" {
		return findWindowsConfigFile()
	}
	return findUnixConfigFile()
}

// findWindowsConfigFile looks for configuration files in Windows-specific locations
func findWindowsConfigFile() string {
	// Check Windows environment variables for config override
	if configDir := resolveWindowsEnvVar("FERRET_CONFIG_DIR"); configDir != "" {
		configFile := filepath.Join(configDir, "config.yaml")
		if fileExists(configFile) {
			return configFile
		}
	}

	// Check APPDATA directory (recommended Windows location)
	if appData := resolveWindowsEnvVar("APPDATA"); appData != "" {
		configFile := filepath.Join(appData, "ferret-scan", "config.yaml")
		if fileExists(configFile) {
			return configFile
		}
		configFile = filepath.Join(appData, "ferret-scan", "config.yml")
		if fileExists(configFile) {
			return configFile
		}
	}

	// Check USERPROFILE directory (fallback)
	if userProfile := resolveWindowsEnvVar("USERPROFILE"); userProfile != "" {
		configFile := filepath.Join(userProfile, ".ferret-scan", "config.yaml")
		if fileExists(configFile) {
			return configFile
		}
		configFile = filepath.Join(userProfile, ".ferret-scan", "config.yml")
		if fileExists(configFile) {
			return configFile
		}

		// Check legacy locations in user profile
		homeConfig := filepath.Join(userProfile, ".ferret.yaml")
		if fileExists(homeConfig) {
			return homeConfig
		}
		homeConfig = filepath.Join(userProfile, ".ferret.yml")
		if fileExists(homeConfig) {
			return homeConfig
		}
	}

	// Check system-wide configuration (PROGRAMDATA)
	if programData := resolveWindowsEnvVar("PROGRAMDATA"); programData != "" {
		configFile := filepath.Join(programData, "ferret-scan", "config.yaml")
		if fileExists(configFile) {
			return configFile
		}
		configFile = filepath.Join(programData, "ferret-scan", "config.yml")
		if fileExists(configFile) {
			return configFile
		}
	}

	return ""
}

// findUnixConfigFile looks for configuration files in Unix-specific locations
func findUnixConfigFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	// Check legacy locations in home directory
	homeConfig := filepath.Join(home, ".ferret.yaml")
	if fileExists(homeConfig) {
		return homeConfig
	}
	homeConfig = filepath.Join(home, ".ferret.yml")
	if fileExists(homeConfig) {
		return homeConfig
	}

	// Check XDG config directory
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}
	xdgConfigFile := filepath.Join(xdgConfig, "ferret-scan", "config.yaml")
	if fileExists(xdgConfigFile) {
		return xdgConfigFile
	}
	xdgConfigFile = filepath.Join(xdgConfig, "ferret-scan", "config.yml")
	if fileExists(xdgConfigFile) {
		return xdgConfigFile
	}

	return ""
}

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// ListProfiles returns a list of available profile names
func (c *Config) ListProfiles() []string {
	profiles := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		profiles = append(profiles, name)
	}
	return profiles
}

// GetProfile returns a profile by name, or nil if not found
func (c *Config) GetProfile(name string) *Profile {
	if profile, exists := c.Profiles[name]; exists {
		return &profile
	}
	return nil
}

// GetPrecommitProfile returns the pre-commit profile, creating a default one if it doesn't exist
func (c *Config) GetPrecommitProfile() *Profile {
	if profile := c.GetProfile("precommit"); profile != nil {
		return profile
	}

	// Return default pre-commit profile if not found in config
	defaultProfile := Profile{
		Format:              "text",
		ConfidenceLevels:    "high,medium",
		Checks:              "CREDIT_CARD,SECRETS,SSN,EMAIL,PHONE,IP_ADDRESS",
		Verbose:             false,
		Debug:               false,
		NoColor:             true,
		Recursive:           false,
		EnablePreprocessors: true,
		Description:         "Optimized for pre-commit hooks with concise output and essential checks",
		Validators:          make(map[string]map[string]interface{}),
		Redaction: struct {
			Enabled   bool   `yaml:"enabled"`
			OutputDir string `yaml:"output_dir"`
			Strategy  string `yaml:"strategy"`
			IndexFile string `yaml:"index_file"`
		}{
			Enabled:   false,
			OutputDir: normalizePlatformPath("./redacted"),
			Strategy:  "format_preserving",
			IndexFile: "",
		},
	}
	return &defaultProfile
}

// containsField checks if a nested field exists in the YAML data
func containsField(data []byte, path ...string) bool {
	var yamlData map[string]interface{}
	err := yaml.Unmarshal(data, &yamlData)
	if err != nil {
		return false
	}

	current := yamlData
	for i, key := range path {
		if i == len(path)-1 {
			// Last key - check if it exists
			_, exists := current[key]
			return exists
		}
		// Intermediate key - navigate deeper
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return false
		}
	}
	return false
}

// resolveWindowsEnvVar resolves Windows environment variables with proper expansion
func resolveWindowsEnvVar(varName string) string {
	value := os.Getenv(varName)
	if value == "" {
		return ""
	}

	// Expand any embedded environment variables (e.g., %USERPROFILE%\AppData)
	// This handles cases where environment variables reference other variables
	expanded := os.ExpandEnv(value)

	// Normalize the path for Windows
	return normalizePlatformPath(expanded)
}

// normalizePlatformPath normalizes a path for the current platform
func normalizePlatformPath(path string) string {
	if path == "" {
		return ""
	}

	// Use the platform-aware path normalization
	return paths.NormalizePath(path)
}

// getDefaultPlatformConfig returns default platform-specific configuration
func getDefaultPlatformConfig() *PlatformConfig {
	platformConfig := &PlatformConfig{}

	if runtime.GOOS == "windows" {
		platformConfig.Windows = &WindowsConfig{
			UseAppData:        true,  // Use APPDATA by default on Windows
			SystemWideInstall: false, // User-specific install by default
			CreateShortcuts:   false, // Don't create shortcuts by default
			AddToPath:         false, // Don't modify PATH by default
			LongPathSupport:   false, // Disabled by default for compatibility
		}
	} else {
		platformConfig.Unix = &UnixConfig{
			UseXDG: true, // Use XDG Base Directory specification by default
		}
	}

	return platformConfig
}

// ValidateConfig validates the configuration for platform-specific requirements
func ValidateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate platform-specific settings
	if config.Platform != nil {
		if err := validatePlatformConfig(config.Platform); err != nil {
			return fmt.Errorf("platform configuration validation failed: %w", err)
		}
	}

	// Validate paths in configuration
	if err := validateConfigPaths(config); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	return nil
}

// validatePlatformConfig validates platform-specific configuration settings
func validatePlatformConfig(platformConfig *PlatformConfig) error {
	if runtime.GOOS == "windows" && platformConfig.Windows != nil {
		return validateWindowsConfig(platformConfig.Windows)
	}

	if runtime.GOOS != "windows" && platformConfig.Unix != nil {
		return validateUnixConfig(platformConfig.Unix)
	}

	return nil
}

// validateWindowsConfig validates Windows-specific configuration
func validateWindowsConfig(windowsConfig *WindowsConfig) error {
	// Validate custom config directory if specified
	if windowsConfig.ConfigDir != "" {
		if err := paths.ValidatePath(windowsConfig.ConfigDir); err != nil {
			return fmt.Errorf("invalid Windows config directory: %w", err)
		}
	}

	// Validate custom temp directory if specified
	if windowsConfig.TempDir != "" {
		if err := paths.ValidatePath(windowsConfig.TempDir); err != nil {
			return fmt.Errorf("invalid Windows temp directory: %w", err)
		}
	}

	return nil
}

// validateUnixConfig validates Unix-specific configuration
func validateUnixConfig(unixConfig *UnixConfig) error {
	// Validate custom config directory if specified
	if unixConfig.ConfigDir != "" {
		if err := paths.ValidatePath(unixConfig.ConfigDir); err != nil {
			return fmt.Errorf("invalid Unix config directory: %w", err)
		}
	}

	// Validate custom temp directory if specified
	if unixConfig.TempDir != "" {
		if err := paths.ValidatePath(unixConfig.TempDir); err != nil {
			return fmt.Errorf("invalid Unix temp directory: %w", err)
		}
	}

	return nil
}

// validateConfigPaths validates all paths in the configuration
func validateConfigPaths(config *Config) error {
	// Validate redaction output directory
	if config.Redaction.OutputDir != "" {
		if err := paths.ValidatePath(config.Redaction.OutputDir); err != nil {
			return fmt.Errorf("invalid redaction output directory: %w", err)
		}
	}

	// Validate redaction index file path
	if config.Redaction.IndexFile != "" {
		if err := paths.ValidatePath(config.Redaction.IndexFile); err != nil {
			return fmt.Errorf("invalid redaction index file path: %w", err)
		}
	}

	// Validate profile-specific paths
	for profileName, profile := range config.Profiles {
		if profile.Redaction.OutputDir != "" {
			if err := paths.ValidatePath(profile.Redaction.OutputDir); err != nil {
				return fmt.Errorf("invalid redaction output directory in profile '%s': %w", profileName, err)
			}
		}
		if profile.Redaction.IndexFile != "" {
			if err := paths.ValidatePath(profile.Redaction.IndexFile); err != nil {
				return fmt.Errorf("invalid redaction index file path in profile '%s': %w", profileName, err)
			}
		}
	}

	return nil
}

// GetEffectiveConfigDir returns the effective configuration directory based on platform and config
func GetEffectiveConfigDir(config *Config) string {
	// Check for platform-specific override
	if config.Platform != nil {
		if runtime.GOOS == "windows" && config.Platform.Windows != nil && config.Platform.Windows.ConfigDir != "" {
			return normalizePlatformPath(config.Platform.Windows.ConfigDir)
		}
		if runtime.GOOS != "windows" && config.Platform.Unix != nil && config.Platform.Unix.ConfigDir != "" {
			return normalizePlatformPath(config.Platform.Unix.ConfigDir)
		}
	}

	// Fall back to default platform-aware config directory
	return paths.GetConfigDir()
}

// GetEffectiveTempDir returns the effective temporary directory based on platform and config
func GetEffectiveTempDir(config *Config) string {
	// Check for platform-specific override
	if config.Platform != nil {
		if runtime.GOOS == "windows" && config.Platform.Windows != nil && config.Platform.Windows.TempDir != "" {
			return normalizePlatformPath(config.Platform.Windows.TempDir)
		}
		if runtime.GOOS != "windows" && config.Platform.Unix != nil && config.Platform.Unix.TempDir != "" {
			return normalizePlatformPath(config.Platform.Unix.TempDir)
		}
	}

	// Fall back to default platform-aware temp directory
	return paths.GetTempDir()
}

// ApplyPlatformDefaults applies platform-specific defaults to paths in the configuration
func ApplyPlatformDefaults(config *Config) {
	if config == nil {
		return
	}

	// Normalize redaction output directory
	if config.Redaction.OutputDir != "" {
		config.Redaction.OutputDir = normalizePlatformPath(config.Redaction.OutputDir)
	}

	// Normalize redaction index file path
	if config.Redaction.IndexFile != "" {
		config.Redaction.IndexFile = normalizePlatformPath(config.Redaction.IndexFile)
	}

	// Apply platform defaults to profiles
	for profileName, profile := range config.Profiles {
		if profile.Redaction.OutputDir != "" {
			profile.Redaction.OutputDir = normalizePlatformPath(profile.Redaction.OutputDir)
		}
		if profile.Redaction.IndexFile != "" {
			profile.Redaction.IndexFile = normalizePlatformPath(profile.Redaction.IndexFile)
		}
		config.Profiles[profileName] = profile
	}
}

// LoadConfigOrDefault loads configuration from configFile (or searches standard locations
// when configFile is empty). If loading fails, it returns a default configuration.
// This is the shared helper used by both the CLI and the web server.
func LoadConfigOrDefault(configFile string) *Config {
	configPath := configFile
	if configPath == "" {
		configPath = FindConfigFile()
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		// Fall back to defaults — callers should not crash on a missing/bad config file.
		cfg, _ = LoadConfig("")
	}
	return cfg
}
