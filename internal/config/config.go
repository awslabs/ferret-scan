// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/paths"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// SourcePath records WHICH file this config was loaded from, or "" for built-in
	// defaults.
	//
	// It exists so a run can say what governed it. FindConfigFile searches the CURRENT
	// WORKING DIRECTORY before the user config dir, so a config.yaml or
	// .ferret-scan.yaml sitting next to the scanned content wins — and can switch off
	// whole detection categories via validators.<name>.disabled_types. Measured: the
	// same binary, flags and input went from 1 finding to 0 because of a file dropped
	// beside the content, with nothing in the output naming it.
	//
	// That is a real trust boundary. THREAT_MODEL TB-7 already covers "an outside
	// contributor's PR run through a maintainer's pre-commit/CI", and TM-11 covers that
	// attacker driving confidence to zero through attacker-authored CONTENT; a config
	// file in the same PR reaches the same outcome more directly. Naming the config in
	// effect does not close that hole, but it makes the substitution visible instead of
	// silent, which is the difference between a reviewable event and an invisible one.
	//
	// yaml:"-" so a config file cannot set it and claim a different provenance than the
	// one it actually has. See #293.
	SourcePath string `yaml:"-" json:"-"`

	// Default settings
	Defaults struct {
		Format               string   `yaml:"format"`
		ConfidenceLevels     string   `yaml:"confidence_levels"`
		Checks               string   `yaml:"checks"`
		Verbose              bool     `yaml:"verbose"`
		Debug                bool     `yaml:"debug"`
		NoColor              bool     `yaml:"no_color"`
		Recursive            bool     `yaml:"recursive"`
		EnablePreprocessors  bool     `yaml:"enable_preprocessors"`
		ExcludePatterns      []string `yaml:"exclude_patterns"`
		RespectGitignore     bool     `yaml:"respect_gitignore"`
		ShowMatch            bool     `yaml:"show_match"`
		Quiet                bool     `yaml:"quiet"`
		ShowSuppressed       bool     `yaml:"show_suppressed"`
		GenerateSuppressions bool     `yaml:"generate_suppressions"`
		FailOnIncomplete     bool     `yaml:"fail_on_incomplete"`
	} `yaml:"defaults"`

	// Global validator configurations
	Validators map[string]map[string]interface{} `yaml:"validators"`

	// Preprocessor configurations
	Preprocessors struct {
		TextExtraction struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"text_extraction"`
	} `yaml:"preprocessors"`

	// Redaction configurations
	Redaction struct {
		Enabled   bool   `yaml:"enabled"`
		OutputDir string `yaml:"output_dir"`
		Strategy  string `yaml:"strategy"`
		// IndexFile is the JSON redaction log. `audit_log_file` is the name the
		// shipped config, the docs and the --redaction-audit-log flag all use,
		// so it is accepted as an alias; see resolveAuditLogAlias.
		IndexFile    string `yaml:"index_file"`
		AuditLogFile string `yaml:"audit_log_file"`
	} `yaml:"redaction"`

	// Suppression configurations. These are the config-file equivalents of
	// --suppression-file, --generate-suppressions and --show-suppressed.
	Suppressions struct {
		File           string `yaml:"file"`
		GenerateOnScan bool   `yaml:"generate_on_scan"`
		ShowSuppressed bool   `yaml:"show_suppressed"`
	} `yaml:"suppressions"`

	// Platform-specific configurations
	Platform *PlatformConfig `yaml:"platform,omitempty"`

	// Profiles for different scanning scenarios
	Profiles map[string]Profile `yaml:"profiles"`

	// UnknownKeys lists config keys the schema does not recognize. Populated by
	// LoadConfig so callers can warn; a typo'd option is otherwise invisible.
	// Not itself a config key.
	UnknownKeys []string `yaml:"-"`
}

// PlatformConfig holds platform-specific configuration settings
type PlatformConfig struct {
	// Windows-specific configuration
	Windows *WindowsConfig `yaml:"windows,omitempty"`
	// Unix-specific configuration (Linux, macOS, etc.)
	Unix *UnixConfig `yaml:"unix,omitempty"`
}

// WindowsConfig holds Windows-specific configuration settings.
//
// This block once also carried use_appdata, system_wide_install,
// create_shortcuts, add_to_path and long_path_support. Those describe an
// installer, not a scanner: nothing in this repo (including the install-system
// scripts) ever read them, so they were validated and then ignored. They are
// gone; the directory overrides below are the two that have a meaning here.
type WindowsConfig struct {
	ConfigDir string `yaml:"config_dir"` // Override default config directory
	TempDir   string `yaml:"temp_dir"`   // Override default temp directory
}

// UnixConfig holds Unix-specific configuration settings. See WindowsConfig for
// why use_xdg is no longer here.
type UnixConfig struct {
	ConfigDir string `yaml:"config_dir"` // Override default config directory
	TempDir   string `yaml:"temp_dir"`   // Override default temp directory
}

// ProfileRedaction holds a profile's redaction settings. It is a named type
// rather than an anonymous struct so that constructing a default profile does
// not require restating every field and tag verbatim at each site.
type ProfileRedaction struct {
	Enabled   bool   `yaml:"enabled"`
	OutputDir string `yaml:"output_dir"`
	Strategy  string `yaml:"strategy"`
	// IndexFile / AuditLogFile are the same slot under two names; see
	// resolveAuditLogAlias.
	IndexFile    string `yaml:"index_file"`
	AuditLogFile string `yaml:"audit_log_file"`
}

// Profile represents a scanning profile with specific settings
type Profile struct {
	Format               string                            `yaml:"format"`
	ConfidenceLevels     string                            `yaml:"confidence_levels"`
	Checks               string                            `yaml:"checks"`
	Verbose              bool                              `yaml:"verbose"`
	Debug                bool                              `yaml:"debug"`
	NoColor              bool                              `yaml:"no_color"`
	Recursive            bool                              `yaml:"recursive"`
	EnablePreprocessors  bool                              `yaml:"enable_preprocessors"`
	ExcludePatterns      []string                          `yaml:"exclude_patterns"`
	RespectGitignore     bool                              `yaml:"respect_gitignore"`
	ShowMatch            bool                              `yaml:"show_match"`
	Quiet                bool                              `yaml:"quiet"`
	ShowSuppressed       bool                              `yaml:"show_suppressed"`
	GenerateSuppressions bool                              `yaml:"generate_suppressions"`
	FailOnIncomplete     bool                              `yaml:"fail_on_incomplete"`
	Description          string                            `yaml:"description"`
	Validators           map[string]map[string]interface{} `yaml:"validators"`
	// Redaction settings for this profile
	Redaction ProfileRedaction `yaml:"redaction"`
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

	// Set default redaction values with platform-aware paths
	config.Redaction.Enabled = false
	config.Redaction.OutputDir = normalizePlatformPath("./redacted")
	config.Redaction.Strategy = "format_preserving"
	config.Redaction.IndexFile = ""

	// Set default suppression values
	config.Suppressions.File = ""
	config.Suppressions.GenerateOnScan = false
	config.Suppressions.ShowSuppressed = false

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
		Redaction: ProfileRedaction{
			Enabled:   false,
			OutputDir: normalizePlatformPath("./redacted"),
			Strategy:  "format_preserving",
			IndexFile: "",
		},
	}

	// If no config file specified, return default config. SourcePath stays empty,
	// which is what "built-in defaults" means to a caller inspecting it.
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

	// Parse the raw YAML into a generic tree ONCE for all field-presence checks
	// below (bool fields that unmarshal to false when omitted must be told apart
	// from an explicit false). Reused by containsField and backfillProfileBools
	// instead of each re-parsing the whole document.
	yamlTree := parseYAMLTree(data)

	// Restore defaults if not explicitly set in config file
	// This handles the case where YAML unmarshaling sets bool fields to false
	// when they're not present in the config file
	if !containsField(yamlTree, "defaults", "enable_preprocessors") {
		config.Defaults.EnablePreprocessors = defaultEnablePreprocessors
	}
	if !containsField(yamlTree, "preprocessors", "text_extraction", "enabled") {
		config.Preprocessors.TextExtraction.Enabled = defaultTextExtractionEnabled
	}

	// Backfill profile bool fields from defaults when the profile YAML omits
	// them. Without this, a profile that doesn't mention `verbose` would
	// unmarshal with Verbose=false and silently override defaults.verbose=true.
	// See backfillProfileBools for the list of fields this handles.
	backfillProfileBools(yamlTree, config)

	// Fold `audit_log_file` into the slot that actually drives the redaction log.
	resolveAuditLogAlias(config)

	// Apply platform-specific defaults and path normalization
	ApplyPlatformDefaults(config)

	// Collect (but do not fail on) keys the schema does not recognize, so a
	// typo'd option is visible instead of silently ignored.
	config.UnknownKeys = collectUnknownKeys(data)

	// Validate the configuration
	if err := ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Publish the platform block's temp directory so paths.GetTempDir honors it.
	// Without this the whole `platform:` block was validated and then ignored.
	//
	// This runs AFTER validation, and only on success: the override is
	// process-wide, so publishing it earlier would let a config that is about to
	// be rejected — for a bad path, possibly that very temp_dir — leave the
	// process pointing at a directory no accepted config ever named.
	paths.SetTempDirOverride(platformTempDirOverride(config))

	// Record the provenance only on the SUCCESS path, so SourcePath never names a file
	// whose contents were rejected. A caller reads this to report what governed the run.
	config.SourcePath = cleanPath

	return config, nil
}

// resolveAuditLogAlias folds redaction.audit_log_file into redaction.index_file.
//
// These are one feature with two names: the struct field has always been
// `index_file`, while the shipped config.yaml, every doc that mentions it, and
// the --redaction-audit-log flag all call it `audit_log_file`. The mismatch dates
// to the initial commit, so setting the documented name wrote to a field nothing
// read and produced no log and no error.
//
// index_file wins when both are set, because it is the name the loader has always
// honored — a user who set both is most likely mid-migration.
func resolveAuditLogAlias(config *Config) {
	if config.Redaction.IndexFile == "" {
		config.Redaction.IndexFile = config.Redaction.AuditLogFile
	}
	for name, profile := range config.Profiles {
		if profile.Redaction.IndexFile == "" && profile.Redaction.AuditLogFile != "" {
			profile.Redaction.IndexFile = profile.Redaction.AuditLogFile
			config.Profiles[name] = profile
		}
	}
}

// collectUnknownKeys reports config keys the schema does not recognize.
//
// The authoritative decode above is deliberately lenient: erroring on an unknown
// key would be a breaking change, and would reject this project's own shipped
// config.yaml. So this makes a second, strict pass purely to collect the key
// names and throws its result away. Callers surface these as warnings.
//
// Returns paths like "redaction.typo" in file order.
func collectUnknownKeys(data []byte) []string {
	var throwaway Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	err := dec.Decode(&throwaway)
	if err == nil {
		return nil
	}
	typeErr := &yaml.TypeError{}
	if !errors.As(err, &typeErr) {
		// A malformed document, not an unknown key. The lenient decode above
		// already succeeded, so there is nothing to report.
		return nil
	}

	var keys []string
	for _, msg := range typeErr.Errors {
		if name, ok := unknownFieldName(msg); ok {
			keys = append(keys, name)
		}
	}
	return keys
}

// unknownFieldName pulls the key name out of a yaml.v3 "field X not found"
// message. Anything else (a type mismatch, say) is not an unknown key and is
// reported as such so the caller can ignore it.
func unknownFieldName(msg string) (string, bool) {
	const marker = "field "
	i := strings.Index(msg, marker)
	if i < 0 {
		return "", false
	}
	rest := msg[i+len(marker):]
	j := strings.Index(rest, " not found in type")
	if j < 0 {
		return "", false
	}
	name := strings.TrimSpace(rest[:j])
	if name == "" {
		return "", false
	}
	return name, true
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
	// #nosec G703 -- filename is the operator-supplied --config / --suppression-file
	// path; no untrusted input reaches Stat.
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// sortedProfileNames returns the profile names in alphabetical order, for loops
// whose observable behavior depends on which profile is reached first (an error
// return, a log line) rather than on visiting all of them.
func sortedProfileNames(profiles map[string]Profile) []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ListProfiles returns the available profile names in alphabetical order.
//
// Sorted because this feeds `--list-profiles` directly: ranging the Profiles map
// printed the same config file's profiles in a different sequence on every
// invocation, which makes the listing impossible to diff and looks like the
// config changed when it did not.
func (c *Config) ListProfiles() []string {
	profiles := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		profiles = append(profiles, name)
	}
	sort.Strings(profiles)
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
		Redaction: ProfileRedaction{
			Enabled:   false,
			OutputDir: normalizePlatformPath("./redacted"),
			Strategy:  "format_preserving",
			IndexFile: "",
		},
	}
	return &defaultProfile
}

// parseYAMLTree unmarshals raw config bytes into a generic nested map ONCE, so
// the many field-presence checks below (containsField) can walk it in memory
// instead of re-parsing the whole (potentially 50KB+) document per lookup — the
// old containsField re-ran yaml.Unmarshal on every call, and backfillProfileBools
// calls it profiles×bool-fields times. Returns nil on parse error; callers treat
// a nil tree as "no field present" (identical to the old error path).
func parseYAMLTree(data []byte) map[string]interface{} {
	var tree map[string]interface{}
	if err := yaml.Unmarshal(data, &tree); err != nil {
		return nil
	}
	return tree
}

// containsField reports whether a nested field exists in the pre-parsed YAML
// tree (see parseYAMLTree). A nil tree yields false, matching the old
// re-parse-and-fail behavior.
func containsField(tree map[string]interface{}, path ...string) bool {
	current := tree
	for i, key := range path {
		if current == nil {
			return false
		}
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

// profileBoolField describes one bool field on a Profile that needs backfilling
// from defaults when the profile YAML omits it. The yamlPath is relative to a
// profile block (e.g. "verbose" or "redaction.enabled").
type profileBoolField struct {
	yamlPath     []string
	defaultValue func(*Config) bool
	setProfile   func(*Profile, bool)
}

// profileBoolFields is the registry of Profile bool fields whose "missing in
// YAML" must be distinguished from "explicit false". Adding a new profile
// bool? Register it here and backfillProfileBools picks it up automatically.
var profileBoolFields = []profileBoolField{
	{
		yamlPath:     []string{"verbose"},
		defaultValue: func(c *Config) bool { return c.Defaults.Verbose },
		setProfile:   func(p *Profile, v bool) { p.Verbose = v },
	},
	{
		yamlPath:     []string{"debug"},
		defaultValue: func(c *Config) bool { return c.Defaults.Debug },
		setProfile:   func(p *Profile, v bool) { p.Debug = v },
	},
	{
		yamlPath:     []string{"no_color"},
		defaultValue: func(c *Config) bool { return c.Defaults.NoColor },
		setProfile:   func(p *Profile, v bool) { p.NoColor = v },
	},
	{
		yamlPath:     []string{"recursive"},
		defaultValue: func(c *Config) bool { return c.Defaults.Recursive },
		setProfile:   func(p *Profile, v bool) { p.Recursive = v },
	},
	{
		yamlPath:     []string{"enable_preprocessors"},
		defaultValue: func(c *Config) bool { return c.Defaults.EnablePreprocessors },
		setProfile:   func(p *Profile, v bool) { p.EnablePreprocessors = v },
	},
	{
		yamlPath:     []string{"redaction", "enabled"},
		defaultValue: func(c *Config) bool { return c.Redaction.Enabled },
		setProfile:   func(p *Profile, v bool) { p.Redaction.Enabled = v },
	},
	{
		yamlPath:     []string{"respect_gitignore"},
		defaultValue: func(c *Config) bool { return c.Defaults.RespectGitignore },
		setProfile:   func(p *Profile, v bool) { p.RespectGitignore = v },
	},
	{
		yamlPath:     []string{"show_match"},
		defaultValue: func(c *Config) bool { return c.Defaults.ShowMatch },
		setProfile:   func(p *Profile, v bool) { p.ShowMatch = v },
	},
	{
		yamlPath:     []string{"quiet"},
		defaultValue: func(c *Config) bool { return c.Defaults.Quiet },
		setProfile:   func(p *Profile, v bool) { p.Quiet = v },
	},
	{
		yamlPath:     []string{"show_suppressed"},
		defaultValue: func(c *Config) bool { return c.Defaults.ShowSuppressed },
		setProfile:   func(p *Profile, v bool) { p.ShowSuppressed = v },
	},
	{
		yamlPath:     []string{"generate_suppressions"},
		defaultValue: func(c *Config) bool { return c.Defaults.GenerateSuppressions },
		setProfile:   func(p *Profile, v bool) { p.GenerateSuppressions = v },
	},
}

// backfillProfileBools walks every profile in the parsed config and, for each
// registered bool field that is NOT present in the raw YAML, copies the value
// from the corresponding Defaults field. This fixes the Go YAML unmarshaling
// gotcha where a missing bool unmarshals as false, silently overriding a
// truthy default when a profile is applied.
//
// Profiles that DO explicitly set a field (to either true or false) are left
// alone — their explicit value wins.
func backfillProfileBools(yamlTree map[string]interface{}, config *Config) {
	if config == nil || len(config.Profiles) == 0 {
		return
	}
	for name, profile := range config.Profiles {
		for _, f := range profileBoolFields {
			path := append([]string{"profiles", name}, f.yamlPath...)
			if containsField(yamlTree, path...) {
				// Profile explicitly set this field; keep its value.
				continue
			}
			// Profile omitted this field; fall back to defaults.
			f.setProfile(&profile, f.defaultValue(config))
		}
		config.Profiles[name] = profile
	}
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

// getDefaultPlatformConfig returns default platform-specific configuration.
//
// Both directory overrides default to empty, which means "use the platform's own
// location" (see paths.GetConfigDir / paths.GetTempDir). The struct is still
// populated for the current OS so that a config file setting only one of the two
// keys merges into a non-nil block.
func getDefaultPlatformConfig() *PlatformConfig {
	platformConfig := &PlatformConfig{}

	if runtime.GOOS == "windows" {
		platformConfig.Windows = &WindowsConfig{}
	} else {
		platformConfig.Unix = &UnixConfig{}
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

	// Validate profile-specific paths. Profiles are visited in name order
	// because this loop returns on the FIRST invalid path: ranging the map meant
	// a config with two bad profiles reported whichever one Go happened to visit
	// first, so an operator fixed it, re-ran, and got a fresh complaint about a
	// different profile with no indication the first fix had worked.
	for _, profileName := range sortedProfileNames(config.Profiles) {
		profile := config.Profiles[profileName]
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
	if dir := platformTempDirOverride(config); dir != "" {
		return dir
	}

	// Fall back to default platform-aware temp directory
	return paths.GetTempDir()
}

// platformTempDirOverride returns the config file's temp directory for the
// current OS, or "" when the platform block does not set one.
func platformTempDirOverride(config *Config) string {
	if config == nil || config.Platform == nil {
		return ""
	}
	if runtime.GOOS == "windows" {
		if config.Platform.Windows != nil && config.Platform.Windows.TempDir != "" {
			return normalizePlatformPath(config.Platform.Windows.TempDir)
		}
		return ""
	}
	if config.Platform.Unix != nil && config.Platform.Unix.TempDir != "" {
		return normalizePlatformPath(config.Platform.Unix.TempDir)
	}
	return ""
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
// when configFile is empty). If loading fails, it logs a warning to stderr and
// returns a default configuration so callers don't crash on a missing/malformed
// auto-discovered file.
//
// This helper is intended for the auto-discovery path (configFile == "") and
// for callers that explicitly want best-effort loading. When the user passes an
// explicit --config <path> flag, prefer LoadConfigStrict so YAML parse errors
// surface immediately instead of being silently swallowed.
func LoadConfigOrDefault(configFile string) *Config {
	configPath := configFile
	if configPath == "" {
		configPath = FindConfigFile()
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		// Surface the failure on stderr so users at least see *something* when
		// their config silently isn't applied. Previously this was swallowed
		// entirely, which made YAML escape gotchas (e.g. "\b" in double-quoted
		// strings) and missing-file typos invisible.
		if configPath != "" {
			fmt.Fprintf(os.Stderr,
				"Warning: failed to load config %q: %v — using built-in defaults.\n",
				configPath, err)
		}
		// Built-in defaults, and SourcePath is empty on this path, so a caller
		// reporting provenance says "built-in defaults" rather than naming a file
		// whose contents were never applied.
		cfg, _ = LoadConfig("")
	}
	return cfg
}

// LoadConfigStrict loads configuration from configFile and returns an error if
// the file does not exist, cannot be read, or fails to parse.
//
// This is a thin wrapper around LoadConfig that adds two contract guarantees
// relevant to operator-supplied paths:
//
//  1. An empty path is rejected outright (unlike LoadConfig, which silently
//     returns a default config when given ""). Callers that want
//     auto-discovery should explicitly use LoadConfigOrDefault — passing ""
//     to a function named "Strict" is almost certainly a bug.
//  2. Errors are wrapped with the file path so the operator sees what they
//     supplied in the error message (LoadConfig's errors don't include the
//     path the caller used).
//
// Use this when the caller has an operator-supplied path (e.g. --config <path>
// or web --config) and a silent fallback to defaults would hide a real bug.
// Both wrap-and-reject behaviors are exercised by callers in production
// (cmd/main.go, internal/web/server.go) so the wrapper pulls its weight.
func LoadConfigStrict(configFile string) (*Config, error) {
	if configFile == "" {
		return nil, fmt.Errorf("LoadConfigStrict requires an explicit config path; use LoadConfigOrDefault for auto-discovery")
	}
	cfg, err := LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config %q: %w", configFile, err)
	}
	// Enforce the typed schema on the strict (operator-supplied) path so a
	// typo'd enum value (format/strategy/checks/confidence_levels) is reported
	// instead of silently ignored. The lenient LoadConfig/LoadConfigOrDefault
	// path deliberately skips this to preserve best-effort auto-discovery
	// behavior (v2 gap 6.4; see schema.go).
	if err := ValidateSchema(cfg); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", configFile, err)
	}
	return cfg, nil
}
