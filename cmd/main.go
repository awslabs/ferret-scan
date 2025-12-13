// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	// GENAI_DISABLED: AWS SDK imports for credential validation
	// awsconfig "github.com/aws/aws-sdk-go-v2/config"
	// "github.com/aws/aws-sdk-go-v2/service/sts"

	"ferret-scan/internal/config"
	"ferret-scan/internal/core"
	"ferret-scan/internal/precommit"
	"ferret-scan/internal/version"
	"ferret-scan/internal/web"

	// GENAI_DISABLED: Cost estimation for GenAI services
	// "ferret-scan/internal/cost"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/help"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
	"ferret-scan/internal/redactors/image"
	"ferret-scan/internal/redactors/office"
	"ferret-scan/internal/redactors/pdf"
	"ferret-scan/internal/redactors/plaintext"
	"ferret-scan/internal/validators"

	"ferret-scan/internal/formatters"
	_ "ferret-scan/internal/formatters/csv"
	_ "ferret-scan/internal/formatters/gitlab-sast"
	_ "ferret-scan/internal/formatters/json"
	_ "ferret-scan/internal/formatters/junit"
	_ "ferret-scan/internal/formatters/sarif"
	_ "ferret-scan/internal/formatters/text"
	_ "ferret-scan/internal/formatters/yaml"
	"ferret-scan/internal/parallel"

	"golang.org/x/term"

	"ferret-scan/internal/router"
	"ferret-scan/internal/suppressions"
	"ferret-scan/internal/validators/creditcard"
	"ferret-scan/internal/validators/email"
	"ferret-scan/internal/validators/intellectualproperty"
	"ferret-scan/internal/validators/ipaddress"
	"ferret-scan/internal/validators/metadata"
	"ferret-scan/internal/validators/passport"
	"ferret-scan/internal/validators/personname"
	"ferret-scan/internal/validators/phone"
	"ferret-scan/internal/validators/secrets"
	"ferret-scan/internal/validators/socialmedia"
	"ferret-scan/internal/validators/ssn"
	// GENAI_DISABLED: Comprehend validator import
	// "ferret-scan/internal/validators/comprehend"
)

// loadConfiguration loads the configuration file or returns default config
func loadConfiguration(configFile string) *config.Config {
	// If config file is not specified, try to find one in standard locations
	configPath := configFile
	if configPath == "" {
		configPath = config.FindConfigFile()
	}

	// Load configuration (will use defaults if file not found)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Error loading config file: %v\n", err)
		fmt.Fprintf(os.Stderr, "Using default configuration\n")
		cfg, _ = config.LoadConfig("") // Load default config
	}
	return cfg
}

// configFlags holds command line flag values
type configFlags struct {
	outputFormat        string
	confidenceLevels    string
	checksToRun         string
	verbose             bool
	debug               bool
	noColor             bool
	recursive           bool
	enablePreprocessors bool
	preprocessOnly      bool
	precommitMode       bool
	// GENAI_DISABLED: GenAI-related configuration flags
	// enableGenAI         bool
	// genaiServices       string
	// textractRegion      string
	// estimateOnly        bool
	// Redaction flags
	enableRedaction    bool
	redactionOutputDir string
	redactionStrategy  string
	redactionAuditLog  string
}

// finalConfiguration holds resolved configuration values
type finalConfiguration struct {
	format              string
	confidenceLevels    string
	checksToRun         string
	verbose             bool
	debug               bool
	noColor             bool
	recursive           bool
	enablePreprocessors bool
	preprocessOnly      bool
	precommitMode       bool
	// GENAI_DISABLED: GenAI-related configuration values
	// enableGenAI         bool
	// genaiServices       map[string]bool
	// textractRegion      string
	// estimateOnly        bool
	// Redaction configuration
	enableRedaction    bool
	redactionOutputDir string
	redactionStrategy  string
	redactionAuditLog  string
}

// resolveConfiguration resolves final configuration values from config file, profile, and command line flags
func resolveConfiguration(cfg *config.Config, activeProfile *config.Profile, flags *configFlags) *finalConfiguration {
	final := &finalConfiguration{}

	// Format
	final.format = "text" // default fallback
	if cfg != nil && cfg.Defaults.Format != "" {
		final.format = cfg.Defaults.Format
	}
	if activeProfile != nil && activeProfile.Format != "" {
		final.format = activeProfile.Format
	}
	if isFlagSet("format") && flags.outputFormat != "" {
		final.format = flags.outputFormat
	}

	// Confidence levels
	final.confidenceLevels = "all" // default fallback
	if cfg != nil && cfg.Defaults.ConfidenceLevels != "" {
		final.confidenceLevels = cfg.Defaults.ConfidenceLevels
	}
	if activeProfile != nil && activeProfile.ConfidenceLevels != "" {
		final.confidenceLevels = activeProfile.ConfidenceLevels
	}
	if isFlagSet("confidence") && flags.confidenceLevels != "" {
		final.confidenceLevels = flags.confidenceLevels
	}

	// Checks to run
	final.checksToRun = "all" // default fallback
	if cfg != nil && cfg.Defaults.Checks != "" {
		final.checksToRun = cfg.Defaults.Checks
	}
	if activeProfile != nil && activeProfile.Checks != "" {
		final.checksToRun = activeProfile.Checks
	}
	if isFlagSet("checks") && flags.checksToRun != "" {
		final.checksToRun = flags.checksToRun
	}

	// Verbose
	final.verbose = false // default fallback
	if cfg != nil {
		final.verbose = cfg.Defaults.Verbose
	}
	if activeProfile != nil {
		final.verbose = activeProfile.Verbose
	}
	if isFlagSet("verbose") {
		final.verbose = flags.verbose
	}

	// Debug
	final.debug = false // default fallback
	if cfg != nil {
		final.debug = cfg.Defaults.Debug
	}
	if activeProfile != nil {
		final.debug = activeProfile.Debug
	}
	if isFlagSet("debug") {
		final.debug = flags.debug
	}

	// No color
	final.noColor = false // default fallback
	if cfg != nil {
		final.noColor = cfg.Defaults.NoColor
	}
	if activeProfile != nil {
		final.noColor = activeProfile.NoColor
	}
	if isFlagSet("no-color") {
		final.noColor = flags.noColor
	}

	// Recursive
	final.recursive = false // default fallback
	if cfg != nil {
		final.recursive = cfg.Defaults.Recursive
	}
	if activeProfile != nil {
		final.recursive = activeProfile.Recursive
	}
	if isFlagSet("recursive") {
		final.recursive = flags.recursive
	}

	// Enable preprocessors
	final.enablePreprocessors = true // default fallback
	if cfg != nil {
		final.enablePreprocessors = cfg.Defaults.EnablePreprocessors
	}
	if activeProfile != nil {
		final.enablePreprocessors = activeProfile.EnablePreprocessors
	}
	if isFlagSet("enable-preprocessors") {
		final.enablePreprocessors = flags.enablePreprocessors
	}

	// Preprocess only
	final.preprocessOnly = false // default fallback
	if isFlagSet("preprocess-only") || isFlagSet("p") {
		final.preprocessOnly = flags.preprocessOnly
	}

	// Pre-commit mode
	final.precommitMode = false // default fallback
	if isFlagSet("pre-commit-mode") {
		final.precommitMode = flags.precommitMode
	}

	// GENAI_DISABLED: GenAI (Textract) configuration resolution
	// final.enableGenAI = false // default fallback
	// if cfg != nil && cfg.Preprocessors.Textract.Enabled {
	// 	final.enableGenAI = cfg.Preprocessors.Textract.Enabled
	// }
	// if activeProfile != nil {
	// 	final.enableGenAI = activeProfile.EnableGenAI
	// }
	// if isFlagSet("enable-genai") {
	// 	final.enableGenAI = flags.enableGenAI
	// }

	// GENAI_DISABLED: GenAI Services parsing
	// final.genaiServices = parseGenAIServices(flags.genaiServices, final.enableGenAI)

	// GENAI_DISABLED: Textract region configuration
	// final.textractRegion = "us-east-1" // default fallback
	// if cfg != nil && cfg.Preprocessors.Textract.Region != "" {
	// 	final.textractRegion = cfg.Preprocessors.Textract.Region
	// }
	// if isFlagSet("textract-region") {
	// 	final.textractRegion = flags.textractRegion
	// }

	// GENAI_DISABLED: Estimate only configuration
	// final.estimateOnly = false // default fallback
	// if activeProfile != nil {
	// 	final.estimateOnly = activeProfile.EstimateOnly
	// }
	// if isFlagSet("estimate-only") {
	// 	final.estimateOnly = flags.estimateOnly
	// }

	// Redaction configuration
	final.enableRedaction = false // default fallback
	if cfg != nil {
		final.enableRedaction = cfg.Redaction.Enabled
	}
	if activeProfile != nil {
		final.enableRedaction = activeProfile.Redaction.Enabled
	}
	if isFlagSet("enable-redaction") {
		final.enableRedaction = flags.enableRedaction
	}

	final.redactionOutputDir = "./redacted" // default fallback
	if cfg != nil && cfg.Redaction.OutputDir != "" {
		final.redactionOutputDir = cfg.Redaction.OutputDir
	}
	if activeProfile != nil && activeProfile.Redaction.OutputDir != "" {
		final.redactionOutputDir = activeProfile.Redaction.OutputDir
	}
	if isFlagSet("redaction-output-dir") && flags.redactionOutputDir != "" {
		final.redactionOutputDir = flags.redactionOutputDir
	}

	final.redactionStrategy = "format_preserving" // default fallback
	if cfg != nil && cfg.Redaction.Strategy != "" {
		final.redactionStrategy = cfg.Redaction.Strategy
	}
	if activeProfile != nil && activeProfile.Redaction.Strategy != "" {
		final.redactionStrategy = activeProfile.Redaction.Strategy
	}
	if isFlagSet("redaction-strategy") && flags.redactionStrategy != "" {
		final.redactionStrategy = flags.redactionStrategy
	}

	final.redactionAuditLog = "" // default fallback (no audit log file)
	if cfg != nil && cfg.Redaction.IndexFile != "" {
		final.redactionAuditLog = cfg.Redaction.IndexFile
	}
	if activeProfile != nil && activeProfile.Redaction.IndexFile != "" {
		final.redactionAuditLog = activeProfile.Redaction.IndexFile
	}
	if isFlagSet("redaction-audit-log") && flags.redactionAuditLog != "" {
		final.redactionAuditLog = flags.redactionAuditLog
	}

	return final
}

// processPreprocessOnly handles preprocess-only mode
func processPreprocessOnly(supportedFiles []string, fileRouter *router.FileRouter, finalConfig *finalConfiguration) error {
	if len(supportedFiles) == 0 {
		fmt.Println("No files to preprocess")
		return nil
	}

	// Check if preprocessors are enabled
	if !finalConfig.enablePreprocessors {
		fmt.Fprintf(os.Stderr, "Error: Preprocessors are disabled. Enable with --enable-preprocessors\n")
		return fmt.Errorf("preprocessors disabled")
	}

	processedCount := 0
	errorCount := 0

	for i, filePath := range supportedFiles {
		// Add separator between files (except for the first file)
		if i > 0 {
			fmt.Println()
		}

		// Print file header
		fmt.Printf("=== FILE: %s ===\n", filePath)

		// Enhanced file access error handling
		if _, err := os.Stat(filePath); err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("Status: Error - File not found: %s\n", filePath)
			} else if os.IsPermission(err) {
				fmt.Printf("Status: Error - Permission denied: %s\n", filePath)
			} else {
				fmt.Printf("Status: Error - File access error: %v\n", err)
			}
			errorCount++
			continue
		}

		// Check if file can be processed
		canProcess, reason := fileRouter.CanProcessFile(filePath, finalConfig.enablePreprocessors, false)
		if !canProcess {
			// Enhanced error messages for unsupported file types
			if strings.Contains(reason, "Unsupported file type") {
				ext := strings.ToLower(filepath.Ext(filePath))
				if ext == "" {
					fmt.Printf("Status: Error - No file extension detected, cannot determine file type\n")
				} else {
					fmt.Printf("Status: Error - Unsupported file type '%s' - no preprocessor available\n", ext)
				}
			} else {
				fmt.Printf("Status: Error - %s\n", reason)
			}
			errorCount++
			continue
		}

		// Create processing context with enhanced error handling
		processingContext, err := fileRouter.CreateProcessingContext(filePath, false, nil, "", finalConfig.debug)
		if err != nil {
			// Provide more specific error messages
			if strings.Contains(err.Error(), "permission") {
				fmt.Printf("Status: Error - Permission denied accessing file: %v\n", err)
			} else if strings.Contains(err.Error(), "not found") {
				fmt.Printf("Status: Error - File not found during context creation: %v\n", err)
			} else {
				fmt.Printf("Status: Error - Failed to create processing context: %v\n", err)
			}
			errorCount++
			continue
		}

		// Process the file with enhanced error handling
		processedContent, err := fileRouter.ProcessFileWithContext(filePath, processingContext)
		if err != nil {
			// Provide meaningful error messages for preprocessing failures
			if strings.Contains(err.Error(), "no preprocessor can handle") {
				fmt.Printf("Status: Error - No suitable preprocessor found for this file type\n")
			} else if strings.Contains(err.Error(), "all preprocessors failed") {
				fmt.Printf("Status: Error - All available preprocessors failed to process this file\n")
			} else if strings.Contains(err.Error(), "permission") {
				fmt.Printf("Status: Error - Permission denied reading file: %v\n", err)
			} else if strings.Contains(err.Error(), "not found") {
				fmt.Printf("Status: Error - File not found during processing: %v\n", err)
			} else {
				fmt.Printf("Status: Error - Preprocessing failed: %v\n", err)
			}
			errorCount++
			continue
		}

		// Check if processing was successful with enhanced error reporting
		if processedContent == nil || !processedContent.Success {
			if processedContent != nil && processedContent.Error != nil {
				// Provide more specific error messages based on the error type
				errMsg := processedContent.Error.Error()
				if strings.Contains(errMsg, "corrupted") || strings.Contains(errMsg, "invalid") {
					fmt.Printf("Status: Error - File appears to be corrupted or invalid: %v\n", processedContent.Error)
				} else if strings.Contains(errMsg, "encrypted") || strings.Contains(errMsg, "password") {
					fmt.Printf("Status: Error - File is encrypted or password-protected: %v\n", processedContent.Error)
				} else if strings.Contains(errMsg, "format") {
					fmt.Printf("Status: Error - Unsupported or invalid file format: %v\n", processedContent.Error)
				} else {
					fmt.Printf("Status: Error - %v\n", processedContent.Error)
				}
			} else {
				fmt.Printf("Status: Error - Preprocessing failed with no specific error details\n")
			}
			errorCount++
			continue
		}

		// Display processor information and status
		fmt.Printf("Processor: %s\n", processedContent.ProcessorType)
		fmt.Printf("Status: Success\n")

		// Check if there's any extracted text with enhanced messaging
		if processedContent.Text == "" {
			// Provide more specific messages based on file type and processor
			if strings.Contains(processedContent.ProcessorType, "PDF") {
				fmt.Printf("\n[No text content found - PDF may contain only images or be empty]\n")
			} else if strings.Contains(processedContent.ProcessorType, "Office") {
				fmt.Printf("\n[No text content found - document may be empty or contain only images/objects]\n")
			} else if strings.Contains(processedContent.ProcessorType, "Image") {
				fmt.Printf("\n[No text content found - image may not contain readable text]\n")
			} else {
				fmt.Printf("\n[No preprocessable content found]\n")
			}
		} else {
			// Display metadata if available
			if processedContent.WordCount > 0 || processedContent.CharCount > 0 {
				fmt.Printf("Content: %d words, %d characters", processedContent.WordCount, processedContent.CharCount)
				if processedContent.PageCount > 0 {
					fmt.Printf(", %d pages", processedContent.PageCount)
				}
				fmt.Printf("\n")
			}

			// Output the preprocessed text
			fmt.Printf("\n%s\n", processedContent.Text)
		}

		processedCount++
	}

	// Print summary if processing multiple files
	if len(supportedFiles) > 1 {
		fmt.Printf("\n=== SUMMARY ===\n")
		fmt.Printf("Files processed: %d\n", processedCount)
		if errorCount > 0 {
			fmt.Printf("Files with errors: %d\n", errorCount)
		}
	}

	return nil
}

// handleProfiles handles profile listing and selection
func handleProfiles(cfg *config.Config, listProfiles bool, profileName, configFile string, precommitConfig *precommit.PrecommitConfig) *config.Profile {
	// List profiles if requested
	if listProfiles {
		if configFile == "" {
			fmt.Println("No configuration file found. No profiles available.")
			os.Exit(0)
		}

		profiles := cfg.ListProfiles()
		if len(profiles) == 0 {
			fmt.Println("No profiles defined in configuration file.")
		} else {
			fmt.Println("Available profiles:")
			for _, name := range profiles {
				profile := cfg.GetProfile(name)
				if profile != nil && profile.Description != "" {
					fmt.Printf("  - %s: %s\n", name, profile.Description)
				} else {
					fmt.Printf("  - %s\n", name)
				}
			}
		}
		os.Exit(0)
	}

	// Apply profile settings if specified
	var activeProfile *config.Profile
	if profileName != "" {
		if cfg == nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Cannot use profile '%s' - no configuration loaded", profileName),
				"Check that config file exists and is readable")
			os.Exit(1)
		}
		activeProfile = cfg.GetProfile(profileName)
		if activeProfile == nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Profile '%s' not found in config file", profileName),
				"Check available profiles with --help or verify config file")
			os.Exit(1)
		}
	}
	return activeProfile
}

// registerDefaultRedactors registers all default redactors with the manager
func registerDefaultRedactors(manager *redactors.RedactionManager) error {
	// Get the output manager and observer from the redaction manager
	outputManager := manager.GetOutputManager()
	observer := manager.GetObserver()

	// Register PlainText redactor
	plainTextRedactor := plaintext.NewPlainTextRedactor(outputManager, observer)
	if err := manager.RegisterRedactor(plainTextRedactor); err != nil {
		return fmt.Errorf("failed to register PlainText redactor: %w", err)
	}

	// Register PDF redactor
	pdfRedactor := pdf.NewPDFRedactor(outputManager, observer)
	if err := manager.RegisterRedactor(pdfRedactor); err != nil {
		return fmt.Errorf("failed to register PDF redactor: %w", err)
	}

	// Register Office redactor
	officeRedactor := office.NewOfficeRedactor(outputManager, observer)
	if err := manager.RegisterRedactor(officeRedactor); err != nil {
		return fmt.Errorf("failed to register Office redactor: %w", err)
	}

	// Register Image Metadata redactor
	imageRedactor := image.NewImageMetadataRedactor(outputManager, observer)
	if err := manager.RegisterRedactor(imageRedactor); err != nil {
		return fmt.Errorf("failed to register Image Metadata redactor: %w", err)
	}

	return nil
}

// getBoolFlag safely gets the value of a boolean flag pointer, returning false if nil
func getBoolFlag(flag *bool) bool {
	if flag != nil {
		return *flag
	}
	return false
}

// getStringFlag safely gets the value of a string flag pointer, returning empty string if nil
func getStringFlag(flag *string) string {
	if flag != nil {
		return *flag
	}
	return ""
}

// setBoolFlag safely sets the value of a boolean flag pointer if it's not nil
func setBoolFlag(flag *bool, value bool) {
	if flag != nil {
		*flag = value
	}
}

// shouldSuppressProgressOutput determines if progress output should be suppressed
func shouldSuppressProgressOutput(finalConfig *finalConfiguration, quiet bool, precommitConfig *precommit.PrecommitConfig, isInteractive bool) bool {
	suppress := finalConfig.debug || quiet || !isInteractive
	if precommitConfig != nil && precommitConfig.QuietMode {
		suppress = true
	}
	return suppress
}

// extractedFlags holds safely extracted flag values to avoid repeated nil checks
type extractedFlags struct {
	webMode              bool
	webPort              string
	inputFile            string
	configFile           string
	profileName          string
	listProfiles         bool
	outputFormat         string
	outputFile           string
	confidenceLevels     string
	checksToRun          string
	verbose              bool
	debug                bool
	quiet                bool
	noColor              bool
	recursive            bool
	enablePreprocessors  bool
	preprocessOnly       bool
	precommitMode        bool
	showMatch            bool
	showSuppressed       bool
	generateSuppressions bool
	enableRedaction      bool
	redactionOutputDir   string
	redactionStrategy    string
	redactionAuditLog    string
	suppressionFile      string
}

// flagPointers groups all flag pointers for easier management
type flagPointers struct {
	// Boolean flags
	webMode              *bool
	quiet                *bool
	debug                *bool
	noColor              *bool
	verbose              *bool
	recursive            *bool
	enablePreprocessors  *bool
	preprocessOnly       *bool
	preprocessOnlyShort  *bool
	precommitMode        *bool
	showMatch            *bool
	showSuppressed       *bool
	generateSuppressions *bool
	enableRedaction      *bool
	listProfiles         *bool

	// String flags
	webPort            *string
	inputFile          *string
	configFile         *string
	profileName        *string
	outputFormat       *string
	confidenceLevels   *string
	checksToRun        *string
	redactionOutputDir *string
	redactionStrategy  *string
	redactionAuditLog  *string
	outputFile         *string
	suppressionFile    *string
}

// extractAllFlags safely extracts all flag values once to avoid repeated nil checks
func extractAllFlags(flags flagPointers) extractedFlags {
	return extractedFlags{
		webMode:              getBoolFlag(flags.webMode),
		webPort:              getStringFlag(flags.webPort),
		inputFile:            getStringFlag(flags.inputFile),
		configFile:           getStringFlag(flags.configFile),
		profileName:          getStringFlag(flags.profileName),
		listProfiles:         getBoolFlag(flags.listProfiles),
		outputFormat:         getStringFlag(flags.outputFormat),
		confidenceLevels:     getStringFlag(flags.confidenceLevels),
		checksToRun:          getStringFlag(flags.checksToRun),
		verbose:              getBoolFlag(flags.verbose),
		debug:                getBoolFlag(flags.debug),
		quiet:                getBoolFlag(flags.quiet),
		noColor:              getBoolFlag(flags.noColor),
		recursive:            getBoolFlag(flags.recursive),
		enablePreprocessors:  getBoolFlag(flags.enablePreprocessors),
		preprocessOnly:       getBoolFlag(flags.preprocessOnly) || getBoolFlag(flags.preprocessOnlyShort),
		precommitMode:        getBoolFlag(flags.precommitMode),
		showMatch:            getBoolFlag(flags.showMatch),
		showSuppressed:       getBoolFlag(flags.showSuppressed),
		generateSuppressions: getBoolFlag(flags.generateSuppressions),
		enableRedaction:      getBoolFlag(flags.enableRedaction),
		redactionOutputDir:   getStringFlag(flags.redactionOutputDir),
		redactionStrategy:    getStringFlag(flags.redactionStrategy),
		redactionAuditLog:    getStringFlag(flags.redactionAuditLog),
		outputFile:           getStringFlag(flags.outputFile),
		suppressionFile:      getStringFlag(flags.suppressionFile),
	}
}

func main() {
	// Parse command line flags
	inputFile := flag.String("file", "", "Path to the input file, directory, or glob pattern (e.g., *.pdf)")
	configFile := flag.String("config", "", "Path to configuration file (YAML)")
	profileName := flag.String("profile", "", "Profile name to use from config file")
	listProfiles := flag.Bool("list-profiles", false, "List available profiles in config file")
	outputFormat := flag.String("format", "", "Output format: text, json, csv, yaml, junit, gitlab-sast, sarif (default: text)")
	confidenceLevels := flag.String("confidence", "", "Confidence levels to display: high, medium, low, or combinations like 'high,medium'")
	checksToRun := flag.String("checks", "", "Specific checks to run: CREDIT_CARD, PASSPORT, METADATA, or combinations like 'CREDIT_CARD,METADATA'")
	verbose := flag.Bool("verbose", false, "Display detailed information for each finding")
	debug := flag.Bool("debug", false, "Enable debug logging to show preprocessing and validation flow")
	outputFile := flag.String("output", "", "Path to output file (if not specified, output to stdout)")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	showHelp := flag.Bool("help", false, "Show help information")
	showVersion := flag.Bool("version", false, "Show version information")
	showMatch := flag.Bool("show-match", false, "Display the actual matched text in findings")
	recursive := flag.Bool("recursive", false, "Recursively scan directories")
	enablePreprocessors := flag.Bool("enable-preprocessors", true, "Enable text extraction from documents (PDF, Office files) (default: true, use --enable-preprocessors=false to disable)")
	preprocessOnly := flag.Bool("preprocess-only", false, "Output preprocessed text and exit (no validation or redaction)")
	preprocessOnlyShort := flag.Bool("p", false, "Output preprocessed text and exit (alias for --preprocess-only)")
	// GENAI_DISABLED: GenAI-related command line flags
	// enableGenAI := flag.Bool("enable-genai", false, "Enable AI-powered services: Textract OCR, Transcribe, and Comprehend PII detection (requires AWS credentials, data sent to AWS, costs may apply)")
	// genaiServices := flag.String("genai-services", "all", "Comma-separated list of GenAI services to use: textract, transcribe, comprehend, or 'all' (only used with --enable-genai)")
	// textractRegion := flag.String("textract-region", "us-east-1", "AWS region for Textract service (only used with --enable-genai)")
	// transcribeBucket := flag.String("transcribe-bucket", "", "S3 bucket name for Transcribe audio uploads (optional, creates temporary bucket if not specified)")
	suppressionFile := flag.String("suppression-file", "", "Path to suppression configuration file (default: .ferret-scan-suppressions.yaml)")
	generateSuppressions := flag.Bool("generate-suppressions", false, "Generate suppression rules for all findings (disabled by default, can be enabled in YAML)")

	showSuppressed := flag.Bool("show-suppressed", false, "Include suppressed findings in output with suppression details (marked as [SUPP] in text format)")
	// GENAI_DISABLED: Cost control flags for GenAI services
	// maxCost := flag.Float64("max-cost", 0, "Maximum cost limit for GenAI services (default: no limit)")
	// estimateOnly := flag.Bool("estimate-only", false, "Show cost estimate and exit without processing")
	quiet := flag.Bool("quiet", false, "Suppress progress output (useful for scripts and CI/CD)")
	precommitMode := flag.Bool("pre-commit-mode", false, "Enable pre-commit optimizations (quiet mode, no colors, appropriate exit codes)")

	// Redaction flags
	enableRedaction := flag.Bool("enable-redaction", false, "Enable redaction of sensitive data found in documents")
	redactionOutputDir := flag.String("redaction-output-dir", "./redacted", "Directory where redacted files will be stored")
	redactionStrategy := flag.String("redaction-strategy", "format_preserving", "Default redaction strategy: simple, format_preserving, or synthetic")
	redactionAuditLog := flag.String("redaction-audit-log", "", "Path to save redaction audit log file (JSON format for compliance)")

	// Web server flags
	webMode := flag.Bool("web", false, "Start web server mode instead of CLI scanning")
	webPort := flag.String("port", "8080", "Port for web server (default: 8080)")

	flag.Parse()

	// Extract all flag values once for performance and consistency
	flags := extractAllFlags(flagPointers{
		// Boolean flags
		webMode:              webMode,
		quiet:                quiet,
		debug:                debug,
		noColor:              noColor,
		verbose:              verbose,
		recursive:            recursive,
		enablePreprocessors:  enablePreprocessors,
		preprocessOnly:       preprocessOnly,
		preprocessOnlyShort:  preprocessOnlyShort,
		precommitMode:        precommitMode,
		showMatch:            showMatch,
		showSuppressed:       showSuppressed,
		generateSuppressions: generateSuppressions,
		enableRedaction:      enableRedaction,
		listProfiles:         listProfiles,

		// String flags
		webPort:            webPort,
		inputFile:          inputFile,
		configFile:         configFile,
		profileName:        profileName,
		outputFormat:       outputFormat,
		confidenceLevels:   confidenceLevels,
		checksToRun:        checksToRun,
		redactionOutputDir: redactionOutputDir,
		redactionStrategy:  redactionStrategy,
		redactionAuditLog:  redactionAuditLog,
		outputFile:         outputFile,
		suppressionFile:    suppressionFile,
	})

	// Handle web mode early - validate flags and start web server if requested
	if flags.webMode {
		if err := handleWebMode(flags.webPort, flag.Args(), flags.inputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		// Web server will run indefinitely, so this should not be reached
		return
	}

	// Auto-detect non-interactive environment
	isInteractive := isTerminal(os.Stderr)
	if !isInteractive || flags.quiet || os.Getenv("CI") != "" {
		setBoolFlag(noColor, true)
	}

	// Create debug observer early for configuration logging
	var mainDebugObs *observability.DebugObserver
	if flags.debug {
		mainDebugObs = observability.NewDebugObserver(os.Stderr)
		mainDebugObs.LogDetail("main", fmt.Sprintf("Command line arguments: %v", os.Args))
		if flags.inputFile != "" {
			mainDebugObs.LogDetail("main", fmt.Sprintf("Parsed --file flag: %s", flags.inputFile))
		}
	}

	// Load configuration
	cfg := loadConfiguration(flags.configFile)

	// Initialize pre-commit detector early to check for automatic profile selection
	precommitDetector := precommit.NewPrecommitDetectorWithFlag(flags.precommitMode)
	var precommitConfig *precommit.PrecommitConfig

	// Apply pre-commit optimizations if detected or explicitly enabled
	if precommitDetector.IsPrecommitEnvironment() {
		precommitConfig = precommitDetector.GetOptimizedConfig()
	}

	// Determine profile name - use pre-commit profile automatically if in pre-commit environment and no explicit profile
	effectiveProfileName := flags.profileName
	if effectiveProfileName == "" && precommitDetector.IsPrecommitEnvironment() {
		suggestedProfile := precommitDetector.GetSuggestedProfile()
		if suggestedProfile != "" && cfg != nil && cfg.GetProfile(suggestedProfile) != nil {
			effectiveProfileName = suggestedProfile
		}
	}

	// Handle profile operations
	activeProfile := handleProfiles(cfg, flags.listProfiles, effectiveProfileName, flags.configFile, precommitConfig)

	// Resolve final configuration values using extracted flags
	finalConfig := resolveConfiguration(cfg, activeProfile, &configFlags{
		outputFormat:        flags.outputFormat,
		confidenceLevels:    flags.confidenceLevels,
		checksToRun:         flags.checksToRun,
		verbose:             flags.verbose,
		debug:               flags.debug,
		noColor:             flags.noColor,
		recursive:           flags.recursive,
		enablePreprocessors: flags.enablePreprocessors,
		preprocessOnly:      flags.preprocessOnly,
		precommitMode:       flags.precommitMode,
		// GENAI_DISABLED: GenAI configuration flag passing
		// enableGenAI:         *enableGenAI,
		// genaiServices:       *genaiServices,
		// textractRegion:      *textractRegion,
		// estimateOnly:        *estimateOnly,
		// Redaction flags
		enableRedaction:    flags.enableRedaction,
		redactionOutputDir: flags.redactionOutputDir,
		redactionStrategy:  flags.redactionStrategy,
		redactionAuditLog:  flags.redactionAuditLog,
	})

	// Use the pre-commit detector initialized earlier (no need to reinitialize)
	// precommitConfig is already initialized above

	// Apply additional pre-commit optimizations to final config
	if precommitConfig != nil {

		// Override configuration with pre-commit optimizations
		if precommitConfig.QuietMode {
			setBoolFlag(quiet, true)
		}
		if precommitConfig.NoColor {
			finalConfig.noColor = true
		}
		if precommitConfig.Format != "" {
			finalConfig.format = precommitConfig.Format
		}

		if mainDebugObs != nil {
			mainDebugObs.LogDetail("precommit", "Pre-commit environment detected, applying optimizations")
			mainDebugObs.LogDetail("precommit", fmt.Sprintf("Quiet mode: %v, No color: %v, Format: %s",
				precommitConfig.QuietMode, precommitConfig.NoColor, precommitConfig.Format))
		}
	}

	// Check if FERRET_DEBUG environment variable is set
	if os.Getenv("FERRET_DEBUG") != "" {
		finalConfig.debug = true
	}

	// Set environment variable for validators to detect debug mode
	if finalConfig.debug {
		os.Setenv("FERRET_DEBUG", "1")
	}

	// Validate flag combinations
	if finalConfig.preprocessOnly {
		// Check for incompatible flags with preprocess-only mode
		if finalConfig.enableRedaction {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --enable-redaction\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode outputs text content and exits before redaction phase.\n")
			os.Exit(1)
		}

		// Check if output format flags are used (they don't make sense with preprocess-only)
		if flags.outputFile != "" {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --output\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode outputs directly to stdout.\n")
			os.Exit(1)
		}

		// Check if validation-specific flags are used
		if flags.showMatch {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --show-match\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation.\n")
			os.Exit(1)
		}

		if flags.generateSuppressions {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --generate-suppressions\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation or generate findings.\n")
			os.Exit(1)
		}

		if flags.suppressionFile != "" && flags.suppressionFile != ".ferret-scan-suppressions.yaml" {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --suppression-file\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation.\n")
			os.Exit(1)
		}

		if flags.showSuppressed {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --show-suppressed\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation.\n")
			os.Exit(1)
		}

		// Warn about format flags that will be ignored
		if finalConfig.format != "text" && isFlagSet("format") {
			fmt.Fprintf(os.Stderr, "Warning: --format flag is ignored in preprocess-only mode\n")
		}

		if finalConfig.confidenceLevels != "all" && isFlagSet("confidence") {
			fmt.Fprintf(os.Stderr, "Warning: --confidence flag is ignored in preprocess-only mode\n")
		}

		if finalConfig.checksToRun != "all" && isFlagSet("checks") {
			fmt.Fprintf(os.Stderr, "Warning: --checks flag is ignored in preprocess-only mode\n")
		}

		// Check if preprocessors are disabled
		if !finalConfig.enablePreprocessors {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only requires preprocessors to be enabled\n")
			fmt.Fprintf(os.Stderr, "Remove --enable-preprocessors=false or use --enable-preprocessors=true\n")
			os.Exit(1)
		}
	}

	// Context analyzer is now integrated into the enhanced validator pipeline

	// STREAMLINED IMPLEMENTATION: Context-aware validation optimized for CLI
	enhancedManager := validators.NewEnhancedValidatorManager(&validators.EnhancedValidatorConfig{
		EnableBatchProcessing:        true,
		BatchSize:                    100,
		EnableParallelProcessing:     true,
		MaxWorkers:                   8,
		EnableContextAnalysis:        true,
		ContextWindowSize:            500,
		EnableCrossValidatorAnalysis: true, // Session-only cross-validator intelligence
		EnableConfidenceCalibration:  true, // Statistical confidence calibration
		EnableLanguageDetection:      true,
		DefaultLanguage:              "en",
		SupportedLanguages:           []string{"en"},
		EnableAdvancedAnalytics:      true,
		EnableRealTimeMetrics:        finalConfig.debug,
	})

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("enhanced", "Enhanced Validator Manager configured with:")
		mainDebugObs.LogDetail("enhanced", "  - In-memory pattern caching enabled (10K patterns)")
		mainDebugObs.LogDetail("enhanced", "  - Cross-validator analysis enabled")
		mainDebugObs.LogDetail("enhanced", "  - Pattern learning enabled")
		mainDebugObs.LogDetail("enhanced", "  - Confidence calibration enabled")
		mainDebugObs.LogDetail("enhanced", "  - Batch processing (100 items/batch)")
	}

	// Parse which checks should be run based on --checks parameter
	// GENAI_DISABLED: Pass false for enableGenAI parameter
	enabledChecks := parseChecksToRun(finalConfig.checksToRun, false)

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("config", fmt.Sprintf("Enabled checks: %v", enabledChecks))
	}

	// Initialize standard validators and wrap them with enhanced capabilities
	// Only create validators that are enabled
	standardValidators := make(map[string]detector.Validator)

	if enabledChecks["CREDIT_CARD"] {
		standardValidators["CREDIT_CARD"] = creditcard.NewValidator()
	}
	if enabledChecks["EMAIL"] {
		standardValidators["EMAIL"] = email.NewValidator()
	}
	if enabledChecks["PHONE"] {
		standardValidators["PHONE"] = phone.NewValidator()
	}
	if enabledChecks["IP_ADDRESS"] {
		standardValidators["IP_ADDRESS"] = ipaddress.NewValidator()
	}
	if enabledChecks["PASSPORT"] {
		standardValidators["PASSPORT"] = passport.NewValidator()
	}
	if enabledChecks["PERSON_NAME"] {
		standardValidators["PERSON_NAME"] = personname.NewValidator()
	}
	if enabledChecks["METADATA"] {
		standardValidators["METADATA"] = metadata.NewValidator()
	}
	if enabledChecks["INTELLECTUAL_PROPERTY"] {
		standardValidators["INTELLECTUAL_PROPERTY"] = intellectualproperty.NewValidator()
	}
	if enabledChecks["SOCIAL_MEDIA"] {
		standardValidators["SOCIAL_MEDIA"] = socialmedia.NewValidator()
	}
	if enabledChecks["SSN"] {
		standardValidators["SSN"] = ssn.NewValidator()
	}
	if enabledChecks["SECRETS"] {
		standardValidators["SECRETS"] = secrets.NewValidator()
	}
	// GENAI_DISABLED: COMPREHEND_PII validator removed from available validators
	// if enabledChecks["COMPREHEND_PII"] {
	//     standardValidators["COMPREHEND_PII"] = comprehend.NewValidator()
	// }

	// Set up dual path validation integration
	var dualPathObserver *observability.StandardObserver
	if mainDebugObs != nil {
		dualPathObserver = mainDebugObs.StandardObserver
		dualPathObserver.DebugObserver = mainDebugObs
	} else {
		dualPathObserver = observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
	}

	dualPathHelper := validators.NewValidatorIntegrationHelper(dualPathObserver)
	err := dualPathHelper.SetupDualPathValidation(standardValidators)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to setup dual path validation: %v\n", err)
	} else if mainDebugObs != nil {
		mainDebugObs.LogDetail("enhanced", "Set up dual path validation system")
	}

	// Connect dual path helper to enhanced manager
	enhancedManager.SetDualPathHelper(dualPathHelper)

	// Register enhanced validators with the manager (excluding metadata validator)
	for name, validator := range standardValidators {
		// Skip metadata validator - it's handled by dual path system
		if name == "METADATA" {
			if mainDebugObs != nil {
				mainDebugObs.LogDetail("enhanced", "Metadata validator handled by dual path system")
			}
			continue
		}

		bridge := validators.NewValidatorBridge(name, validator)
		err := enhancedManager.RegisterValidator(name, bridge)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to register enhanced validator %s: %v\n", name, err)
		} else if mainDebugObs != nil {
			mainDebugObs.LogDetail("enhanced", fmt.Sprintf("Registered enhanced validator: %s", name))
		}
	}

	// Keep reference to standard validators for backward compatibility
	allValidators := standardValidators

	// Observability will be set up after router initialization

	// Configure validators with settings from config file
	// First apply global validator configurations
	if ipValidator, ok := allValidators["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator); ok && cfg != nil {
		ipValidator.Configure(cfg)
	}
	if smValidator, ok := allValidators["SOCIAL_MEDIA"].(*socialmedia.Validator); ok && cfg != nil {
		smValidator.Configure(cfg)
	}

	// GENAI_DISABLED: Configure Comprehend validator with GenAI settings
	// if comprehendValidator, ok := allValidators["COMPREHEND_PII"].(*comprehend.Validator); ok {
	// 	comprehendValidator.SetEnabled(finalConfig.enableGenAI && finalConfig.genaiServices["comprehend"])
	// 	comprehendValidator.SetRegion(finalConfig.textractRegion)
	// 	if mainDebugObs != nil {
	// 		mainDebugObs.LogDetail("config", fmt.Sprintf("Comprehend validator enabled: %v (GenAI: %v, Service: %v)",
	// 			finalConfig.enableGenAI && finalConfig.genaiServices["comprehend"],
	// 			finalConfig.enableGenAI, finalConfig.genaiServices["comprehend"]))
	// 	}
	// }

	// Then apply profile-specific configurations if a profile is active
	if activeProfile != nil && activeProfile.Validators != nil {
		// Create a temporary config with just the profile's validator settings
		profileConfig := &config.Config{
			Validators: activeProfile.Validators,
		}

		// Configure validators with profile-specific settings
		if ipValidator, ok := allValidators["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator); ok {
			ipValidator.Configure(profileConfig)
		}
		// Note: Comprehend validator settings are controlled by GenAI flag, not profiles
	}

	// Use enhanced manager wrapper instead of individual validators
	// This enables context analysis and other advanced features
	enhancedWrapper := validators.NewEnhancedManagerWrapper(enhancedManager)
	validatorsList := []detector.Validator{enhancedWrapper}

	// Handle version command
	if *showVersion {
		fmt.Println(version.Info())
		return
	}

	// Handle help commands
	if *showHelp {
		helpSystem := help.NewSystem(finalConfig.noColor)

		// Register ALL validators as help providers (not just filtered ones)
		for _, validator := range allValidators {
			if provider, ok := validator.(help.Provider); ok {
				helpSystem.RegisterProvider(provider)
			}
		}

		// Process help command
		args := flag.Args()
		if len(args) == 0 {
			// Show general help
			helpSystem.ShowGeneralHelp()
			return
		} else if len(args) == 1 {
			if strings.ToLower(args[0]) == "checks" {
				// Show list of all checks
				helpSystem.ShowChecksHelp()
				return
			}
			// Show help for specific check
			if helpSystem.ShowCheckHelp(args[0]) {
				return
			}
			os.Exit(1)
		} else {
			fmt.Println("Error: Too many arguments for help command")
			fmt.Println("Use 'ferret-scan --help', 'ferret-scan --help checks', or 'ferret-scan --help <check>'")
			os.Exit(1)
		}
	}

	// Handle file arguments (files/directories)
	var inputPaths []string
	if *inputFile != "" {
		inputPaths = append(inputPaths, *inputFile)
	}

	// Add any additional arguments as file paths (for shell-expanded globs)
	// Only do this if help is not being requested
	args := flag.Args()
	if len(args) > 0 && !*showHelp {
		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", fmt.Sprintf("Found %d additional arguments: %v", len(args), args))
		}
		inputPaths = append(inputPaths, args...)
	}

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", fmt.Sprintf("Total input paths to process: %d", len(inputPaths)))
		for i, path := range inputPaths {
			mainDebugObs.LogDetail("main", fmt.Sprintf("  %d: %s", i+1, path))
		}
	}

	if len(inputPaths) == 0 {
		printPrecommitError(precommitConfig,
			"Input file or directory is required",
			"Specify a file or directory path to scan")
		os.Exit(1)
	}

	// Get list of files to process (supports glob patterns like *.pdf)
	var allFilesToProcess []string
	var totalSkipped int

	for i, inputPath := range inputPaths {
		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", fmt.Sprintf("Processing input path %d: %s", i+1, inputPath))
		}
		// Validate and sanitize the input path
		cleanPath := filepath.Clean(inputPath)
		abs, err := filepath.Abs(cleanPath)
		if err != nil {
			fmt.Printf("Error: Invalid input path: %s\n", inputPath)
			continue
		}
		// Check for path traversal attempts - handle as skipped instead of error
		if strings.Contains(inputPath, "..") || strings.Contains(cleanPath, "..") {
			totalSkipped++
			// Don't show warning for path traversal attempts - they're security-related
			continue
		}
		cleanPath = abs
		result, err := getFilesToProcess(cleanPath, finalConfig.recursive)
		if err != nil {
			fmt.Printf("Error processing %s: %v\n", inputPath, err)
			continue
		}

		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", fmt.Sprintf("  Found %d files from this path", len(result.FilesToProcess)))
		}

		allFilesToProcess = append(allFilesToProcess, result.FilesToProcess...)

		// Handle skipped files
		for _, skipped := range result.SkippedFiles {
			totalSkipped++
			if !skipped.Silent {
				fmt.Fprintf(os.Stderr, "Warning: Skipping %s: %s\n", skipped.Path, skipped.Reason)
			}
		}
	}

	filesToProcess := allFilesToProcess

	if len(filesToProcess) == 0 {
		if finalConfig.preprocessOnly {
			if totalSkipped > 0 {
				printPrecommitError(precommitConfig,
					fmt.Sprintf("No files to preprocess - all %d files were skipped", totalSkipped),
					"Check file types, permissions, or size limits")
			} else {
				printPrecommitError(precommitConfig,
					"No files found to preprocess",
					"Verify path exists and contains supported file types")
			}
			os.Exit(2) // Use exit code 2 for no files to process as per design
		} else {
			fmt.Println("No files to process")
			os.Exit(0)
		}
	}

	// Initialize suppression manager
	suppressionManager := suppressions.NewSuppressionManager(*suppressionFile)
	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Suppression manager initialized")
	}

	// Parse confidence levels
	confidenceFilter := parseConfidenceLevels(finalConfig.confidenceLevels)

	// GENAI_DISABLED: GenAI warning and cost estimate logic
	// if finalConfig.enableGenAI {
	// 	fmt.Fprintf(os.Stderr, "\n⚠️  GENAI MODE ENABLED - IMPORTANT NOTICE:\n")
	// 	fmt.Fprintf(os.Stderr, "   • Amazon Textract OCR will be used for text extraction\n")
	// 	fmt.Fprintf(os.Stderr, "   • Amazon Comprehend will be used for PII detection\n")
	// 	fmt.Fprintf(os.Stderr, "   • Your files/text will be sent to AWS services\n")
	// 	fmt.Fprintf(os.Stderr, "   • Region: %s\n", finalConfig.textractRegion)
	// 	fmt.Fprintf(os.Stderr, "\n")

	// 	// Show cost estimate (no AWS credentials needed for estimation)
	// 	costEstimator := cost.NewEstimator()
	// 	estimate, err := costEstimator.EstimateFiles(filesToProcess, finalConfig.genaiServices)
	// 	if err == nil && estimate.TotalCost > 0 {
	// 		fmt.Fprintf(os.Stderr, "💰 %s\n", estimate.FormatDetailedSummary())

	// 		// Handle estimate-only mode (exit before credential validation and user prompt)
	// 		if finalConfig.estimateOnly {
	// 			fmt.Fprintf(os.Stderr, "\nEstimate-only mode: exiting without processing\n")
	// 			os.Exit(0)
	// 		}

	// 		// Check cost limits
	// 		if *maxCost > 0 && estimate.TotalCost > *maxCost {
	// 			fmt.Fprintf(os.Stderr, "\n❌ Cost limit exceeded: $%.4f > $%.4f\n", estimate.TotalCost, *maxCost)
	// 			fmt.Fprintf(os.Stderr, "Use --max-cost %.4f to override or reduce file count\n", estimate.TotalCost)
	// 			os.Exit(1)
	// 		}

	// 		// Prompt for any GenAI costs (only when actually processing)
	// 		if estimate.TotalCost > 0.0 {
	// 			fmt.Fprintf(os.Stderr, "\nContinue? [y/N]: ")
	// 			var response string
	// 			fmt.Scanln(&response)
	// 			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
	// 				fmt.Fprintf(os.Stderr, "Operation cancelled by user\n")
	// 				os.Exit(0)
	// 			}
	// 		}
	// 		fmt.Fprintf(os.Stderr, "\n")
	// 	} else if finalConfig.estimateOnly {
	// 		// Handle estimate-only mode even when no costs (e.g., text files with no GenAI services)
	// 		fmt.Fprintf(os.Stderr, "💰 Estimated cost: $0.00 (no GenAI services needed for this file type)\n")
	// 		fmt.Fprintf(os.Stderr, "\nEstimate-only mode: exiting without processing\n")
	// 		os.Exit(0)
	// 	}

	// 	// Validate AWS credentials (only if not estimate-only mode)
	// 	if !finalConfig.estimateOnly {
	// 		fmt.Fprintf(os.Stderr, "Validating AWS credentials...\n")
	// 		if err := validateAWSCredentials(finalConfig.textractRegion); err != nil {
	// 			fmt.Fprintf(os.Stderr, "\nError: AWS credentials validation failed: %v\n\n", err)
	// 			fmt.Fprintf(os.Stderr, "To fix this issue:\n")
	// 			fmt.Fprintf(os.Stderr, "1. Configure AWS credentials using one of these methods:\n")
	// 			fmt.Fprintf(os.Stderr, "   - Run 'aws configure' (requires AWS CLI)\n")
	// 			fmt.Fprintf(os.Stderr, "   - Set environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY\n")
	// 			fmt.Fprintf(os.Stderr, "   - Use IAM roles (for EC2 instances)\n")
	// 			fmt.Fprintf(os.Stderr, "   - Configure AWS credentials file (~/.aws/credentials)\n")
	// 			fmt.Fprintf(os.Stderr, "2. Ensure your credentials have permissions for:\n")
	// 			fmt.Fprintf(os.Stderr, "   - textract:DetectDocumentText\n")
	// 			fmt.Fprintf(os.Stderr, "   - comprehend:DetectPiiEntities\n")
	// 			fmt.Fprintf(os.Stderr, "3. Check that the specified region (%s) is correct\n\n", finalConfig.textractRegion)
	// 			os.Exit(1)
	// 		}
	// 		fmt.Fprintf(os.Stderr, "AWS credentials validated successfully.\n\n")
	// 	}
	// }

	// Initialize file router with observability
	fileRouter := router.NewFileRouter(finalConfig.debug)

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Registering default preprocessors...")
	}
	router.RegisterDefaultPreprocessors(fileRouter)

	// GENAI_DISABLED: Router configuration with GenAI settings
	routerConfig := router.CreateRouterConfig(
		false,                       // enableGenAI disabled
		nil,                         // genaiServices disabled
		"",                          // textractRegion disabled
		finalConfig.enableRedaction, // Pass redaction setting to preprocessors
	)
	// GENAI_DISABLED: Transcribe bucket configuration
	// if *transcribeBucket != "" {
	// 	routerConfig["transcribe_bucket"] = *transcribeBucket
	// }

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Initializing preprocessors...")
	}
	fileRouter.InitializePreprocessors(routerConfig)

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", fmt.Sprintf("File router initialized with %d preprocessors", fileRouter.GetPreprocessorCount()))
	}

	// Connect FileRouter to dual path helper for metadata capability detection
	dualPathHelper.SetFileRouter(fileRouter)
	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Connected FileRouter to dual path helper for metadata filtering")
	}

	// Initialize redaction manager if redaction is enabled
	var redactionManager *redactors.RedactionManager
	if finalConfig.enableRedaction {
		var redactionObserver *observability.StandardObserver
		if finalConfig.debug {
			debugObs := observability.NewDebugObserver(os.Stderr)
			redactionObserver = debugObs.StandardObserver
			redactionObserver.DebugObserver = debugObs
		} else {
			redactionObserver = observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
		}

		// Create output structure manager
		outputManager, err := redactors.NewOutputStructureManager(finalConfig.redactionOutputDir, redactionObserver)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output structure manager: %v\n", err)
			os.Exit(1)
		}

		// Parse the CLI redaction strategy
		strategy := redactors.ParseRedactionStrategy(finalConfig.redactionStrategy)

		// Create redaction manager config with CLI strategy
		redactionConfig := &redactors.RedactionManagerConfig{
			DefaultStrategy:         strategy,
			MaxConcurrentRedactions: 4,
			EnableBatchProcessing:   true,
			BatchSize:               100,
			RetryAttempts:           3,
			RetryDelay:              time.Second * 2,
			EnableAuditTrail:        true,
			FailureHandling:         redactors.FailureHandlingGraceful,
		}

		// Create redaction manager with custom config
		redactionManager = redactors.NewRedactionManagerWithConfig(outputManager, redactionObserver, redactionConfig)

		// Register default redactors
		if err := registerDefaultRedactors(redactionManager); err != nil {
			fmt.Fprintf(os.Stderr, "Error registering default redactors: %v\n", err)
			os.Exit(1)
		}

		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", "Redaction manager initialized with default redactors")
		}
	}

	// Set up observability for all components
	for _, validator := range allValidators {
		if observableValidator, ok := validator.(interface {
			SetObserver(observer *observability.StandardObserver)
		}); ok {
			var observer *observability.StandardObserver
			if finalConfig.debug {
				debugObs := observability.NewDebugObserver(os.Stderr)
				observer = debugObs.StandardObserver
				// Store the debug observer in the standard observer for access
				observer.DebugObserver = debugObs
			} else {
				observer = observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
			}
			observableValidator.SetObserver(observer)
		}
	}

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", fmt.Sprintf("File router initialized with %d preprocessors", fileRouter.GetPreprocessorCount()))
	}

	if mainDebugObs != nil {
		finishConfigStep := mainDebugObs.StartStep("main", "configuration_summary", "")
		mainDebugObs.LogDetail("config", fmt.Sprintf("Preprocessors enabled: %v", finalConfig.enablePreprocessors))
		if cfg != nil {
			mainDebugObs.LogDetail("config", fmt.Sprintf("Text extraction enabled: %v", cfg.Preprocessors.TextExtraction.Enabled))
		} else {
			mainDebugObs.LogDetail("config", "Text extraction enabled: true (default)")
		}
		// GENAI_DISABLED: GenAI debug logging
		// mainDebugObs.LogDetail("config", fmt.Sprintf("GenAI (Textract) enabled: %v", finalConfig.enableGenAI))
		// if finalConfig.enableGenAI {
		// 	mainDebugObs.LogDetail("config", fmt.Sprintf("Textract region: %s", finalConfig.textractRegion))
		// }
		mainDebugObs.LogDetail("config", fmt.Sprintf("Validators to run: %v", finalConfig.checksToRun))
		mainDebugObs.LogDetail("config", fmt.Sprintf("Recursive scan: %v", finalConfig.recursive))
		mainDebugObs.LogDetail("config", fmt.Sprintf("Confidence levels: %v", finalConfig.confidenceLevels))
		mainDebugObs.LogMetric("config", "files_to_process", len(filesToProcess))
		finishConfigStep(true, "Configuration validated")
	}

	// Get the appropriate formatter with error handling
	formatter, exists := formatters.Get(finalConfig.format)
	if !exists {
		availableFormats := formatters.List()
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Unsupported output format '%s'", finalConfig.format),
			fmt.Sprintf("Use one of: %s", strings.Join(availableFormats, ", ")))
		os.Exit(1)
	}

	// Create formatter options
	formatterOptions := formatters.FormatterOptions{
		ConfidenceLevel: confidenceFilter,
		Verbose:         finalConfig.verbose,
		NoColor:         finalConfig.noColor,
		ShowMatch:       flags.showMatch,
		PrecommitMode:   precommitConfig != nil && precommitConfig.QuietMode,
	}

	// Process all files using parallel processing
	var allMatches []detector.Match
	processedFiles := 0
	skippedFiles := 0

	// Suppress progress messages in pre-commit mode or quiet mode
	if !shouldSuppressProgressOutput(finalConfig, flags.quiet, precommitConfig, isInteractive) {
		fmt.Fprintf(os.Stderr, "Starting scan of %d files...\n", len(filesToProcess))

		// Show filtering info if files were filtered out
		if totalSkipped > 0 {
			fmt.Fprintf(os.Stderr, "Filtered out %d unsupported files\n", totalSkipped)
		}
	}

	// Progress bar function with ETA
	progressStart := time.Now()
	updateProgress := func(current, total, skipped int) {
		if shouldSuppressProgressOutput(finalConfig, flags.quiet, precommitConfig, isInteractive) {
			return // Don't show progress bar in debug mode, quiet mode, pre-commit mode, or non-interactive environments
		}
		percent := float64(current) / float64(total) * 100
		barWidth := 40
		filledWidth := int(float64(barWidth) * float64(current) / float64(total))
		bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)

		// Calculate ETA
		var etaStr string
		if current > 0 {
			elapsed := time.Since(progressStart)
			avgTime := elapsed / time.Duration(current)
			remaining := time.Duration(total-current) * avgTime
			etaStr = fmt.Sprintf(" ETA: %s", remaining.Round(time.Second))
		}

		fmt.Fprintf(os.Stderr, "\r[%s] %d/%d files (%.1f%%) - %d skipped%s",
			bar, current, total, percent, skipped, etaStr)
		if current == total {
			fmt.Fprintf(os.Stderr, "\n")
		}
	}

	// Use parallel processing for all files (single or multiple)
	parallelProcessor := parallel.NewParallelProcessor(observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr))

	// Filter supported files
	var supportedFiles []string
	for _, filePath := range filesToProcess {
		// GENAI_DISABLED: Pass false for enableGenAI parameter
		canProcess, _ := fileRouter.CanProcessFile(filePath, finalConfig.enablePreprocessors, false)
		if canProcess {
			supportedFiles = append(supportedFiles, filePath)
		} else {
			skippedFiles++
		}
	}

	// Handle preprocess-only mode - exit early after preprocessing
	if finalConfig.preprocessOnly {
		err := processPreprocessOnly(supportedFiles, fileRouter, finalConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in preprocess-only mode: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Calculate progress based on supported files only
	totalFilesForProgress := len(supportedFiles)

	// Show additional filtering info if more files were filtered out
	if skippedFiles > 0 && !shouldSuppressProgressOutput(finalConfig, flags.quiet, precommitConfig, isInteractive) {
		fmt.Fprintf(os.Stderr, "Filtered out %d unsupported file types\n", skippedFiles)
	}

	if len(supportedFiles) > 0 {
		// PHASE 1 IMPLEMENTATION: Context analysis is now integrated into the parallel processing pipeline
		// to avoid duplicate file processing and improve performance

		jobConfig := &parallel.JobConfig{
			// GENAI_DISABLED: EnableGenAI:        false,
			// GENAI_DISABLED: GenAIServices:      nil,
			// GENAI_DISABLED: TextractRegion:     "",
			Debug:              finalConfig.debug,
			EnableRedaction:    finalConfig.enableRedaction,
			RedactionStrategy:  finalConfig.redactionStrategy,
			RedactionOutputDir: finalConfig.redactionOutputDir,
		}

		// Show initial progress
		if !finalConfig.debug {
			updateProgress(0, totalFilesForProgress, 0)
		}

		// Create progress callback that updates the progress bar
		var progressCallback func(completed, total int)
		if !shouldSuppressProgressOutput(finalConfig, flags.quiet, precommitConfig, isInteractive) {
			progressCallback = func(completed, total int) {
				// Update progress based on completed supported files
				updateProgress(completed, totalFilesForProgress, 0)
			}
		}

		parallelMatches, stats, err := parallelProcessor.ProcessFilesWithProgress(supportedFiles, validatorsList, fileRouter, jobConfig, redactionManager, progressCallback)
		if err == nil {

			allMatches = append(allMatches, parallelMatches...)
			processedFiles = stats.ProcessedFiles

			// Handle inline redaction results if redaction was enabled
			if finalConfig.enableRedaction && redactionManager != nil {
				// Note: Redaction results are now handled inline during parallel processing
				// The redaction index and results are managed by the redaction manager
				// during the job processing phase

				if mainDebugObs != nil {
					mainDebugObs.LogDetail("main", "Redaction completed inline during parallel processing")
				}

				// Export redaction audit log if specified
				if finalConfig.redactionAuditLog != "" {
					if err := redactionManager.ExportAuditLog(finalConfig.redactionAuditLog); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: Failed to export redaction audit log: %v\n", err)
					} else if !flags.quiet {
						fmt.Fprintf(os.Stderr, "Redaction audit log exported to: %s\n", finalConfig.redactionAuditLog)
					}
				}
			}

			// Final progress is already updated by the progress callback

			if finalConfig.debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Parallel processing: %d files, %d matches, %d workers, %dms\n",
					stats.ProcessedFiles, stats.TotalMatches, stats.WorkerCount, stats.TotalDuration.Milliseconds())
			}
		} else {
			fmt.Fprintf(os.Stderr, "Parallel processing failed: %v\n", err)
		}
	}

	elapsed := time.Since(progressStart)
	finalSkippedCount := totalSkipped + skippedFiles

	// Provide clearer reporting (suppress in pre-commit mode)
	totalAttempted := len(supportedFiles)
	failedFiles := totalAttempted - processedFiles

	if !shouldSuppressProgressOutput(finalConfig, flags.quiet, precommitConfig, isInteractive) {
		if finalSkippedCount > 0 || failedFiles > 0 {
			fmt.Fprintf(os.Stderr, "Scan complete: %d files processed successfully", processedFiles)
			if failedFiles > 0 {
				fmt.Fprintf(os.Stderr, ", %d files had no results", failedFiles)
			}
			if finalSkippedCount > 0 {
				fmt.Fprintf(os.Stderr, ", %d files skipped (%d unsupported types)", finalSkippedCount, skippedFiles)
			}
			fmt.Fprintf(os.Stderr, " in %s\n", elapsed.Round(time.Millisecond))
		} else {
			fmt.Fprintf(os.Stderr, "Scan complete: %d files processed in %s\n",
				processedFiles, elapsed.Round(time.Millisecond))
		}
	}

	// Apply suppressions
	var unsuppressedMatches []detector.Match
	var suppressedMatches []detector.SuppressedMatch
	suppressedCount := 0
	for _, match := range allMatches {
		if suppressed, rule := suppressionManager.IsSuppressed(match); suppressed {
			suppressedCount++
			if finalConfig.debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Suppressed finding: %s (Rule: %s, Reason: %s)\n",
					match.Type, rule.ID, rule.Reason)
			}
			// Collect suppressed findings if requested
			if flags.showSuppressed {
				// Check if rule is expired
				expired := rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt)

				suppressedMatches = append(suppressedMatches, detector.SuppressedMatch{
					Match:        match,
					SuppressedBy: rule.ID,
					RuleReason:   rule.Reason,
					ExpiresAt:    rule.ExpiresAt,
					Expired:      expired,
				})
			}
		} else {
			unsuppressedMatches = append(unsuppressedMatches, match)
		}
	}

	if suppressedCount > 0 {
		if flags.noColor {
			if flags.showSuppressed {
				fmt.Fprintf(os.Stderr, "Suppressed %d findings based on suppression rules (shown below with [SUPP] label)\n", suppressedCount)
			} else {
				fmt.Fprintf(os.Stderr, "Suppressed %d findings based on suppression rules (use --show-suppressed to see them)\n", suppressedCount)
			}
		} else {
			if flags.showSuppressed {
				fmt.Fprintf(os.Stderr, "\033[33mSuppressed\033[0m \033[31m%d\033[0m \033[33mfindings\033[0m based on suppression rules (shown below with \033[37m[SUPP]\033[0m label)\n", suppressedCount)
			} else {
				fmt.Fprintf(os.Stderr, "\033[33mSuppressed\033[0m \033[31m%d\033[0m \033[33mfindings\033[0m based on suppression rules (use \033[36m--show-suppressed\033[0m to see them)\n", suppressedCount)
			}
		}
	}

	// Generate suppression rules if requested
	if flags.generateSuppressions {
		if len(allMatches) > 0 {
			reason := "Auto-generated suppression rule (disabled by default)"
			err := suppressionManager.GenerateSuppressionRules(allMatches, reason, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to generate suppression rules: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Updated suppression rules: existing rules had last_seen_at updated, new rules added (disabled by default)\n")
				fmt.Fprintf(os.Stderr, "Edit the suppression file to enable specific rules by setting 'enabled: true'\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "No findings to generate suppression rules for\n")
		}
	}

	// Format and display results
	var result string
	if flags.showSuppressed {
		result, err = formatter.Format(unsuppressedMatches, suppressedMatches, formatterOptions)
	} else {
		result, err = formatter.Format(unsuppressedMatches, nil, formatterOptions)
	}
	if err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Error formatting results: %v", err),
			"Check output format and file permissions")
		os.Exit(1)
	}

	// Clear sensitive data from memory
	for i := range allMatches {
		allMatches[i].Clear()
	}
	allMatches = nil
	runtime.GC() // Force garbage collection

	// Output results
	if *outputFile != "" {
		// Validate and sanitize output file path
		cleanOutputPath := filepath.Clean(*outputFile)
		abs, err := filepath.Abs(cleanOutputPath)
		if err != nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Invalid output file path: %s", *outputFile),
				"Check that the path is valid and accessible")
			os.Exit(1)
		}
		// Check for path traversal attempts
		if strings.Contains(*outputFile, "..") || strings.Contains(cleanOutputPath, "..") {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Path traversal not allowed in output path: %s", *outputFile),
				"Use absolute paths or paths without '..' components")
			os.Exit(1)
		}
		cleanOutputPath = abs
		// Ensure output directory exists with secure permissions (owner only)
		outputDir := filepath.Dir(cleanOutputPath)
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Error creating output directory: %v", err),
				"Check directory permissions and available disk space")
			os.Exit(1)
		}
		// Use more restrictive permissions (0600) for files that might contain sensitive data
		err = os.WriteFile(cleanOutputPath, []byte(result), 0600)
		if err != nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Error writing to output file: %v", err),
				"Check file permissions and available disk space")
			os.Exit(1)
		}
	} else {
		fmt.Println(result)
	}

	// Determine appropriate exit code based on findings and pre-commit configuration
	hasFindings := len(unsuppressedMatches) > 0
	hasErrors := failedFiles > 0 // Track if there were any system errors during processing

	// Determine the highest confidence level of findings
	highestConfidence := ""
	for _, match := range unsuppressedMatches {
		var currentLevel string
		if match.Confidence >= 90 {
			currentLevel = "high"
		} else if match.Confidence >= 60 {
			currentLevel = "medium"
		} else {
			currentLevel = "low"
		}

		// Update highest confidence level
		if currentLevel == "high" {
			highestConfidence = "high"
		} else if currentLevel == "medium" && highestConfidence != "high" {
			highestConfidence = "medium"
		} else if currentLevel == "low" && highestConfidence != "high" && highestConfidence != "medium" {
			highestConfidence = "low"
		}
	}

	// Use pre-commit exit code logic if in pre-commit mode
	if precommitConfig != nil {
		exitCode := precommit.GetExitCode(hasFindings, hasErrors, highestConfidence, precommitConfig)
		os.Exit(exitCode)
	}

	// Default behavior: always exit with code 0 (traditional behavior)
	os.Exit(0)
}

// parseConfidenceLevels delegates to core.ParseConfidenceLevels to avoid code duplication between CLI and web modes.
// Converts a comma-separated string of confidence levels (e.g., "high,medium" or "all")
// into a map of confidence level thresholds for filtering scan results.
func parseConfidenceLevels(levels string) map[string]bool {
	return core.ParseConfidenceLevels(levels)
}

// ProcessingResult holds the result of file processing discovery
type ProcessingResult struct {
	FilesToProcess []string
	SkippedFiles   []SkippedFile
}

// SkippedFile represents a file that was skipped during processing
type SkippedFile struct {
	Path   string
	Reason string
	Silent bool // true = don't show to user, false = show as warning
}

// isUnsupportedType checks if a file extension is an unsupported type that should be silently skipped
func isUnsupportedType(ext string) bool {
	unsupportedTypes := map[string]bool{
		".mp4": true, ".mov": true, ".avi": true, ".mkv": true,
		".dmg": true, ".iso": true, ".img": true,
		".zip": true, ".tar": true, ".gz": true, ".7z": true,
	}
	return unsupportedTypes[ext]
}

// getFilesToProcess returns a list of files to process based on the input path
// Supports glob patterns like *.pdf, files, and directories
func getFilesToProcess(inputPath string, recursive bool) (*ProcessingResult, error) {
	result := &ProcessingResult{
		FilesToProcess: []string{},
		SkippedFiles:   []SkippedFile{},
	}
	// Validate input path before any file operations
	if strings.Contains(inputPath, "..") {
		return nil, fmt.Errorf("path traversal not allowed: %s", inputPath)
	}

	// Check if input contains glob patterns (but first check if file exists as-is)
	if _, err := os.Stat(inputPath); err == nil {
		// File exists as-is, treat as literal filename even if it contains glob chars
		info, err := os.Stat(inputPath)
		if err != nil {
			return nil, fmt.Errorf("path does not exist or is not accessible: %w", err)
		}
		if info.Mode().IsRegular() {
			ext := strings.ToLower(filepath.Ext(inputPath))
			audioTypes := map[string]bool{
				".mp3": true, ".wav": true, ".m4a": true, ".flac": true,
			}

			var sizeLimit int64 = 100 * 1024 * 1024 // 100MB default
			if audioTypes[ext] {
				sizeLimit = 500 * 1024 * 1024 // 500MB for audio files
			}

			if info.Size() <= sizeLimit {
				result.FilesToProcess = append(result.FilesToProcess, inputPath)
				return result, nil
			}
			// Skip large unsupported files silently
			limitMB := sizeLimit / (1024 * 1024)
			if isUnsupportedType(ext) {
				result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
					Path:   inputPath,
					Reason: fmt.Sprintf("file too large (max size: %dMB)", limitMB),
					Silent: true,
				})
				return result, nil
			}
			result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
				Path:   inputPath,
				Reason: fmt.Sprintf("file too large (max size: %dMB)", limitMB),
				Silent: false,
			})
			return result, nil
		}
	} else if strings.ContainsAny(inputPath, "*?") || (strings.Contains(inputPath, "[") && strings.Contains(inputPath, "]")) {
		// Expand home directory if present
		expandedPath := inputPath
		if strings.HasPrefix(inputPath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err == nil {
				expandedPath = filepath.Join(homeDir, inputPath[2:])
			}
		}

		// Handle glob pattern
		matches, err := filepath.Glob(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files match pattern: %s", inputPath)
		}

		// Filter out directories and check file sizes
		var filesToProcess []string
		for _, match := range matches {
			// Validate each match for path traversal
			cleanMatch := filepath.Clean(match)
			if strings.Contains(match, "..") || strings.Contains(cleanMatch, "..") {
				continue
			}
			// Additional validation before file access
			if strings.Contains(cleanMatch, "..") {
				continue
			}
			info, err := os.Stat(cleanMatch)
			if err != nil {
				continue
			}
			if info.Mode().IsRegular() {
				if info.Size() <= 100*1024*1024 {
					filesToProcess = append(filesToProcess, cleanMatch)
				} else {
					// Skip large unsupported files silently
					ext := strings.ToLower(filepath.Ext(cleanMatch))
					unsupportedTypes := map[string]bool{
						".mp4": true, ".mov": true, ".avi": true, ".mkv": true,
						".dmg": true, ".iso": true, ".img": true,
						".zip": true, ".tar": true, ".gz": true, ".7z": true,
					}
					if !unsupportedTypes[ext] {
						fmt.Fprintf(os.Stderr, "Warning: Skipping %s: file too large (> 100MB)\n", cleanMatch)
					}
				}
			}
		}
		result.FilesToProcess = filesToProcess
		return result, nil
	}

	// Clean the path to resolve any ".." components
	cleanPath := filepath.Clean(inputPath)

	// Additional validation after cleaning
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("path traversal not allowed after cleaning: %s", inputPath)
	}

	// Check if the path exists
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("path does not exist or is not accessible: %w", err)
	}

	var filesToProcess []string
	var skippedFiles []string

	// If it's a regular file, just process it
	if fileInfo.Mode().IsRegular() {
		// Skip large files silently for unsupported types
		if fileInfo.Size() > 100*1024*1024 { // 100MB limit
			ext := strings.ToLower(filepath.Ext(inputPath))
			if isUnsupportedType(ext) {
				result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
					Path:   inputPath,
					Reason: "file too large (max size: 100MB)",
					Silent: true,
				})
				return result, nil // Skip silently
			}
			result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
				Path:   inputPath,
				Reason: "file too large (max size: 100MB)",
				Silent: false,
			})
			return result, nil
		}
		result.FilesToProcess = append(result.FilesToProcess, cleanPath)
		return result, nil
	}

	// If it's a directory, get all files
	if fileInfo.IsDir() {
		err := filepath.Walk(cleanPath, func(path string, info os.FileInfo, err error) error {
			// Validate path for traversal attempts
			cleanWalkPath := filepath.Clean(path)
			if strings.Contains(path, "..") || strings.Contains(cleanWalkPath, "..") {
				return nil // Skip paths with traversal attempts
			}

			// Handle errors accessing a path
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Skipping %s: %v\n", path, err)
				skippedFiles = append(skippedFiles, path)
				return nil // Continue walking despite the error
			}

			// Skip directories if not recursive
			if !recursive && info.IsDir() && path != cleanPath {
				return filepath.SkipDir
			}

			// Only add regular files
			if info.Mode().IsRegular() {
				// Check file size
				if info.Size() <= 100*1024*1024 { // 100MB limit
					filesToProcess = append(filesToProcess, cleanWalkPath)
				} else {
					// Skip large unsupported files silently
					ext := strings.ToLower(filepath.Ext(cleanWalkPath))
					unsupportedTypes := map[string]bool{
						".mp4": true, ".mov": true, ".avi": true, ".mkv": true,
						".dmg": true, ".iso": true, ".img": true,
						".zip": true, ".tar": true, ".gz": true, ".7z": true,
					}
					if !unsupportedTypes[ext] {
						fmt.Fprintf(os.Stderr, "Warning: Skipping %s: file too large (> 100MB)\n", cleanWalkPath)
					}
					skippedFiles = append(skippedFiles, cleanWalkPath)
				}
			}

			return nil
		})

		// Only return an error if we couldn't even start the walk
		if err != nil {
			return nil, fmt.Errorf("error accessing directory: %w", err)
		}

		// Print summary of skipped files
		if len(skippedFiles) > 0 {
			fmt.Fprintf(os.Stderr, "Skipped %d files or directories due to errors\n", len(skippedFiles))
		}

		result.FilesToProcess = filesToProcess
		return result, nil
	}

	return nil, fmt.Errorf("path is neither a regular file nor a directory")
}

// isFlagSet checks if a flag was explicitly set on the command line
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// GENAI_DISABLED: parseGenAIServices converts a comma-separated string of GenAI service names
// into a map of enabled services
// func parseGenAIServices(services string, enableGenAI bool) map[string]bool {
// 	result := map[string]bool{
// 		"textract":   false,
// 		"transcribe": false,
// 		"comprehend": false,
// 	}

// 	if !enableGenAI {
// 		return result
// 	}

// 	if services == "all" {
// 		result["textract"] = true
// 		result["transcribe"] = true
// 		result["comprehend"] = true
// 		return result
// 	}

// 	// Parse comma-separated list of services
// 	for _, service := range strings.Split(services, ",") {
// 		serviceStr := strings.ToLower(strings.TrimSpace(service))
// 		if _, exists := result[serviceStr]; exists {
// 			result[serviceStr] = true
// 		}
// 	}

// 	return result
// }

// parseChecksToRun converts a comma-separated string of check names
// into a map of enabled checks
func parseChecksToRun(checks string, enableGenAI bool) map[string]bool {
	// Define available checks
	availableChecks := []string{
		"CREDIT_CARD", "EMAIL", "PHONE", "IP_ADDRESS", "PASSPORT",
		"PERSON_NAME", "METADATA", "INTELLECTUAL_PROPERTY",
		"SOCIAL_MEDIA", "SSN", "SECRETS",
	}

	result := make(map[string]bool)
	for _, check := range availableChecks {
		result[check] = false
	}

	if checks == "all" {
		// Enable all checks, COMPREHEND_PII excluded since GenAI is disabled
		for key := range result {
			// GENAI_DISABLED: COMPREHEND_PII logic removed
			// if key == "COMPREHEND_PII" {
			// 	result[key] = enableGenAI
			// } else {
			// 	result[key] = true
			// }
			result[key] = true
		}
		return result
	}

	// Parse comma-separated list of checks
	for _, check := range strings.Split(checks, ",") {
		checkStr := strings.ToUpper(strings.TrimSpace(check))
		if _, exists := result[checkStr]; exists {
			result[checkStr] = true
		} else if checkStr != "" {
			// GENAI_DISABLED: Reject unknown checks including COMPREHEND_PII
			fmt.Fprintf(os.Stderr, "Error: Unknown check type '%s'\n", checkStr)
			fmt.Fprintf(os.Stderr, "Available checks: CREDIT_CARD, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS, METADATA, PASSPORT, PERSON_NAME, PHONE, SECRETS, SOCIAL_MEDIA, SSN\n")
			os.Exit(1)
		}
	}

	return result
}

// GENAI_DISABLED: validateAWSCredentials checks if AWS credentials are properly configured
// func validateAWSCredentials(region string) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
// 	defer cancel()

// 	// Load AWS configuration
// 	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
// 	if err != nil {
// 		return fmt.Errorf("failed to load AWS configuration: %w", err)
// 	}

// 	// Create STS client to test credentials
// 	stsClient := sts.NewFromConfig(cfg)

// 	// Call GetCallerIdentity to validate credentials
// 	_, err = stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
// 	if err != nil {
// 		return fmt.Errorf("credentials are invalid or expired: %w", err)
// 	}

// 	return nil
// }

// handleWebMode validates web mode flags and starts the web server
func handleWebMode(port string, args []string, inputFile string) error {
	// Validate that no file arguments are provided with web mode
	if len(args) > 0 {
		return fmt.Errorf("--web flag cannot be used with file arguments\n"+
			"Web mode starts a server - use the web interface to upload files\n"+
			"Troubleshooting: Remove file arguments and access http://localhost:%s after startup", port)
	}

	// Validate that --file flag is not used with web mode
	if inputFile != "" {
		return fmt.Errorf("--web flag cannot be used with --file flag\n"+
			"Web mode starts a server - use the web interface to upload files\n"+
			"Troubleshooting: Remove --file flag and access http://localhost:%s after startup", port)
	}

	// Validate incompatible flags with web mode
	if err := validateWebModeFlags(); err != nil {
		return err
	}

	// Validate and find available port
	finalPort, err := findAvailablePort(port)
	if err != nil {
		return fmt.Errorf("port validation failed: %w\n"+
			"Troubleshooting: Try a different port with --port <number> or ensure no other services are using ports 8080-8089", err)
	}

	// Start web server
	return startWebServer(finalPort)
}

// validateWebModeFlags validates that incompatible flags are not used with --web
func validateWebModeFlags() error {
	var incompatibleFlags []string
	var troubleshooting []string

	// Check for output-related flags
	if isFlagSet("output") {
		incompatibleFlags = append(incompatibleFlags, "--output")
		troubleshooting = append(troubleshooting, "Web mode provides its own output interface")
	}

	if isFlagSet("format") {
		incompatibleFlags = append(incompatibleFlags, "--format")
		troubleshooting = append(troubleshooting, "Web mode handles output formatting automatically")
	}

	// Check for CLI-specific display flags
	if isFlagSet("show-match") {
		incompatibleFlags = append(incompatibleFlags, "--show-match")
		troubleshooting = append(troubleshooting, "Web mode has its own match display controls")
	}

	if isFlagSet("no-color") {
		incompatibleFlags = append(incompatibleFlags, "--no-color")
		troubleshooting = append(troubleshooting, "Web mode uses its own color scheme")
	}

	if isFlagSet("quiet") {
		incompatibleFlags = append(incompatibleFlags, "--quiet")
		troubleshooting = append(troubleshooting, "Web mode provides its own progress indicators")
	}

	// Check for processing mode flags
	if isFlagSet("preprocess-only") || isFlagSet("p") {
		if isFlagSet("preprocess-only") {
			incompatibleFlags = append(incompatibleFlags, "--preprocess-only")
		}
		if isFlagSet("p") {
			incompatibleFlags = append(incompatibleFlags, "-p")
		}
		troubleshooting = append(troubleshooting, "Web mode does not support preprocess-only mode")
	}

	// Check for redaction flags
	if isFlagSet("enable-redaction") {
		incompatibleFlags = append(incompatibleFlags, "--enable-redaction")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	if isFlagSet("redaction-output-dir") {
		incompatibleFlags = append(incompatibleFlags, "--redaction-output-dir")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	if isFlagSet("redaction-strategy") {
		incompatibleFlags = append(incompatibleFlags, "--redaction-strategy")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	if isFlagSet("redaction-audit-log") {
		incompatibleFlags = append(incompatibleFlags, "--redaction-audit-log")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	// Check for CLI help/info flags
	if isFlagSet("help") {
		incompatibleFlags = append(incompatibleFlags, "--help")
		troubleshooting = append(troubleshooting, "Web mode has built-in help - access it through the web interface")
	}

	if isFlagSet("version") {
		incompatibleFlags = append(incompatibleFlags, "--version")
		troubleshooting = append(troubleshooting, "Web mode displays version info in the top-right corner")
	}

	if isFlagSet("list-profiles") {
		incompatibleFlags = append(incompatibleFlags, "--list-profiles")
		troubleshooting = append(troubleshooting, "Web mode does not currently support configuration profiles")
	}

	// Check for CLI-specific suppression flags
	if isFlagSet("generate-suppressions") {
		incompatibleFlags = append(incompatibleFlags, "--generate-suppressions")
		troubleshooting = append(troubleshooting, "Web mode has its own suppression management interface")
	}

	if isFlagSet("show-suppressed") {
		incompatibleFlags = append(incompatibleFlags, "--show-suppressed")
		troubleshooting = append(troubleshooting, "Web mode has its own suppressed findings display")
	}

	// If any incompatible flags were found, return an error
	if len(incompatibleFlags) > 0 {
		errorMsg := fmt.Sprintf("--web flag cannot be used with the following flags: %s\n\n", strings.Join(incompatibleFlags, ", "))
		errorMsg += "Troubleshooting:\n"
		for i, tip := range troubleshooting {
			errorMsg += fmt.Sprintf("  %d. %s\n", i+1, tip)
		}
		errorMsg += "\nRemove the incompatible flags and try again."
		return fmt.Errorf("%s", errorMsg)
	}

	return nil
}

// findAvailablePort validates the requested port and finds an available port
func findAvailablePort(requestedPort string) (string, error) {
	// Validate port format and range
	port, err := validatePort(requestedPort)
	if err != nil {
		return "", err
	}

	// Check if requested port is available
	if isPortAvailable(port) {
		return port, nil
	}

	// If requested port is not available, try alternatives in range 8080-8089
	basePort := 8080
	for i := 0; i < 10; i++ {
		alternativePort := fmt.Sprintf("%d", basePort+i)
		if isPortAvailable(alternativePort) {
			fmt.Fprintf(os.Stderr, "Warning: Port %s is not available, using port %s instead\n", requestedPort, alternativePort)
			return alternativePort, nil
		}
	}

	return "", fmt.Errorf("no available ports found in range 8080-8089")
}

// validatePort validates that the port string is a valid port number
func validatePort(portStr string) (string, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port format '%s': must be a number", portStr)
	}

	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}

	if port < 1024 && os.Geteuid() != 0 {
		return "", fmt.Errorf("port %d requires root privileges (ports below 1024 are privileged)", port)
	}

	return portStr, nil
}

// printPrecommitError prints error messages optimized for pre-commit workflows
func printPrecommitError(precommitConfig *precommit.PrecommitConfig, errorMsg string, resolutionGuidance ...string) {
	if precommitConfig != nil && precommitConfig.QuietMode {
		// In pre-commit mode, provide concise, actionable error messages
		fmt.Fprintf(os.Stderr, "ferret-scan: %s\n", errorMsg)

		if len(resolutionGuidance) > 0 {
			fmt.Fprintf(os.Stderr, "Resolution: %s\n", resolutionGuidance[0])
		}

		// Add pre-commit specific guidance
		fmt.Fprintf(os.Stderr, "Pre-commit hook failed. Fix the issue above and retry your commit.\n")
	} else {
		// In normal mode, provide detailed error messages
		fmt.Fprintf(os.Stderr, "Error: %s\n", errorMsg)

		for _, guidance := range resolutionGuidance {
			fmt.Fprintf(os.Stderr, "%s\n", guidance)
		}
	}
}

// isPortAvailable checks if a port is available for binding
func isPortAvailable(port string) bool {
	address := fmt.Sprintf(":%s", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// startWebServer starts the web server on the specified port with timeout and resilience
func startWebServer(port string) error {
	// Import web server package
	webServer := web.NewWebServer(port)

	// Start the web server (this will block)
	return webServer.Start()
}

// isTerminal checks if the file descriptor is a terminal
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
