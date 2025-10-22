// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package help

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
)

// CheckInfo contains standardized information about a check
type CheckInfo struct {
	Name                string             // Name of the check (e.g., "CREDIT_CARD")
	ShortDescription    string             // Short description for the checks list
	DetailedDescription string             // Detailed description of what the check does
	Patterns            []string           // Patterns the check looks for
	SupportedFormats    []string           // Formats or types supported by the check
	ConfidenceFactors   []ConfidenceFactor // Factors affecting confidence
	PositiveKeywords    []string           // Keywords that increase confidence
	NegativeKeywords    []string           // Keywords that decrease confidence
	ConfigurationInfo   string             // Information about how to configure the check
	Examples            []string           // Usage examples
}

// ConfidenceFactor represents a factor that affects confidence scoring
type ConfidenceFactor struct {
	Name        string  // Name of the factor
	Description string  // Description of the factor
	Weight      float64 // Weight of the factor in the confidence score (percentage)
}

// Provider defines the interface for help content providers
type Provider interface {
	GetCheckInfo() CheckInfo
}

// System manages help content for the application
type System struct {
	providers map[string]Provider
	noColor   bool
	colors    map[string]*color.Color
}

// NewSystem creates a new help system
func NewSystem(noColor bool) *System {
	// Disable colors if requested
	if noColor {
		color.NoColor = true
	}

	return &System{
		providers: make(map[string]Provider),
		noColor:   noColor,
		colors: map[string]*color.Color{
			"title":    color.New(color.FgWhite, color.Bold),
			"subtitle": color.New(color.FgCyan, color.Bold),
			"header":   color.New(color.FgBlue, color.Bold),
			"item":     color.New(color.FgCyan),
			"emphasis": color.New(color.FgWhite, color.Bold),
			"positive": color.New(color.FgGreen),
			"negative": color.New(color.FgRed),
			"warning":  color.New(color.FgYellow),
			"example":  color.New(color.FgMagenta),
		},
	}
}

// RegisterProvider adds a help provider to the system
func (h *System) RegisterProvider(provider Provider) {
	info := provider.GetCheckInfo()
	h.providers[strings.ToLower(info.Name)] = provider
}

// ShowGeneralHelp displays general help information
func (h *System) ShowGeneralHelp() {
	h.colors["title"].Println("Ferret Scan - Sensitive Data Detection Tool")
	fmt.Println("===========================================")
	fmt.Println()
	h.colors["header"].Println("USAGE:")
	fmt.Println("  ferret-scan --file <path-to-file> [options]")
	fmt.Println("  ferret-scan --web [--port <port>]  # Web server mode")
	fmt.Println()

	h.colors["header"].Println("OPTIONS:")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  --file\t<path>\tPath to the input file or directory to scan (required)")
	fmt.Fprintln(w, "  --config\t<path>\tPath to configuration file (YAML)")
	fmt.Fprintln(w, "  --profile\t<name>\tProfile name to use from config file")
	fmt.Fprintln(w, "  --list-profiles\t\tList available profiles in config file")
	fmt.Fprintln(w, "  --recursive\t\tRecursively scan directories")
	fmt.Fprintln(w, "  --format\t<format>\tOutput format: text, json, csv, yaml, junit, gitlab-sast, sarif (default: text)")
	fmt.Fprintln(w, "\t\t\tNote: gitlab-sast generates GitLab Security Report format for integration with GitLab Security Dashboard")
	fmt.Fprintln(w, "\t\t\tNote: sarif generates SARIF 2.1.0 format for integration with GitHub Security and other SARIF-compatible tools")
	fmt.Fprintln(w, "  --checks\t<checks>\tSpecific checks to run: CREDIT_CARD,EMAIL,INTELLECTUAL_PROPERTY,IP_ADDRESS,METADATA,PASSPORT,PERSON_NAME,PHONE,SECRETS,SOCIAL_MEDIA,SSN,all (default: all)")
	fmt.Fprintln(w, "\t\t\tNote: INTELLECTUAL_PROPERTY requires configuration for internal URL detection")
	fmt.Fprintln(w, "\t\t\tNote: METADATA validator now includes enhanced preprocessor-aware validation for images, documents, audio, and video")
	// GENAI_DISABLED: COMPREHEND_PII reference removed from help
	// fmt.Fprintln(w, "\t\t\tNote: COMPREHEND_PII auto-enabled with --enable-genai, requires AWS credentials")
	fmt.Fprintln(w, "  --confidence\t<levels>\tConfidence levels to display: high,medium,low,all (default: all)")
	fmt.Fprintln(w, "  --verbose\t\tDisplay detailed information for each finding")
	fmt.Fprintln(w, "  --debug\t\tEnable debug logging to show preprocessing, content routing, and validation flow")
	fmt.Fprintln(w, "  --output\t<path>\tPath to output file (if not specified, output to stdout)")
	fmt.Fprintln(w, "  --no-color\t\tDisable colored output")
	fmt.Fprintln(w, "  --show-match\t\tDisplay the actual matched text in findings (otherwise shows [HIDDEN])")
	fmt.Fprintln(w, "  --enable-preprocessors\t\tEnable text extraction from documents (PDF, Office files) (default: true, use --enable-preprocessors=false to disable)")
	fmt.Fprintln(w, "  --preprocess-only, -p\t\tOutput preprocessed text and exit (no validation or redaction)")
	// GENAI_DISABLED: GenAI-related command line options
	// fmt.Fprintln(w, "  --enable-genai\t\tEnable AI-powered services: Textract OCR, Transcribe, Comprehend PII (AWS costs apply)")
	// fmt.Fprintln(w, "  --genai-services\t<services>\tGenAI services to use: textract,transcribe,comprehend,all (default: all)")
	// fmt.Fprintln(w, "  --textract-region\t<region>\tAWS region for Textract service (default: us-east-1)")
	// fmt.Fprintln(w, "  --transcribe-bucket\t<bucket>\tS3 bucket name for Transcribe audio uploads (optional)")
	fmt.Fprintln(w, "  --suppression-file\t<path>\tPath to suppression configuration file (default: .ferret-scan-suppressions.yaml)")
	fmt.Fprintln(w, "  --generate-suppressions\t\tGenerate suppression rules for all findings (disabled by default)")
	// GENAI_DISABLED: Cost control options for GenAI services
	// fmt.Fprintln(w, "  --max-cost\t<amount>\tMaximum cost limit for GenAI services (default: no limit)")
	// fmt.Fprintln(w, "  --estimate-only\t\tShow cost estimate and exit without processing")
	fmt.Fprintln(w, "  --quiet\t\tSuppress progress output (useful for scripts and CI/CD)")
	fmt.Fprintln(w, "  --pre-commit-mode\t\tEnable pre-commit optimizations (quiet mode, no colors, appropriate exit codes)")
	fmt.Fprintln(w, "  --enable-redaction\t\tEnable redaction of sensitive data found in documents")
	fmt.Fprintln(w, "  --redaction-output-dir\t<path>\tDirectory where redacted files will be stored (default: ./redacted)")
	fmt.Fprintln(w, "  --redaction-strategy\t<strategy>\tDefault redaction strategy: simple, format_preserving, or synthetic (default: format_preserving)")
	fmt.Fprintln(w, "  --redaction-audit-log\t<path>\tPath to save redaction audit log file (JSON format for compliance)")
	fmt.Fprintln(w, "  --web\t\tStart web server mode instead of CLI scanning")
	fmt.Fprintln(w, "  --port\t<port>\tPort for web server (default: 8080, only used with --web)")
	fmt.Fprintln(w, "  --version\t\tShow version information")
	fmt.Fprintln(w, "  --help\t\tShow this help message")
	fmt.Fprintln(w, "  --help checks\t\tList all available checks")
	fmt.Fprintln(w, "  --help <check>\t\tShow detailed help for a specific check")
	w.Flush()

	fmt.Println()
	h.colors["header"].Println("EXAMPLES:")
	fmt.Println("  Basic Usage:")
	h.colors["example"].Println("    ferret-scan --file sample.txt")
	h.colors["example"].Println("    ferret-scan --file sample.txt --confidence high,medium --verbose")
	fmt.Println("  Configuration and Profiles:")
	h.colors["example"].Println("    ferret-scan --file . --config ferret.yaml --profile production")
	h.colors["example"].Println("    ferret-scan --list-profiles --config ferret.yaml")
	// GENAI_DISABLED: GenAI examples and cost control examples
	// fmt.Println()
	// h.colors["header"].Println("GenAI Examples (Textract OCR + Transcribe + Comprehend PII):")
	// h.colors["warning"].Println("  ⚠️  WARNING: GenAI mode sends files/text to AWS and incurs costs")
	// h.colors["example"].Println("  ferret-scan --file scanned-document.pdf --enable-genai  # OCR + PII detection")
	// h.colors["example"].Println("  ferret-scan --file document.txt --enable-genai  # Comprehend PII detection")
	// h.colors["example"].Println("  ferret-scan --file image.png --enable-genai --textract-region us-west-2")
	// h.colors["example"].Println("  ferret-scan --file audio.mp3 --enable-genai --transcribe-bucket my-bucket")
	// h.colors["example"].Println("  ferret-scan --file image.jpg --enable-genai --genai-services textract")
	// h.colors["example"].Println("  ferret-scan --file audio.mp3 --enable-genai --genai-services textract,transcribe")
	// h.colors["example"].Println("  ferret-scan --file *.pdf --enable-genai --format json")
	// h.colors["example"].Println("  ferret-scan --file data.txt --enable-genai --checks COMPREHEND_PII  # PII only")
	// fmt.Println()
	// h.colors["header"].Println("Cost Control Examples:")
	// h.colors["example"].Println("  ferret-scan --file document.pdf --enable-genai --estimate-only  # Show cost estimate only")
	// h.colors["example"].Println("  ferret-scan --file *.pdf --enable-genai --max-cost 5.00  # Set spending limit")
	// h.colors["example"].Println("  ferret-scan --file document.txt --enable-genai --max-cost 0.10  # Low cost limit")

	fmt.Println()
	h.colors["header"].Println("Redaction Examples:")
	h.colors["example"].Println("  ferret-scan --file document.txt --enable-redaction  # Redact sensitive data")
	h.colors["example"].Println("  ferret-scan --file *.pdf --enable-redaction --redaction-output-dir ./safe-docs")

	fmt.Println()
	h.colors["header"].Println("Web Server Examples:")
	h.colors["example"].Println("  ferret-scan --web  # Start web server on default port")
	h.colors["example"].Println("  ferret-scan --web --port 9000  # Start web server on custom port")

	fmt.Println()
	h.colors["header"].Println("CONFIGURATION:")
	fmt.Println("  Default config: ~/.ferret-scan/config.yaml")
	fmt.Println("  Project config: ferret.yaml or .ferret-scan.yaml (in current directory)")
	fmt.Println("  Environment: FERRET_CONFIG_DIR - Override config directory")
	fmt.Println()
	h.colors["header"].Println("SUPPORT:")
	fmt.Println("  Developers: Andrea Di Fabio (adifabio@amazon.com), Lee Myers (mlmyers@amazon.com)")
	fmt.Println("  Slack Channel: ferret-scan-interest")
}

// ShowChecksHelp displays information about all available checks
func (h *System) ShowChecksHelp() {
	h.colors["title"].Println("Available Checks in Ferret Scan")
	fmt.Println("==============================")
	fmt.Println()
	fmt.Println("The following checks are available for detecting sensitive data:")
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	h.colors["header"].Fprintln(w, "  CHECK\tDESCRIPTION")
	h.colors["header"].Fprintln(w, "  -----\t-----------")

	// Get all check names and sort them alphabetically
	var checkNames []string
	for _, provider := range h.providers {
		info := provider.GetCheckInfo()
		checkNames = append(checkNames, info.Name)
	}

	// Sort alphabetically
	for i := 0; i < len(checkNames); i++ {
		for j := i + 1; j < len(checkNames); j++ {
			if checkNames[i] > checkNames[j] {
				checkNames[i], checkNames[j] = checkNames[j], checkNames[i]
			}
		}
	}

	// Display in alphabetical order
	for _, checkName := range checkNames {
		for _, provider := range h.providers {
			info := provider.GetCheckInfo()
			if info.Name == checkName {
				fmt.Fprintf(w, "  ")
				h.colors["emphasis"].Fprintf(w, "%s", info.Name)
				fmt.Fprintf(w, "\t%s\n", info.ShortDescription)
				break
			}
		}
	}
	w.Flush()

	fmt.Println()
	fmt.Println("For detailed information about a specific check, use:")
	h.colors["example"].Println("  ferret-scan --help <check>")
	fmt.Println()

	// Get the first available check name for the example
	var exampleCheck string
	if len(h.providers) > 0 {
		// Find the first check name
		for _, provider := range h.providers {
			info := provider.GetCheckInfo()
			exampleCheck = info.Name
			break
		}
	} else {
		// Fallback if no checks are available
		exampleCheck = "<check>"
	}

	fmt.Println("Example:")
	h.colors["example"].Printf("  ferret-scan --help %s\n", exampleCheck)
}

// ShowCheckHelp displays detailed help for a specific check
func (h *System) ShowCheckHelp(checkName string) bool {
	provider, exists := h.providers[strings.ToLower(checkName)]
	if !exists {
		h.colors["negative"].Printf("Error: Check '%s' not found.\n", checkName)
		fmt.Println("Use 'ferret-scan --help checks' to see a list of available checks.")
		return false
	}

	info := provider.GetCheckInfo()

	h.colors["title"].Printf("%s Check\n", info.Name)
	fmt.Println(strings.Repeat("=", len(info.Name)+6))
	fmt.Println()
	fmt.Println(info.DetailedDescription)
	fmt.Println()

	// Display patterns
	if len(info.Patterns) > 0 {
		h.colors["header"].Println("PATTERNS DETECTED:")
		for _, pattern := range info.Patterns {
			fmt.Print("  - ")
			h.colors["item"].Println(pattern)
		}
		fmt.Println()
	}

	// Display supported formats
	if len(info.SupportedFormats) > 0 {
		h.colors["header"].Println("SUPPORTED FORMATS:")
		for _, format := range info.SupportedFormats {
			fmt.Print("  - ")
			h.colors["item"].Println(format)
		}
		fmt.Println()
	}

	// Display confidence scoring
	h.colors["header"].Println("CONFIDENCE SCORING:")

	// Group factors by category
	categories := make(map[string][]ConfidenceFactor)
	for _, factor := range info.ConfidenceFactors {
		category := "Other"
		if strings.Contains(strings.ToLower(factor.Name), "format") ||
			strings.Contains(strings.ToLower(factor.Name), "length") ||
			strings.Contains(strings.ToLower(factor.Name), "pattern") ||
			strings.Contains(strings.ToLower(factor.Name), "valid") {
			category = "Format Validation"
		} else if strings.Contains(strings.ToLower(factor.Name), "test") ||
			strings.Contains(strings.ToLower(factor.Name), "sequential") {
			category = "Pattern Analysis"
		} else if strings.Contains(strings.ToLower(factor.Name), "context") ||
			strings.Contains(strings.ToLower(factor.Name), "keyword") {
			category = "Contextual Analysis"
		}
		categories[category] = append(categories[category], factor)
	}

	// Print factors by category
	categoryOrder := []string{"Format Validation", "Pattern Analysis", "Contextual Analysis", "Other"}

	totalWeight := 0.0
	for _, category := range categoryOrder {
		factors, exists := categories[category]
		if !exists || len(factors) == 0 {
			continue
		}

		// Calculate category weight
		categoryWeight := 0.0
		for _, factor := range factors {
			categoryWeight += factor.Weight
		}

		h.colors["emphasis"].Printf("1. %s ", category)
		fmt.Printf("(%.0f%% of base score):\n", categoryWeight)
		for _, factor := range factors {
			fmt.Printf("   - ")
			h.colors["item"].Printf("%s ", factor.Name)
			fmt.Printf("(%.0f%%): %s\n", factor.Weight, factor.Description)
		}

		totalWeight += categoryWeight
		fmt.Println()
	}

	// Display contextual analysis
	if len(info.PositiveKeywords) > 0 || len(info.NegativeKeywords) > 0 {
		h.colors["subtitle"].Println("Contextual Analysis (up to +25% or -50% adjustment):")

		if len(info.PositiveKeywords) > 0 {
			fmt.Print("   - Positive keywords (+5% each): ")
			h.colors["positive"].Printf("%s",
				strings.Join(info.PositiveKeywords[:min(5, len(info.PositiveKeywords))], ", "))
			if len(info.PositiveKeywords) > 5 {
				fmt.Println("\n     and others...")
			} else {
				fmt.Println()
			}
		}

		if len(info.NegativeKeywords) > 0 {
			fmt.Print("   - Negative keywords (-10% each): ")
			h.colors["negative"].Printf("%s",
				strings.Join(info.NegativeKeywords[:min(5, len(info.NegativeKeywords))], ", "))
			if len(info.NegativeKeywords) > 5 {
				fmt.Println("\n     and others...")
			} else {
				fmt.Println()
			}
		}
		fmt.Println()
	}

	// Display confidence levels
	h.colors["header"].Println("Confidence Levels:")
	fmt.Print("- ")
	h.colors["negative"].Print("HIGH")
	fmt.Println(" (90-100%): Very likely to be sensitive data")
	fmt.Print("- ")
	h.colors["warning"].Print("MEDIUM")
	fmt.Println(" (60-89%): Possibly sensitive data")
	fmt.Print("- ")
	h.colors["positive"].Print("LOW")
	fmt.Println(" (0-59%): Likely not sensitive data or a false positive")
	fmt.Println()

	// Display configuration information if available
	if info.ConfigurationInfo != "" {
		h.colors["header"].Println("CONFIGURATION:")
		fmt.Println(info.ConfigurationInfo)
		fmt.Println()
	}

	// Display examples
	if len(info.Examples) > 0 {
		h.colors["header"].Println("EXAMPLES:")
		for _, example := range info.Examples {
			fmt.Print("  ")
			h.colors["example"].Println(example)
		}
	}

	return true
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
