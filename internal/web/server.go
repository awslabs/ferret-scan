// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/config"
	"ferret-scan/internal/core"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	formatterShared "ferret-scan/internal/formatters/shared"
	"ferret-scan/internal/paths"
	"ferret-scan/internal/platform"
	"ferret-scan/internal/suppressions"
	"ferret-scan/internal/version"

	// Import formatters to register them
	_ "ferret-scan/internal/formatters/csv"
	_ "ferret-scan/internal/formatters/gitlab-sast"
	_ "ferret-scan/internal/formatters/json"
	_ "ferret-scan/internal/formatters/junit"
	_ "ferret-scan/internal/formatters/sarif"
	_ "ferret-scan/internal/formatters/text"
	_ "ferret-scan/internal/formatters/yaml"
)

// WebServer represents the web server instance
type WebServer struct {
	port   string
	server *http.Server
}

// ScanResponse represents the response from a scan operation (wraps CLI JSON output)
type ScanResponse struct {
	Success    bool                        `json:"success"`
	Results    []formatterShared.JSONMatch `json:"results"`
	Suppressed []detector.SuppressedMatch  `json:"suppressed,omitempty"`
	Error      string                      `json:"error,omitempty"`
}

// NewWebServer creates a new web server instance
func NewWebServer(port string) *WebServer {
	return &WebServer{
		port: port,
	}
}

// Start starts the web server
func (ws *WebServer) Start() error {
	// Setup routes with error handling
	if err := ws.setupRoutesWithValidation(); err != nil {
		return fmt.Errorf("failed to setup web server routes: %w\n"+
			"Troubleshooting: Ensure the web server components are properly initialized", err)
	}

	// Try ports starting from the specified port
	var lastError error
	for i := 0; i < 10; i++ {
		currentPort := ws.port
		if i > 0 || ws.port == "8080" {
			currentPort = fmt.Sprintf("%d", 8080+i)
		}

		// Test if port is available first
		listener, err := net.Listen("tcp", ":"+currentPort)
		if err != nil {
			lastError = err
			if i == 0 {
				fmt.Printf("Port %s is not available, trying alternative ports...\n", currentPort)
			}
			continue // Port is busy, try next one
		}
		listener.Close()

		// Create secure server with timeout configurations
		ws.server = ws.createSecureServer(currentPort)

		fmt.Printf("Ferret Scan Web UI started on port %s\n", currentPort)
		fmt.Printf("Access URLs:\n")
		fmt.Printf("Local:     http://localhost:%s\n", currentPort)
		fmt.Printf("Container: Use your mapped port (e.g., -p 8082:%s → http://localhost:8082)\n", currentPort)

		// Start the server with enhanced error handling
		if err := ws.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			lastError = err
			fmt.Printf("Server on port %s failed: %v\n", currentPort, err)
			continue // Try next port
		}
		return nil
	}

	// If we get here, no ports were available
	return fmt.Errorf("could not find an available port in range 8080-8089\n"+
		"Last error: %v\n"+
		"Troubleshooting:\n"+
		"  1. Check if other services are using these ports: netstat -an | grep :808\n"+
		"  2. Try a specific port with --port <number>\n"+
		"  3. Ensure you have permission to bind to the requested port\n"+
		"  4. Check firewall settings if accessing from remote machines", lastError)
}

// Stop stops the web server
func (ws *WebServer) Stop() error {
	if ws.server != nil {
		return ws.server.Close()
	}
	return nil
}

// setupRoutesWithValidation configures all HTTP route handlers with validation
func (ws *WebServer) setupRoutesWithValidation() error {
	// Validate template availability
	if err := ws.validateTemplate(); err != nil {
		return fmt.Errorf("template validation failed: %w", err)
	}

	// Setup routes
	ws.setupRoutes()
	return nil
}

// validateTemplate ensures the web template is available
func (ws *WebServer) validateTemplate() error {
	// Try to load template to ensure it's available
	templateContent := ws.loadTemplate()
	if len(templateContent) == 0 {
		return fmt.Errorf("web template is empty or could not be loaded\n" +
			"Troubleshooting: Ensure web/template.html exists in the current directory")
	}

	// Check if we're using the fallback template
	if strings.Contains(templateContent, "Template not found") {
		return fmt.Errorf("web template not found, using fallback\n" +
			"Troubleshooting: Ensure web/template.html exists in the current directory")
	}

	return nil
}

// setupRoutes configures all HTTP route handlers - MINIMAL ROUTES ONLY
func (ws *WebServer) setupRoutes() {
	http.HandleFunc("/", ws.serveHome)
	http.HandleFunc("/health", ws.handleHealth)
	http.HandleFunc("/scan", ws.handleScan)
	http.HandleFunc("/export", ws.handleExport)

	// Static asset serving with security validation
	http.HandleFunc("/logo", ws.serveLogo)
	http.HandleFunc("/docs/", ws.serveDocs)

	// Suppression management endpoints (delegate to CLI suppression system)
	http.HandleFunc("/suppressions", ws.handleSuppressions)
	http.HandleFunc("/suppressions/create", ws.handleSuppressionsCreate)
	http.HandleFunc("/suppressions/edit", ws.handleSuppressionsEdit)
	http.HandleFunc("/suppressions/remove", ws.handleSuppressionsRemove)
	http.HandleFunc("/suppressions/enable", ws.handleSuppressionsEnable)
	http.HandleFunc("/suppressions/disable", ws.handleSuppressionsDisable)
	http.HandleFunc("/suppressions/bulk-enable", ws.handleSuppressionsBulkEnable)
	http.HandleFunc("/suppressions/bulk-disable", ws.handleSuppressionsBulkDisable)
	http.HandleFunc("/suppressions/bulk-delete", ws.handleSuppressionsBulkDelete)
	http.HandleFunc("/suppressions/bulk-create", ws.handleSuppressionsBulkCreate)
	http.HandleFunc("/suppressions/download", ws.handleSuppressionsDownload)
	http.HandleFunc("/suppressions/check-hash", ws.handleSuppressionsCheckHash)
}

// createSecureServer creates an HTTP server with security timeouts
func (ws *WebServer) createSecureServer(port string) *http.Server {
	return &http.Server{
		Addr: ":" + port,
		// Timeout for reading request headers (prevents slow header attacks)
		ReadHeaderTimeout: 15 * time.Second,
		// Timeout for reading entire request
		ReadTimeout: 30 * time.Second,
		// Timeout for writing response
		WriteTimeout: 30 * time.Second,
		// Timeout for idle connections
		IdleTimeout: 60 * time.Second,
	}
}

// serveHome serves the main HTML page
func (ws *WebServer) serveHome(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Load template
	htmlContent := ws.loadTemplate()

	responseWriter.Header().Set("Content-Type", "text/html")
	responseWriter.WriteHeader(http.StatusOK)
	responseWriter.Write([]byte(htmlContent))
}

// loadTemplate loads the HTML template from file with fallback to embedded template
func (ws *WebServer) loadTemplate() string {
	// Try to load from web/template.html first (use platform-aware path joining)
	templatePath := paths.JoinPath("web", "template.html")
	cleanTemplatePath := filepath.Clean(templatePath)
	if content, err := os.ReadFile(cleanTemplatePath); err == nil {
		return string(content)
	}

	// Try to load from current directory
	cleanCurrentPath := filepath.Clean("template.html")
	if content, err := os.ReadFile(cleanCurrentPath); err == nil {
		return string(content)
	}

	// Fallback to embedded template
	return ws.getEmbeddedTemplate()
}

// getEmbeddedTemplate returns embedded fallback template
func (ws *WebServer) getEmbeddedTemplate() string {
	return `<!DOCTYPE html>
<html><head><title>Ferret Scan</title></head>
<body><h1>Ferret Scan</h1><p>Template not found. Please ensure template.html is in the same directory as the web server.</p></body></html>`
}

// handleHealth provides a health check endpoint with CLI version information
func (ws *WebServer) handleHealth(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get version information from CLI version system
	versionInfo := version.Full()

	// Create health response with identical format as current ferret-web
	healthData := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"service":   "ferret-scan-web",
		"version":   versionInfo["version"], // Short version for compatibility
		"build_info": map[string]interface{}{
			"version":    versionInfo["version"],
			"commit":     versionInfo["commit"],
			"build_date": versionInfo["buildDate"],
			"go_version": versionInfo["goVersion"],
			"platform":   versionInfo["platform"],
		},
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(http.StatusOK)
	json.NewEncoder(responseWriter).Encode(healthData)
}

// handleScan processes file uploads and performs scanning using CLI logic
func (ws *WebServer) handleScan(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form
	err := request.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		ws.sendError(responseWriter, "Failed to parse form data")
		return
	}

	// Extract parameters (same as CLI flags)
	confidence := request.FormValue("confidence")
	if confidence == "" {
		confidence = "all" // CLI default: show all levels
	}

	checks := request.FormValue("checks")
	if checks == "" {
		checks = "all" // CLI default
	}

	verbose := request.FormValue("verbose") == "true"
	recursive := request.FormValue("recursive") == "true"

	// Get uploaded files
	files := request.MultipartForm.File["files"]
	if len(files) == 0 {
		ws.sendError(responseWriter, "No files uploaded")
		return
	}

	// Process all uploaded files using CLI scanning logic
	var allMatches []detector.Match
	var suppressedMatches []detector.SuppressedMatch
	suppressedCount := 0

	for i, fileHeader := range files {
		matches, suppressed, suppCount, err := ws.processUploadedFileWithCLILogic(fileHeader, i, confidence, checks, verbose, recursive)
		if err != nil {
			ws.sendError(responseWriter, err.Error())
			return
		}
		allMatches = append(allMatches, matches...)
		suppressedMatches = append(suppressedMatches, suppressed...)
		suppressedCount += suppCount
	}

	// Use CLI's JSON formatter with CLI's confidence parsing
	// Always use verbose for web UI to include context fields needed for suppression creation
	formatterOptions := formatters.FormatterOptions{
		ConfidenceLevel: core.ParseConfidenceLevels(confidence),
		Verbose:         true, // Always verbose for web UI to include context fields
	}

	// Use CLI's exact JSON formatting
	jsonOutput, err := formatters.Export("json", allMatches, suppressedMatches, formatterOptions)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to format results: %v", err))
		return
	}

	// Parse the CLI JSON output - handle both array and object formats
	var cliResponse formatterShared.JSONResponse

	// First try to unmarshal as JSONResponse object
	if err := json.Unmarshal([]byte(jsonOutput), &cliResponse); err != nil {
		// If that fails, try as array (empty results case)
		var resultsArray []formatterShared.JSONMatch
		if err2 := json.Unmarshal([]byte(jsonOutput), &resultsArray); err2 != nil {
			ws.sendError(responseWriter, fmt.Sprintf("Failed to parse CLI output: %v", err))
			return
		}
		// Convert array to JSONResponse format
		cliResponse = formatterShared.JSONResponse{
			Results:    resultsArray,
			Suppressed: suppressedMatches,
		}
	}

	// Return the exact CLI structure wrapped in success response
	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(ScanResponse{
		Success:    true,
		Results:    cliResponse.Results,
		Suppressed: cliResponse.Suppressed,
	})
}

// processUploadedFileWithCLILogic handles user file uploads using full CLI scanning logic
func (ws *WebServer) processUploadedFileWithCLILogic(uploadedFile *multipart.FileHeader, fileIndex int, confidence, checks string, verbose, recursive bool) ([]detector.Match, []detector.SuppressedMatch, int, error) {
	// Open uploaded file
	file, err := uploadedFile.Open()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to open file %s: %v", uploadedFile.Filename, err)
	}
	defer file.Close()

	// Create secure temp file with proper extension using platform-aware temp directory
	tempDir := paths.GetTempDir()
	tempFile, err := os.CreateTemp(tempDir, fmt.Sprintf("ferret_upload_%d_%d_*.%s", time.Now().Unix(), fileIndex, ws.getFileExtension(uploadedFile.Filename)))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to create temporary file in %s: %v", tempDir, err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Copy uploaded file content to temporary file with size limit protection
	const maxFileSize = 100 << 20 // 100MB limit to prevent decompression bombs
	limitedReader := io.LimitReader(file, maxFileSize)
	_, err = io.Copy(tempFile, limitedReader)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to copy file content: %v", err)
	}

	// Normalize the temporary file path for the current platform
	normalizedTempPath := paths.NormalizePath(tempFile.Name())

	// Run full CLI scanning logic on this file with original filename
	return ws.runFullCLIScan(normalizedTempPath, uploadedFile.Filename, confidence, checks, verbose, recursive)
}

// runFullCLIScan executes the full CLI scanning logic with configuration and suppression support
func (ws *WebServer) runFullCLIScan(filePath, originalFilename, confidence, checks string, verbose, recursive bool) ([]detector.Match, []detector.SuppressedMatch, int, error) {
	// Load configuration (same as CLI)
	cfg := ws.loadConfiguration("")

	// Parse checks parameter (same as CLI)
	var checksSlice []string
	if checks != "" && checks != "all" {
		checksSlice = strings.Split(checks, ",")
	}

	// Resolve final configuration (same logic as CLI)
	_ = ws.resolveWebConfiguration(cfg, confidence, checks, verbose, recursive)

	// Initialize suppression manager (same as CLI)
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to initialize suppression manager: %v", err)
	}

	// Use the core scanning function that CLI uses
	scanConfig := core.ScanConfig{
		FilePath:            filePath,
		Checks:              checksSlice,
		Debug:               false, // Web doesn't use debug mode
		Verbose:             verbose,
		Recursive:           recursive,
		EnablePreprocessors: true,
		EnableRedaction:     false, // Web doesn't support redaction
		RedactionStrategy:   "",
		RedactionOutputDir:  "",
		Config:              cfg,
		Profile:             nil, // Web doesn't use profiles
	}

	result, err := core.ScanFile(scanConfig)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("scanning failed: %v", err)
	}

	// Update filenames to use original filename (critical for suppression matching)
	// Keep original filename for suppression matching first
	for i := range result.Matches {
		result.Matches[i].Filename = originalFilename
	}

	// Apply suppressions (same logic as CLI) - MUST happen before filename sanitization
	var unsuppressedMatches []detector.Match
	var suppressedMatches []detector.SuppressedMatch
	suppressedCount := 0

	for _, match := range result.Matches {
		if suppressed, rule := suppressionManager.IsSuppressed(match); suppressed {
			suppressedCount++
			// Collect suppressed findings
			suppressedMatches = append(suppressedMatches, detector.SuppressedMatch{
				Match:        match,
				SuppressedBy: rule.ID,
				RuleReason:   rule.Reason,
				ExpiresAt:    rule.ExpiresAt,
				Expired:      rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt),
			})
		} else {
			unsuppressedMatches = append(unsuppressedMatches, match)
		}
	}

	// NOW sanitize filenames for safe web display (after suppression matching)
	safeFilename := ws.sanitizeFilenameForDisplay(originalFilename)
	for i := range unsuppressedMatches {
		unsuppressedMatches[i].Filename = safeFilename
	}
	for i := range suppressedMatches {
		suppressedMatches[i].Match.Filename = safeFilename
	}

	return unsuppressedMatches, suppressedMatches, suppressedCount, nil
}

// handleExport exports scan results in the requested format
func (ws *WebServer) handleExport(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var exportRequest struct {
		Format    string                      `json:"format"`
		Results   []formatterShared.JSONMatch `json:"results"`
		ShowMatch bool                        `json:"show_match"`
		Verbose   bool                        `json:"verbose"`
	}

	if err := json.NewDecoder(request.Body).Decode(&exportRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Validate format
	if exportRequest.Format == "" {
		ws.sendError(responseWriter, "Format is required")
		return
	}

	// Check if format is supported
	formatter, exists := formatters.Get(exportRequest.Format)
	if !exists {
		availableFormats := formatters.List()
		ws.sendError(responseWriter, fmt.Sprintf("Unsupported format '%s'. Available formats: %s",
			exportRequest.Format, strings.Join(availableFormats, ", ")))
		return
	}

	// Convert JSONMatch back to detector.Match for formatting
	var matches []detector.Match
	for _, jsonMatch := range exportRequest.Results {
		match := detector.Match{
			Text:       jsonMatch.Text,
			LineNumber: jsonMatch.LineNumber,
			Type:       jsonMatch.Type,
			Confidence: jsonMatch.Confidence,
			Filename:   jsonMatch.Filename,
			Validator:  jsonMatch.Validator,
			Metadata:   jsonMatch.Metadata,
		}

		// Convert context fields if present
		if jsonMatch.FullLine != "" || jsonMatch.BeforeText != "" || jsonMatch.AfterText != "" {
			match.Context = detector.ContextInfo{
				BeforeText: jsonMatch.BeforeText,
				AfterText:  jsonMatch.AfterText,
				FullLine:   jsonMatch.FullLine,
			}
		}

		matches = append(matches, match)
	}

	// Set up formatter options
	formatterOptions := formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true}, // Export all levels
		Verbose:         exportRequest.Verbose,
		NoColor:         true, // Always disable color for exports
		ShowMatch:       exportRequest.ShowMatch,
	}

	// Format the results
	output, err := formatter.Format(matches, []detector.SuppressedMatch{}, formatterOptions)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to format results: %v", err))
		return
	}

	// Get format info using the centralized GetFormatInfo function
	formatInfo := formatters.GetFormatInfo(exportRequest.Format)
	contentType := formatInfo.MimeType
	fileExtension := formatInfo.Extension

	// Generate filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("ferret-scan-results-%s%s", timestamp, fileExtension)

	// Set response headers
	responseWriter.Header().Set("Content-Type", contentType)
	responseWriter.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	responseWriter.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	responseWriter.Header().Set("Pragma", "no-cache")
	responseWriter.Header().Set("Expires", "0")

	// Write the formatted output
	responseWriter.WriteHeader(http.StatusOK)
	responseWriter.Write([]byte(output))
}

// Utility functions

// getFileExtension extracts file extension from filename with sanitization
func (ws *WebServer) getFileExtension(filename string) string {
	if ext := filepath.Ext(filename); ext != "" {
		// Sanitize extension to prevent directory traversal or injection
		safeExt := sanitizeUserInput(strings.TrimPrefix(ext, "."), 10)
		// Only allow alphanumeric extensions
		if safeExt != "" && isAlphanumeric(safeExt) {
			return safeExt
		}
	}
	return "tmp"
}

// isAlphanumeric checks if string contains only alphanumeric characters
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// sendError sends an error response with enhanced error information
func (ws *WebServer) sendError(responseWriter http.ResponseWriter, message string) {
	ws.sendErrorWithStatus(responseWriter, message, http.StatusBadRequest)
}

// sendErrorWithStatus sends an error response with a specific HTTP status code
func (ws *WebServer) sendErrorWithStatus(responseWriter http.ResponseWriter, message string, statusCode int) {
	// Add troubleshooting information for common errors
	enhancedMessage := ws.enhanceErrorMessage(message, statusCode)

	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(statusCode)
	json.NewEncoder(responseWriter).Encode(ScanResponse{
		Success: false,
		Error:   enhancedMessage,
	})
}

// enhanceErrorMessage adds troubleshooting information to error messages
func (ws *WebServer) enhanceErrorMessage(message string, statusCode int) string {
	// Add context-specific troubleshooting tips
	switch {
	case strings.Contains(message, "Failed to parse form data"):
		return message + "\nTroubleshooting: Ensure you're uploading files using multipart/form-data with 'files' field name"
	case strings.Contains(message, "No files uploaded"):
		return message + "\nTroubleshooting: Select one or more files before clicking 'Scan Files'"
	case strings.Contains(message, "file type not supported"):
		return message + "\nTroubleshooting: Check the supported file types list in the web interface help section"
	case strings.Contains(message, "Failed to initialize suppression manager"):
		return message + "\nTroubleshooting: Check file permissions for .ferret-scan-suppressions.yaml"
	case strings.Contains(message, "scanning failed"):
		return message + "\nTroubleshooting: Ensure the uploaded file is not corrupted and is a supported format"
	case statusCode == http.StatusInternalServerError:
		return message + "\nTroubleshooting: Check server logs for detailed error information"
	case statusCode == http.StatusNotFound:
		return message + "\nTroubleshooting: Verify the requested resource path is correct"
	default:
		return message
	}
}

// sanitizeUserInput removes dangerous characters from user input for safe output
func sanitizeUserInput(input string, maxLength int) string {
	// Remove control characters, null bytes, and other dangerous characters
	sanitized := strings.Map(func(r rune) rune {
		// Remove control characters (0-31, 127)
		if r < 32 || r == 127 {
			return -1
		}
		// Remove other potentially dangerous characters
		switch r {
		case '<', '>', '"', '\'', '&':
			return -1 // Remove HTML/XML special characters
		}
		return r
	}, input)

	// Limit length to prevent response bloat
	if len(sanitized) > maxLength {
		sanitized = sanitized[:maxLength] + "..."
	}

	return sanitized
}

// sanitizeFilenameForDisplay sanitizes a filename for safe display in web UI with Windows path handling
func (ws *WebServer) sanitizeFilenameForDisplay(filename string) string {
	// First normalize the path for the current platform
	normalized := paths.NormalizePath(filename)

	// Handle Windows-specific path sanitization
	if platform.IsWindows() {
		// Convert backslashes to forward slashes for consistent web display
		normalized = strings.ReplaceAll(normalized, "\\", "/")

		// Handle Windows drive letters (C: -> C:/)
		if paths.HasDriveLetter(normalized) && len(normalized) >= 2 && normalized[1] == ':' {
			if len(normalized) == 2 || (len(normalized) > 2 && normalized[2] != '/') {
				normalized = normalized[:2] + "/" + normalized[2:]
			}
		}

		// Handle UNC paths (\\server\share -> //server/share)
		if strings.HasPrefix(filename, "\\\\") {
			normalized = "//" + strings.TrimPrefix(normalized, "//")
		}
	}

	// Apply general sanitization with increased length limit for paths
	return sanitizeUserInput(normalized, 500)
}

// normalizePathForWeb converts platform-specific paths to web-friendly format
func (ws *WebServer) normalizePathForWeb(path string) string {
	// Always convert backslashes to forward slashes for consistent web display
	webPath := strings.ReplaceAll(path, "\\", "/")

	// Handle drive letters for web display (works on any platform for Windows-style paths)
	if len(webPath) >= 2 && webPath[1] == ':' {
		// Ensure drive letter format is consistent (C:/ not C:\)
		if len(webPath) == 2 {
			webPath += "/"
		} else if webPath[2] != '/' {
			webPath = webPath[:2] + "/" + webPath[2:]
		}
	}

	return webPath
}

// loadConfiguration loads the configuration file or returns default config (same as CLI)
func (ws *WebServer) loadConfiguration(configFile string) *config.Config {
	// If config file is not specified, try to find one in standard locations
	configPath := configFile
	if configPath == "" {
		configPath = config.FindConfigFile()
	}

	// Load configuration (will use defaults if file not found)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		// Use default configuration for web mode
		cfg, _ = config.LoadConfig("")
	}
	return cfg
}

// webConfiguration holds resolved configuration values for web mode
type webConfiguration struct {
	confidenceLevels    string
	checksToRun         string
	verbose             bool
	recursive           bool
	enablePreprocessors bool
}

// resolveWebConfiguration resolves final configuration values for web mode (simplified version of CLI logic)
func (ws *WebServer) resolveWebConfiguration(cfg *config.Config, confidence, checks string, verbose, recursive bool) *webConfiguration {
	final := &webConfiguration{}

	// Confidence levels
	final.confidenceLevels = "all" // default fallback
	if cfg != nil && cfg.Defaults.ConfidenceLevels != "" {
		final.confidenceLevels = cfg.Defaults.ConfidenceLevels
	}
	if confidence != "" {
		final.confidenceLevels = confidence
	}

	// Checks to run
	final.checksToRun = "all" // default fallback
	if cfg != nil && cfg.Defaults.Checks != "" {
		final.checksToRun = cfg.Defaults.Checks
	}
	if checks != "" {
		final.checksToRun = checks
	}

	// Verbose
	final.verbose = false // default fallback
	if cfg != nil {
		final.verbose = cfg.Defaults.Verbose
	}
	final.verbose = verbose // Web parameter overrides config

	// Recursive
	final.recursive = false // default fallback
	if cfg != nil {
		final.recursive = cfg.Defaults.Recursive
	}
	final.recursive = recursive // Web parameter overrides config

	// Enable preprocessors
	final.enablePreprocessors = true // default fallback
	if cfg != nil {
		final.enablePreprocessors = cfg.Defaults.EnablePreprocessors
	}
	// Web always enables preprocessors

	return final
}

// initializeSuppressionManager initializes the suppression manager (same as CLI)
func (ws *WebServer) initializeSuppressionManager(suppressionFile string) (*suppressions.SuppressionManager, error) {
	// Initialize suppression manager with same logic as CLI (empty string uses default path)
	suppressionManager := suppressions.NewSuppressionManager(suppressionFile)

	return suppressionManager, nil
}

// Suppression management endpoints - delegate to CLI suppression system

// handleSuppressions lists all suppression rules (GET /suppressions)
func (ws *WebServer) handleSuppressions(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Get all suppression rules using CLI suppression system
	rules := suppressionManager.ListSuppressions()

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"rules":   rules,
	})
}

// handleSuppressionsCreate creates a new suppression rule (POST /suppressions/create)
func (ws *WebServer) handleSuppressionsCreate(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var createRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&createRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Create suppression rule using CLI suppression system
	hash, _ := createRequest["hash"].(string)
	reason, _ := createRequest["reason"].(string)
	findingData, _ := createRequest["finding_data"].(map[string]interface{})

	err = suppressionManager.CreateSuppressionFromFinding(hash, reason, findingData)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to create suppression rule: %v", err))
		return
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rule created successfully",
	})
}

// handleSuppressionsEdit edits an existing suppression rule (POST /suppressions/edit)
func (ws *WebServer) handleSuppressionsEdit(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var editRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&editRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Edit suppression rule using CLI suppression system
	id, _ := editRequest["id"].(string)
	reason, _ := editRequest["reason"].(string)
	createdBy, _ := editRequest["created_by"].(string)
	enabled, _ := editRequest["enabled"].(bool)

	err = suppressionManager.EditSuppression(id, reason, createdBy, enabled, nil)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to edit suppression rule: %v", err))
		return
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rule updated successfully",
	})
}

// handleSuppressionsRemove removes a suppression rule (POST /suppressions/remove)
func (ws *WebServer) handleSuppressionsRemove(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var removeRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&removeRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Remove suppression rule using CLI suppression system
	id, _ := removeRequest["id"].(string)

	err = suppressionManager.RemoveSuppression(id)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to remove suppression rule: %v", err))
		return
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rule removed successfully",
	})
}

// handleSuppressionsEnable enables a suppression rule (POST /suppressions/enable)
func (ws *WebServer) handleSuppressionsEnable(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var enableRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&enableRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Enable suppression rule using CLI suppression system
	id, _ := enableRequest["id"].(string)

	// Get current rule and update it to enabled
	rules := suppressionManager.ListSuppressions()
	for _, rule := range rules {
		if rule.ID == id {
			err = suppressionManager.EditSuppression(id, rule.Reason, rule.CreatedBy, true, rule.ExpiresAt)
			if err != nil {
				ws.sendError(responseWriter, fmt.Sprintf("Failed to enable suppression rule: %v", err))
				return
			}
			break
		}
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rule enabled successfully",
	})
}

// handleSuppressionsDisable disables a suppression rule (POST /suppressions/disable)
func (ws *WebServer) handleSuppressionsDisable(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var disableRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&disableRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Disable suppression rule using CLI suppression system
	id, _ := disableRequest["id"].(string)

	err = suppressionManager.DisableSuppressionByID(id)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to disable suppression rule: %v", err))
		return
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rule disabled successfully",
	})
}

// handleSuppressionsBulkEnable enables multiple suppression rules (POST /suppressions/bulk-enable)
func (ws *WebServer) handleSuppressionsBulkEnable(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var bulkRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&bulkRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Bulk enable suppression rules using CLI suppression system
	ids, _ := bulkRequest["ids"].([]interface{})

	rules := suppressionManager.ListSuppressions()
	for _, idInterface := range ids {
		if id, ok := idInterface.(string); ok {
			for _, rule := range rules {
				if rule.ID == id {
					err = suppressionManager.EditSuppression(id, rule.Reason, rule.CreatedBy, true, rule.ExpiresAt)
					if err != nil {
						ws.sendError(responseWriter, fmt.Sprintf("Failed to enable suppression rule %s: %v", id, err))
						return
					}
					break
				}
			}
		}
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rules enabled successfully",
	})
}

// handleSuppressionsBulkDisable disables multiple suppression rules (POST /suppressions/bulk-disable)
func (ws *WebServer) handleSuppressionsBulkDisable(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var bulkRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&bulkRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Bulk disable suppression rules using CLI suppression system
	ids, _ := bulkRequest["ids"].([]interface{})

	for _, idInterface := range ids {
		if id, ok := idInterface.(string); ok {
			err = suppressionManager.DisableSuppressionByID(id)
			if err != nil {
				ws.sendError(responseWriter, fmt.Sprintf("Failed to disable suppression rule %s: %v", id, err))
				return
			}
		}
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rules disabled successfully",
	})
}

// handleSuppressionsBulkDelete deletes multiple suppression rules (POST /suppressions/bulk-delete)
func (ws *WebServer) handleSuppressionsBulkDelete(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var bulkRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&bulkRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Bulk delete suppression rules using CLI suppression system
	ids, _ := bulkRequest["ids"].([]interface{})

	for _, idInterface := range ids {
		if id, ok := idInterface.(string); ok {
			err = suppressionManager.RemoveSuppression(id)
			if err != nil {
				ws.sendError(responseWriter, fmt.Sprintf("Failed to delete suppression rule %s: %v", id, err))
				return
			}
		}
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rules deleted successfully",
	})
}

// handleSuppressionsBulkCreate creates multiple suppression rules (POST /suppressions/bulk-create)
func (ws *WebServer) handleSuppressionsBulkCreate(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var bulkRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&bulkRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Bulk create suppression rules using CLI suppression system
	findings, _ := bulkRequest["findings"].([]interface{})
	reason, _ := bulkRequest["reason"].(string)

	for _, findingInterface := range findings {
		if findingData, ok := findingInterface.(map[string]interface{}); ok {
			hash, _ := findingData["hash"].(string)
			err = suppressionManager.CreateSuppressionFromFinding(hash, reason, findingData)
			if err != nil {
				// Continue with other findings even if one fails
				continue
			}
		}
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"message": "Suppression rules created successfully",
	})
}

// handleSuppressionsDownload downloads the suppression file (GET /suppressions/download)
func (ws *WebServer) handleSuppressionsDownload(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Get suppression file content using CLI suppression system
	configPath := suppressionManager.GetConfigPath()
	cleanConfigPath := filepath.Clean(configPath)
	content, err := os.ReadFile(cleanConfigPath)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to read suppression file: %v", err))
		return
	}

	// Set headers for file download
	responseWriter.Header().Set("Content-Type", "application/x-yaml")
	responseWriter.Header().Set("Content-Disposition", "attachment; filename=\".ferret-scan-suppressions.yaml\"")
	responseWriter.WriteHeader(http.StatusOK)
	responseWriter.Write(content)
}

// handleSuppressionsCheckHash checks hash for a finding (POST /suppressions/check-hash)
func (ws *WebServer) handleSuppressionsCheckHash(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var hashRequest map[string]interface{}
	if err := json.NewDecoder(request.Body).Decode(&hashRequest); err != nil {
		ws.sendError(responseWriter, "Invalid JSON in request body")
		return
	}

	// Initialize suppression manager using CLI logic
	suppressionManager, err := ws.initializeSuppressionManager("")
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	// Generate hash using CLI suppression system
	findingData, _ := hashRequest["finding_data"].(map[string]interface{})
	hash, err := suppressionManager.GenerateFindingHashFromData(findingData)
	if err != nil {
		ws.sendError(responseWriter, fmt.Sprintf("Failed to generate hash: %v", err))
		return
	}

	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"success": true,
		"hash":    hash,
	})
}

// Static asset serving endpoints with security validation

// serveLogo serves the ferret-scan logo with path traversal protection
func (ws *WebServer) serveLogo(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Serve logo from docs/images/ferret-scan-logo.png with platform-aware path handling
	logoPath := paths.JoinPath("docs", "images", "ferret-scan-logo.png")

	// Validate path to prevent traversal attacks
	if !ws.isValidStaticPath(logoPath) {
		http.Error(responseWriter, "Invalid path", http.StatusBadRequest)
		return
	}

	// Normalize path for current platform
	normalizedPath := paths.NormalizePath(logoPath)

	// Check if file exists
	if _, err := os.Stat(normalizedPath); os.IsNotExist(err) {
		ws.sendErrorWithStatus(responseWriter, "Logo not found", http.StatusNotFound)
		return
	}

	// Read and serve the logo file
	cleanLogoPath := filepath.Clean(normalizedPath)
	logoData, err := os.ReadFile(cleanLogoPath)
	if err != nil {
		ws.sendErrorWithStatus(responseWriter, "Failed to read logo file", http.StatusInternalServerError)
		return
	}

	// Set appropriate headers
	responseWriter.Header().Set("Content-Type", "image/png")
	responseWriter.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
	responseWriter.WriteHeader(http.StatusOK)
	responseWriter.Write(logoData)
}

// serveDocs serves documentation files from docs/ directory with security validation
func (ws *WebServer) serveDocs(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the requested path (remove /docs/ prefix)
	docPath := strings.TrimPrefix(request.URL.Path, "/docs/")
	if docPath == "" {
		ws.sendErrorWithStatus(responseWriter, "Document path required", http.StatusBadRequest)
		return
	}

	// Construct full path using platform-aware path joining
	fullPath := paths.JoinPath("docs", docPath)

	// Validate path to prevent traversal attacks
	if !ws.isValidStaticPath(fullPath) {
		ws.sendErrorWithStatus(responseWriter, "Invalid document path - path traversal not allowed", http.StatusBadRequest)
		return
	}

	// Normalize path for current platform
	normalizedPath := paths.NormalizePath(fullPath)

	// Check if file exists
	if _, err := os.Stat(normalizedPath); os.IsNotExist(err) {
		// Sanitize docPath before including in error message
		safeDocPath := sanitizeUserInput(docPath, 100)
		ws.sendErrorWithStatus(responseWriter, fmt.Sprintf("Document not found: %s", safeDocPath), http.StatusNotFound)
		return
	}

	// Read the documentation file
	cleanDocPath := filepath.Clean(normalizedPath)
	docData, err := os.ReadFile(cleanDocPath)
	if err != nil {
		ws.sendErrorWithStatus(responseWriter, "Failed to read document file", http.StatusInternalServerError)
		return
	}

	// Set appropriate content type based on file extension
	contentType := ws.getContentType(normalizedPath)
	responseWriter.Header().Set("Content-Type", contentType)
	responseWriter.Header().Set("Cache-Control", "public, max-age=300") // Cache for 5 minutes
	responseWriter.WriteHeader(http.StatusOK)
	responseWriter.Write(docData)
}

// isValidStaticPath validates static file paths to prevent path traversal attacks
func (ws *WebServer) isValidStaticPath(path string) bool {
	// Ensure the path doesn't contain any path traversal attempts in the original path
	if strings.Contains(path, "..") {
		return false
	}

	// Normalize path for current platform first
	normalizedPath := paths.NormalizePath(path)

	// Clean the path to resolve any . components
	cleanPath := filepath.Clean(normalizedPath)

	// Get absolute path to ensure we're within allowed directories
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return false
	}

	// Get current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}

	// Normalize both paths for comparison (important on Windows)
	normalizedAbsPath := paths.NormalizePath(absPath)
	normalizedCwd := paths.NormalizePath(cwd)

	// Ensure the absolute path is within the current working directory
	// On Windows, use case-insensitive comparison
	if platform.IsWindows() {
		normalizedAbsPath = strings.ToLower(normalizedAbsPath)
		normalizedCwd = strings.ToLower(normalizedCwd)
	}

	if !strings.HasPrefix(normalizedAbsPath, normalizedCwd) {
		return false
	}

	// Ensure the clean path starts with allowed directories
	// Use platform-appropriate path separators for comparison
	allowedPrefixes := []string{
		paths.JoinPath("docs") + string(filepath.Separator),
		paths.JoinPath("web") + string(filepath.Separator),
		"docs" + string(filepath.Separator), // Fallback for relative paths
		"web" + string(filepath.Separator),  // Fallback for relative paths
	}

	for _, prefix := range allowedPrefixes {
		normalizedPrefix := paths.NormalizePath(prefix)
		if platform.IsWindows() {
			// Case-insensitive comparison on Windows
			if strings.HasPrefix(strings.ToLower(cleanPath), strings.ToLower(normalizedPrefix)) {
				return true
			}
		} else {
			if strings.HasPrefix(cleanPath, normalizedPrefix) {
				return true
			}
		}
	}

	return false
}

// getContentType returns the appropriate content type for a file based on its extension
func (ws *WebServer) getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".md":
		return "text/markdown; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}
