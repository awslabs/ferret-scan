// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

//go:embed assets/template.html
var embeddedTemplate string

// WebServer represents the web server instance.
//
// suppressions/config caching: the manager and resolved config are built
// lazily on first use and reloaded only when the underlying file's mtime
// changes (or the file appears/disappears). This eliminates the per-request
// YAML parse cost that previously dominated /scan and /suppressions latency.
// suppCacheMu guards concurrent reload while readers run.
type WebServer struct {
	port             string
	configPath       string
	suppressionsPath string
	excludePatterns  []string
	server           *http.Server

	suppCacheMu     sync.RWMutex
	suppCacheMgr    *suppressions.SuppressionManager
	suppCacheMtime  time.Time
	suppCacheExists bool
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

// NewWebServerWithOptions creates a new web server instance with config and
// suppression file paths supplied by the caller. Empty strings preserve the
// existing default behavior (search standard locations). excludePatterns from
// --exclude take precedence; empty slice means fall back to whatever the
// loaded config file specifies.
func NewWebServerWithOptions(port, configPath, suppressionsPath string, excludePatterns []string) *WebServer {
	return &WebServer{
		port:             port,
		configPath:       configPath,
		suppressionsPath: suppressionsPath,
		excludePatterns:  excludePatterns,
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
			"Troubleshooting: Template should be embedded in the binary")
	}

	// Check if we're using the fallback template
	if strings.Contains(templateContent, "Template not found") {
		return fmt.Errorf("web template not found, using fallback\n" +
			"Troubleshooting: Template should be embedded in the binary at build time")
	}

	return nil
}

// setupRoutes configures all HTTP route handlers - MINIMAL ROUTES ONLY
func (ws *WebServer) setupRoutes() {
	http.HandleFunc("/", ws.serveHome)
	http.HandleFunc("/health", ws.handleHealth)
	http.HandleFunc("/scan", ws.handleScan)
	http.HandleFunc("/export", ws.handleExport)
	http.HandleFunc("/config-info", ws.handleConfigInfo)

	// Static asset serving with security validation
	http.HandleFunc("/logo", ws.serveLogo)

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

// loadTemplate loads the HTML template from embedded content
func (ws *WebServer) loadTemplate() string {
	// Return embedded template (always available in production binary)
	if embeddedTemplate != "" {
		return embeddedTemplate
	}

	// Fallback if embed somehow failed (should never happen)
	return `<!DOCTYPE html>
<html><head><title>Ferret Scan</title></head>
<body><h1>Ferret Scan</h1><p>Template not found. Please ensure template.html is embedded in the binary.</p></body></html>`
}

// resolveExcludePatterns returns the patterns the front-end should apply when
// walking dropped folders. --exclude (passed at startup) takes precedence over
// whatever the loaded config file specifies, matching the CLI's precedence
// order.
func (ws *WebServer) resolveExcludePatterns() []string {
	if len(ws.excludePatterns) > 0 {
		return ws.excludePatterns
	}
	cfg := ws.loadConfiguration(ws.configPath)
	if cfg != nil && len(cfg.Defaults.ExcludePatterns) > 0 {
		return cfg.Defaults.ExcludePatterns
	}
	return nil
}

// handleConfigInfo returns config-derived values the front-end needs at load
// time (currently just exclude_patterns for client-side folder filtering).
func (ws *WebServer) handleConfigInfo(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		http.Error(responseWriter, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	patterns := ws.resolveExcludePatterns()
	if patterns == nil {
		patterns = []string{}
	}
	responseWriter.Header().Set("Content-Type", "application/json")
	json.NewEncoder(responseWriter).Encode(map[string]interface{}{
		"exclude_patterns": patterns,
	})
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
	err := request.ParseMultipartForm(100 << 20) // 100MB max, consistent with maxFileSize in processUploadedFile
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
	// Optional relative path from a folder drop (e.g. "myrepo/src/foo.go") —
	// Go strips path components from multipart filename headers, so the
	// front-end sends it as a parallel field.
	relativePath := request.FormValue("relative_path")

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
		displayName := fileHeader.Filename
		// relative_path applies when there's a single file in the request,
		// which is the front-end's per-file upload pattern.
		if relativePath != "" && len(files) == 1 {
			displayName = relativePath
		}
		matches, suppressed, suppCount, err := ws.processUploadedFileWithCLILogic(fileHeader, i, confidence, checks, verbose, recursive, displayName)
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
func (ws *WebServer) processUploadedFileWithCLILogic(uploadedFile *multipart.FileHeader, fileIndex int, confidence, checks string, verbose, recursive bool, displayName string) ([]detector.Match, []detector.SuppressedMatch, int, error) {
	if displayName == "" {
		displayName = uploadedFile.Filename
	}

	// Open uploaded file
	file, err := uploadedFile.Open()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to open file %s: %v", displayName, err)
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
	return ws.runFullCLIScan(normalizedTempPath, displayName, confidence, checks, verbose, recursive)
}

// runFullCLIScan executes the full CLI scanning logic with configuration and suppression support
func (ws *WebServer) runFullCLIScan(filePath, originalFilename, confidence, checks string, verbose, recursive bool) ([]detector.Match, []detector.SuppressedMatch, int, error) {
	cfg := ws.loadConfiguration(ws.configPath)

	var checksSlice []string
	if checks != "" && checks != "all" {
		checksSlice = strings.Split(checks, ",")
	}

	suppressionManager, err := ws.initializeSuppressionManager(ws.suppressionsPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to initialize suppression manager: %v", err)
	}

	// Scan without applying suppressions — the filename on each match is the
	// random temp path, but suppression hashes were created against the
	// original upload filename. We rename below and then apply suppressions
	// ourselves so the hashes match.
	scanConfig := core.ScanConfig{
		FilePath:            filePath,
		Checks:              checksSlice,
		Debug:               false,
		Verbose:             verbose,
		Recursive:           recursive,
		EnablePreprocessors: true,
		EnableRedaction:     false,
		Config:              cfg,
		Profile:             nil,
		SuppressionManager:  nil,
	}

	result, err := core.ScanFile(scanConfig)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("scanning failed: %v", err)
	}

	// Rewrite each match's filename to the original upload name so hashes
	// computed against the upload identity (rather than the temp path) match
	// any existing suppression rules.
	safeFilename := ws.sanitizeFilenameForDisplay(originalFilename)
	for i := range result.Matches {
		result.Matches[i].Filename = safeFilename
	}

	// Apply suppressions now that filenames are stable.
	var unsuppressed []detector.Match
	var suppressed []detector.SuppressedMatch
	for _, match := range result.Matches {
		if isSuppressed, rule := suppressionManager.IsSuppressed(match); isSuppressed {
			suppressed = append(suppressed, detector.SuppressedMatch{
				Match:        match,
				SuppressedBy: rule.ID,
				RuleReason:   rule.Reason,
				ExpiresAt:    rule.ExpiresAt,
			})
		} else {
			unsuppressed = append(unsuppressed, match)
		}
	}

	return unsuppressed, suppressed, len(suppressed), nil
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

// loadConfiguration loads the configuration file or returns default config (same as CLI)
func (ws *WebServer) loadConfiguration(configFile string) *config.Config {
	return config.LoadConfigOrDefault(configFile)
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

// initializeSuppressionManager returns the cached suppression manager,
// reloading from disk only when the underlying file's mtime changes (or
// the file appears/disappears). Previously every HTTP handler built a
// fresh manager — re-parsing the YAML on every request, which dominated
// /scan and /suppressions latency for any non-trivial rules file.
//
// The suppressionFile parameter is preserved for compatibility but the
// cache always uses ws.suppressionsPath. Callers all pass that anyway.
func (ws *WebServer) initializeSuppressionManager(suppressionFile string) (*suppressions.SuppressionManager, error) {
	// Resolve the path the cache is keyed against. If a non-empty path was
	// passed and it differs from ws.suppressionsPath, build a one-off
	// manager rather than poisoning the cache. (No production caller does
	// this today, but it preserves the original API contract.)
	cachePath := ws.suppressionsPath
	if suppressionFile != "" && suppressionFile != cachePath {
		return suppressions.NewSuppressionManager(suppressionFile), nil
	}

	// Stat the file once to learn the current mtime / existence state.
	var (
		curMtime  time.Time
		curExists bool
	)
	if cachePath != "" {
		if info, err := os.Stat(cachePath); err == nil {
			curMtime = info.ModTime()
			curExists = true
		}
	}

	// Fast path: hold the read lock if the cached state matches what we
	// just observed on disk.
	ws.suppCacheMu.RLock()
	if ws.suppCacheMgr != nil &&
		ws.suppCacheExists == curExists &&
		ws.suppCacheMtime.Equal(curMtime) {
		mgr := ws.suppCacheMgr
		ws.suppCacheMu.RUnlock()
		return mgr, nil
	}
	ws.suppCacheMu.RUnlock()

	// Slow path: rebuild. Re-check under the write lock in case another
	// goroutine refreshed concurrently.
	ws.suppCacheMu.Lock()
	defer ws.suppCacheMu.Unlock()
	if ws.suppCacheMgr != nil &&
		ws.suppCacheExists == curExists &&
		ws.suppCacheMtime.Equal(curMtime) {
		return ws.suppCacheMgr, nil
	}
	ws.suppCacheMgr = suppressions.NewSuppressionManager(cachePath)
	ws.suppCacheExists = curExists
	ws.suppCacheMtime = curMtime
	return ws.suppCacheMgr, nil
}


// Suppression management endpoints — delegate to CLI suppression system.
//
// Each handler is a thin adapter on top of suppressionEndpoint, which
// handles method validation, JSON decoding into a typed request struct,
// suppression-manager acquisition, and JSON response encoding. Previously
// each of the 12 handlers re-implemented all of this inline (~25 lines
// each); now they're 5–10.

// suppressionRequest is the shape of every JSON body that reaches a
// suppression endpoint. Optional fields stay zero-valued for endpoints
// that don't need them — the alternative (a typed struct per endpoint)
// adds 11 small types for negligible safety improvement, since we
// already validate the required fields per-handler.
type suppressionRequest struct {
	ID          string                 `json:"id"`
	Hash        string                 `json:"hash"`
	Reason      string                 `json:"reason"`
	CreatedBy   string                 `json:"created_by"`
	Enabled     bool                   `json:"enabled"`
	IDs         []string               `json:"ids"`
	Findings    []map[string]any       `json:"findings"`
	FindingData map[string]any         `json:"finding_data"`
}

// suppressionEndpoint wraps a handler with shared boilerplate: method
// check, optional JSON decode (only for POST), suppression manager
// resolution, and response encoding. The handler returns the response
// payload and an optional error; non-nil errors become 400 responses.
//
// `decode` controls whether the request body should be parsed into a
// suppressionRequest. GET endpoints that don't accept a body pass false.
func (ws *WebServer) suppressionEndpoint(method string, decode bool,
	fn func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req suppressionRequest
		if decode {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				ws.sendError(w, "Invalid JSON in request body")
				return
			}
		}

		mgr, err := ws.initializeSuppressionManager(ws.suppressionsPath)
		if err != nil {
			ws.sendError(w, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
			return
		}

		payload, err := fn(req, mgr)
		if err != nil {
			ws.sendError(w, err.Error())
			return
		}
		ws.respondJSON(w, payload)
	}
}

// respondJSON writes payload as the JSON response body with Content-Type set.
func (ws *WebServer) respondJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// successMessage is a small helper for endpoints whose response body is
// just {"success": true, "message": "…"}.
func successMessage(msg string) map[string]any {
	return map[string]any{"success": true, "message": msg}
}

// handleSuppressions lists all suppression rules (GET /suppressions).
func (ws *WebServer) handleSuppressions(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("GET", false, func(_ suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		return map[string]any{"success": true, "rules": mgr.ListSuppressions()}, nil
	})(w, r)
}

// handleSuppressionsCreate creates a new suppression rule (POST /suppressions/create).
func (ws *WebServer) handleSuppressionsCreate(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		if err := mgr.CreateSuppressionFromFinding(req.Hash, req.Reason, req.FindingData); err != nil {
			return nil, fmt.Errorf("Failed to create suppression rule: %v", err)
		}
		return successMessage("Suppression rule created successfully"), nil
	})(w, r)
}

// handleSuppressionsEdit edits an existing suppression rule (POST /suppressions/edit).
func (ws *WebServer) handleSuppressionsEdit(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		if err := mgr.EditSuppression(req.ID, req.Reason, req.CreatedBy, req.Enabled, nil); err != nil {
			return nil, fmt.Errorf("Failed to edit suppression rule: %v", err)
		}
		return successMessage("Suppression rule updated successfully"), nil
	})(w, r)
}

// handleSuppressionsRemove removes a suppression rule (POST /suppressions/remove).
func (ws *WebServer) handleSuppressionsRemove(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		if err := mgr.RemoveSuppression(req.ID); err != nil {
			return nil, fmt.Errorf("Failed to remove suppression rule: %v", err)
		}
		return successMessage("Suppression rule removed successfully"), nil
	})(w, r)
}

// handleSuppressionsEnable enables a suppression rule (POST /suppressions/enable).
func (ws *WebServer) handleSuppressionsEnable(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		// Look up the existing rule so we preserve its reason/createdBy/expiry
		// when flipping enabled→true.
		for _, rule := range mgr.ListSuppressions() {
			if rule.ID == req.ID {
				if err := mgr.EditSuppression(req.ID, rule.Reason, rule.CreatedBy, true, rule.ExpiresAt); err != nil {
					return nil, fmt.Errorf("Failed to enable suppression rule: %v", err)
				}
				break
			}
		}
		return successMessage("Suppression rule enabled successfully"), nil
	})(w, r)
}

// handleSuppressionsDisable disables a suppression rule (POST /suppressions/disable).
func (ws *WebServer) handleSuppressionsDisable(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		if err := mgr.DisableSuppressionByID(req.ID); err != nil {
			return nil, fmt.Errorf("Failed to disable suppression rule: %v", err)
		}
		return successMessage("Suppression rule disabled successfully"), nil
	})(w, r)
}

// handleSuppressionsBulkEnable enables multiple suppression rules (POST /suppressions/bulk-enable).
func (ws *WebServer) handleSuppressionsBulkEnable(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		rules := mgr.ListSuppressions()
		for _, id := range req.IDs {
			for _, rule := range rules {
				if rule.ID == id {
					if err := mgr.EditSuppression(id, rule.Reason, rule.CreatedBy, true, rule.ExpiresAt); err != nil {
						return nil, fmt.Errorf("Failed to enable suppression rule %s: %v", id, err)
					}
					break
				}
			}
		}
		return successMessage("Suppression rules enabled successfully"), nil
	})(w, r)
}

// handleSuppressionsBulkDisable disables multiple suppression rules (POST /suppressions/bulk-disable).
func (ws *WebServer) handleSuppressionsBulkDisable(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		for _, id := range req.IDs {
			if err := mgr.DisableSuppressionByID(id); err != nil {
				return nil, fmt.Errorf("Failed to disable suppression rule %s: %v", id, err)
			}
		}
		return successMessage("Suppression rules disabled successfully"), nil
	})(w, r)
}

// handleSuppressionsBulkDelete deletes multiple suppression rules (POST /suppressions/bulk-delete).
func (ws *WebServer) handleSuppressionsBulkDelete(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		for _, id := range req.IDs {
			if err := mgr.RemoveSuppression(id); err != nil {
				return nil, fmt.Errorf("Failed to delete suppression rule %s: %v", id, err)
			}
		}
		return successMessage("Suppression rules deleted successfully"), nil
	})(w, r)
}

// handleSuppressionsBulkCreate creates multiple suppression rules (POST /suppressions/bulk-create).
// Failures on individual findings are skipped silently so the bulk import
// is forgiving — that matches the prior behavior.
func (ws *WebServer) handleSuppressionsBulkCreate(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		for _, finding := range req.Findings {
			hash, _ := finding["hash"].(string)
			_ = mgr.CreateSuppressionFromFinding(hash, req.Reason, finding)
		}
		return successMessage("Suppression rules created successfully"), nil
	})(w, r)
}

// handleSuppressionsDownload downloads the suppression file (GET /suppressions/download).
// Doesn't use suppressionEndpoint because it returns the raw YAML, not JSON.
func (ws *WebServer) handleSuppressionsDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mgr, err := ws.initializeSuppressionManager(ws.suppressionsPath)
	if err != nil {
		ws.sendError(w, fmt.Sprintf("Failed to initialize suppression manager: %v", err))
		return
	}

	cleanConfigPath := filepath.Clean(mgr.GetConfigPath())
	content, err := os.ReadFile(cleanConfigPath)
	if err != nil {
		ws.sendError(w, fmt.Sprintf("Failed to read suppression file: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=\".ferret-scan-suppressions.yaml\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

// handleSuppressionsCheckHash checks hash for a finding (POST /suppressions/check-hash).
func (ws *WebServer) handleSuppressionsCheckHash(w http.ResponseWriter, r *http.Request) {
	ws.suppressionEndpoint("POST", true, func(req suppressionRequest, mgr *suppressions.SuppressionManager) (any, error) {
		hash, err := mgr.GenerateFindingHashFromData(req.FindingData)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate hash: %v", err)
		}
		return map[string]any{"success": true, "hash": hash}, nil
	})(w, r)
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

// isValidStaticPath validates static file paths to prevent path traversal attacks
func (ws *WebServer) isValidStaticPath(path string) bool {
	// Ensure the path doesn't contain any path traversal attempts
	if strings.Contains(path, "..") {
		return false
	}

	// Normalize path for current platform
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

	// Ensure the clean path starts with allowed directories (docs for logo)
	allowedPrefixes := []string{
		paths.JoinPath("docs") + string(filepath.Separator),
		"docs" + string(filepath.Separator), // Fallback for relative paths
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
