# File Router

Decoupled file routing system for Ferret Scan with debug logging and metrics collection.

## Architecture

- **FileRouter**: Main orchestrator that routes files to appropriate preprocessors
- **PreprocessorRegistry**: Registry-based system for preprocessor registration
- **ProcessingContext**: Standardized context passed to all preprocessors
- **DebugLogger**: Structured JSON debug logging
- **RouterMetrics**: Performance and usage metrics collection

## Usage

```go
// Create router with debug enabled
router := NewFileRouter(true)

// Register default preprocessors (includes specialized metadata preprocessors)
RegisterDefaultPreprocessors(router)

// Initialize with configuration
config := CreateRouterConfig(enableGenAI, genaiServices, genaiRegion)
router.InitializePreprocessors(config)

// Process a file
ctx, err := router.CreateProcessingContext(filePath, enableGenAI, genaiServices, genaiRegion, debug)
if err != nil {
    return err
}

result, err := router.ProcessFile(filePath, ctx)
```

## Debug Output

When `--debug` is enabled, structured JSON logs are written to stderr:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456789Z",
  "component": "router",
  "operation": "file_evaluation",
  "data": {
    "request_id": "a1b2c3d4e5f6g7h8",
    "file_path": "/path/to/file.pdf",
    "file_size": 1024000,
    "file_ext": ".pdf",
    "enable_genai": true
  }
}
```

## Metrics

Router collects performance metrics accessible via `GetMetrics()`:

- Files processed count
- Processing time per preprocessor
- Error counts by type
- File type distribution

## Preprocessor Registration

New preprocessors can be registered using factories:

```go
router.RegisterPreprocessor("custom", func(config map[string]interface{}) preprocessors.Preprocessor {
    return &CustomPreprocessor{
        apiKey: config["api_key"].(string),
    }
})
```

## Benefits

- **Decoupled**: File routing logic separated from main application
- **Testable**: Each component can be unit tested independently
- **Observable**: Comprehensive debug logging and metrics
- **Extensible**: Easy to add new preprocessors via registry
- **Consistent**: Standardized context for all preprocessors
