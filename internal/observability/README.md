# Observability Component

Standardized observability for all Ferret-Scan components.

## Standard Data Structure

All components use `OperationData` for consistent observability:

```go
type OperationData struct {
    // Core identification
    Component   string    `json:"component"`     // "router", "preprocessor", "validator"
    Operation   string    `json:"operation"`     // "process_file", "validate_content"
    RequestID   string    `json:"request_id"`    // Correlation ID

    // Performance
    DurationMs  int64     `json:"duration_ms"`   // Operation timing

    // File context
    FilePath    string    `json:"file_path"`     // File being processed
    FileSize    int64     `json:"file_size"`     // File size in bytes
    FileExt     string    `json:"file_ext"`      // File extension

    // Results
    Success     bool      `json:"success"`       // Operation success/failure
    Error       string    `json:"error"`         // Error message if failed

    // Content metrics
    ContentLength int     `json:"content_length"` // Extracted content length
    WordCount     int     `json:"word_count"`     // Word count
    MatchCount    int     `json:"match_count"`    // Validation matches found

    // Component-specific data
    Metadata    map[string]interface{} `json:"metadata"` // Additional data
}
```

## Usage Patterns

### Router Operations
```go
op := observer.StartOperation("router", "process_file", OperationData{
    FilePath: "/path/to/file.pdf",
    FileSize: 1024,
    FileExt:  ".pdf",
})
// ... processing logic ...
op.Complete(map[string]interface{}{
    "preprocessor_used": "Text Extractor",
})
```

### Preprocessor Operations
```go
op := observer.StartOperation("preprocessor", "extract_text", OperationData{
    FilePath: "/path/to/file.pdf",
    Metadata: map[string]interface{}{
        "preprocessor_name": "Text Extractor",
    },
})
// ... processing logic ...
op.Complete(map[string]interface{}{
    "content_length": 2576,
    "word_count": 258,
})
```

### Validator Operations
```go
op := observer.StartOperation("validator", "validate_content", OperationData{
    FilePath: "/path/to/file.pdf",
    ContentLength: 2576,
    Metadata: map[string]interface{}{
        "validator_name": "Credit Card Validator",
    },
})
// ... validation logic ...
op.Complete(map[string]interface{}{
    "match_count": 3,
})
```

## Standard Operations

### Router
- `file_evaluation` - File assessment and routing
- `preprocessor_selection` - Choosing capable preprocessors
- `process_file` - Complete file processing

### Preprocessors
- `capability_check` - Can process file check
- `extract_text` - Text extraction
- `extract_metadata` - Metadata extraction
- `ocr_processing` - OCR text extraction

### Validators
- `validate_file` - Direct file validation
- `validate_content` - Content string validation
- `pattern_matching` - Pattern detection

### Services
