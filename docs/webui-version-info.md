# Web UI Version Information

The Ferret Scan Web UI now displays version information in the top navigation bar.

## Features

### Version Display
- **Location**: Top-right corner of the navigation bar
- **Format**: Shows `v{version}` (e.g., `v1.2.3`)
- **Hover**: Displays build date in tooltip

### Version Details Modal
- **Access**: Click on the version number in the navigation
- **Information Displayed**:
  - Version number
  - Git commit hash
  - Build date and time
  - Go version used for compilation
  - Target platform (OS/architecture)
  - Full version string (same as CLI `--version`)

### API Endpoints

#### `/health`
Returns health status with complete build information:
```json
{
  "status": "healthy",
  "timestamp": "2025-08-28T23:45:25Z",
  "service": "ferret-scan-web",
  "version": "1.2.3",
  "ferret_scan": "available",
  "build_info": {
    "version": "1.2.3",
    "commit": "abc123def456",
    "build_date": "abc123def456",
    "go_version": "go1.25.1",
    "platform": "darwin/arm64"
  }
}
```

**Note**: The `timestamp` field shows the current server time, while `build_info.build_date` shows the actual build timestamp.

## Implementation Details

### Version Source
- Uses the same version information as the CLI `ferret-scan --version`
- Version data comes from `internal/version/version.go`
- Build-time variables are injected during compilation using ldflags

### Building with Version Information
- **Correct**: `make build` - Injects git commit and build timestamp into single executable
- **Incorrect**: `go build cmd/main.go` - Results in "unknown" values
- **Production**: `make build-release VERSION=x.y.z` - Full version info

### Automatic Loading
- Version information is fetched automatically when the page loads
- Falls back to "Version unavailable" if the endpoint is unreachable
- No impact on page functionality if version fetch fails

### User Experience
- Non-intrusive display in the navigation bar
- Click-to-reveal detailed information
- Consistent with CLI version output format
- Responsive design works on mobile devices

## Troubleshooting

### Version Shows "Loading version..."
- Check that the web server is running properly
- Verify the `/health` endpoint is accessible
- Check browser console for JavaScript errors

### Version Shows "Version unavailable"
- The `/health` endpoint returned an error
- Check web server logs for issues
- Verify the `internal/version` package is properly imported

### Build Information Shows "unknown"
- This happens when building without proper ldflags injection
- **Solution**: Use `make build` instead of `go build` directly
- Production builds automatically inject proper build-time variables
- Development: Use `make build` for complete version info (web UI is integrated)