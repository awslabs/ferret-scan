.PHONY: build clean vet fmt run install-config install check-go-version

# Default target
all: check-go-version fmt vet build

# Help target
help:
	@echo "Available targets:"
	@echo ""
	@echo "🏗️  Build:"
	@echo "  build              - Build ferret-scan binary (includes CLI and web modes)"
	@echo "  build-windows      - Build for Windows (amd64)"
	@echo "  build-windows-arm64 - Build for Windows (arm64)"
	@echo "  build-all-platforms - Build for all supported platforms"
	@echo "  container-build    - Build container image (Docker/Finch)"
	@echo "  check-go-version   - Check Go version consistency"
	@echo "  sync-go-version    - Sync Go version across all files"
	@echo "  release-snapshot   - Build snapshot release with GoReleaser"
	@echo "  release-test       - Test GoReleaser configuration"
	@echo "  changelog          - Generate changelog with git-chglog"
	@echo "  version-status     - Show current version and next version"
	@echo "  version-next       - Show next version number"
	@echo "  version-bump       - Create next version tag locally"
	@echo "  version-release    - Create and push next version (triggers release)"
	@echo ""
	@echo "📦 Install (requires sudo):"
	@echo "  sudo make install-system  - Full system install with pre-commit support"
	@echo "  sudo make install         - Basic system install (binary only)"
	@echo "  make install-config       - Install config files only (no sudo needed)"
	@echo "  make uninstall            - Remove system installation"
	@echo ""
	@echo "🚀 Team Setup:"
	@echo "  setup-team         - Complete team setup (config + pre-commit + GitHub Actions)"
	@echo "  setup-developer    - Developer setup (for team members)"
	@echo "  setup-precommit    - Install pre-commit hooks only"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test               - Run all tests"
	@echo "  test-windows       - Run Windows-specific tests"
	@echo "  test-cross-platform - Run cross-platform compatibility tests"
	@echo "  test-precommit     - Test pre-commit integration"
	@echo "  test-suppressions  - Test suppression functionality"
	@echo "  test-git-commit    - Test real git commit blocking"
	@echo "  test-cleanup       - Test cleanup functionality"
	@echo "  container-test     - Test container health"
	@echo ""
	@echo "🔧 Development:"
	@echo "  clean              - Clean build artifacts"
	@echo "  clean-all          - Clean all development artifacts"
	@echo "  clean-precommit    - Remove pre-commit hooks from current project"
	@echo "  clean-everything   - Complete cleanup (build + system + hooks)"
	@echo "  uninstall          - Remove system-wide installation"
	@echo "  fmt                - Format code"

	@echo "  vet                - Run go vet"
	@echo ""
	@echo "🐳 Container:"
	@echo "  container-run      - Run container"
	@echo ""


# Build the application
build:
	@echo "Building..."
	@go env -w GOPROXY=direct
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo "0.0.0-development"); \
	go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$$VERSION' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan cmd/main.go

# Build for Windows (amd64)
build-windows:
	@echo "Building for Windows (amd64)..."
	@go env -w GOPROXY=direct
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo "0.0.0-development"); \
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$$VERSION' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan-win-amd64.exe cmd/main.go

# Build for Windows (arm64)
build-windows-arm64:
	@echo "Building for Windows (arm64)..."
	@go env -w GOPROXY=direct
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo "0.0.0-development"); \
	GOOS=windows GOARCH=arm64 go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$$VERSION' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan-win-arm64.exe cmd/main.go

# Build for all platforms
build-all-platforms:
	@echo "Building for all platforms..."
	@go env -w GOPROXY=direct
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo "0.0.0-development"); \
	echo "Building for current platform..." && make build && \
	echo "Building for Linux (amd64)..." && GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$$VERSION' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan-linux-amd64 cmd/main.go && \
	echo "Building for Linux (arm64)..." && GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$$VERSION' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan-linux-arm64 cmd/main.go && \
	echo "Building for macOS (amd64)..." && GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$$VERSION' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan-darwin-amd64 cmd/main.go && \
	echo "Building for macOS (arm64)..." && GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$$VERSION' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan-darwin-arm64 cmd/main.go
	@make build-windows
	@make build-windows-arm64
	@echo "✓ All platform binaries built in bin/ directory"

# Note: Web UI functionality is now integrated into the main ferret-scan binary
# Use: ferret-scan --web to start web server mode

# Build with version information (used by semantic-release)
build-release:
	@echo "Building release version $(VERSION)..."
	@go env -w GOPROXY=direct
	@go build -ldflags="-s -w -X 'ferret-scan/internal/version.Version=$(VERSION)' -X 'ferret-scan/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)' -X 'ferret-scan/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'" -o bin/ferret-scan cmd/main.go

# Note: Web UI release functionality is now integrated into build-release target
# The single ferret-scan binary includes both CLI and web modes

# Install the application system-wide (basic)
install: build
	@echo "Installing ferret-scan..."
	@if cp bin/ferret-scan /usr/local/bin/ferret-scan 2>/dev/null; then \
		chmod +x /usr/local/bin/ferret-scan; \
		echo "✓ ferret-scan installed to /usr/local/bin/ferret-scan"; \
	else \
		echo "❌ Permission denied. System installation requires administrator privileges."; \
		echo ""; \
		echo "💡 Try one of these options:"; \
		echo "   sudo make install          # Install with sudo"; \
		echo "   sudo make install-system   # Full system install with pre-commit"; \
		echo "   make build                 # Build only (use ./bin/ferret-scan)"; \
		echo ""; \
		exit 1; \
	fi

# Full system installation with configuration and pre-commit integration
install-system: build
	@echo "Running full system installation..."
	@chmod +x scripts/install-system.sh
	@if ./scripts/install-system.sh source 2>/dev/null; then \
		echo "✓ Full system installation complete"; \
	else \
		echo "❌ Permission denied. System installation requires administrator privileges."; \
		echo ""; \
		echo "💡 Try:"; \
		echo "   sudo make install-system   # Full system install with pre-commit"; \
		echo ""; \
		echo "This will install:"; \
		echo "   • ferret-scan binary to /usr/local/bin/"; \
		echo "   • ferret-scan-precommit wrapper to /usr/local/bin/"; \
		echo "   • Configuration files to ~/.ferret-scan/"; \
		echo ""; \
		exit 1; \
	fi

# Install configuration files only
install-config:
	@echo "Installing configuration files..."
	@mkdir -p ~/.ferret-scan
	@if [ -f "examples/ferret.yaml" ]; then \
		cp examples/ferret.yaml ~/.ferret-scan/config.yaml; \
		cp examples/ferret.yaml ~/.ferret-scan/ferret.example.yaml; \
		echo "✓ Default config installed from examples/ferret.yaml"; \
	elif [ -f "config.yaml" ]; then \
		cp config.yaml ~/.ferret-scan/config.yaml; \
		echo "✓ Basic config installed from config.yaml"; \
	else \
		echo "⚠️  No configuration files found"; \
	fi
	@echo "✓ Configuration files installed to ~/.ferret-scan/"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@go clean

# Uninstall system-wide installation
uninstall:
	@echo "🗑️  Uninstalling ferret-scan system-wide installation..."
	@if [ -f "scripts/install-system.sh" ]; then \
		chmod +x scripts/install-system.sh; \
		sudo scripts/install-system.sh uninstall; \
	else \
		echo "❌ install-system.sh not found. Manual uninstall:"; \
		echo "   sudo rm -f /usr/local/bin/ferret-scan"; \
		echo "   sudo rm -f /usr/local/bin/ferret-scan-precommit"; \
		echo "   rm -rf ~/.ferret-scan"; \
	fi

# Clean all local development artifacts
clean-all: clean
	@echo "🧹 Cleaning all development artifacts..."
	@rm -rf coverage.out coverage.html
	@rm -rf dist/
	@rm -rf .goreleaser/
	@go clean -testcache
	@go clean -modcache 2>/dev/null || true
	@echo "✓ All development artifacts cleaned"

# Remove pre-commit hooks from current project
clean-precommit:
	@echo "🔗 Removing pre-commit hooks from current project..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit uninstall 2>/dev/null || echo "No pre-commit hooks to remove"; \
	fi
	@rm -f .git/hooks/pre-commit
	@echo "✓ Pre-commit hooks removed from current project"

# Complete cleanup (build artifacts + system installation + project hooks)
clean-everything: clean-all clean-precommit uninstall
	@echo ""
	@echo "🎯 Complete cleanup performed:"
	@echo "   ✓ Build artifacts removed"
	@echo "   ✓ System installation removed"
	@echo "   ✓ Pre-commit hooks removed"
	@echo ""
	@echo "💡 Manual cleanup (if needed):"
	@echo "   • Remove .ferret-scan.yaml from projects"
	@echo "   • Remove .ferret-scan-suppressions.yaml from projects"
	@echo "   • Check other projects for pre-commit integration"



# Run go vet
vet:
	@echo "Vetting..."
	@go vet ./...

# Format code
fmt:
	@echo "Formatting..."
	@go fmt ./...

# Run the application
run: build
	@echo "Running..."
	@./bin/ferret-scan

# Legacy target - use install-config above
install-config-legacy:
	@echo "Installing configuration file..."
	@./scripts/create-config.sh

# Check GenAI prerequisites
check-genai:
	@echo "Checking GenAI prerequisites..."
	@echo "Checking AWS CLI..."
	@if command -v aws >/dev/null 2>&1; then \
		echo "✓ AWS CLI installed"; \
	else \
		echo "✗ AWS CLI not found. Install from: https://aws.amazon.com/cli/"; \
	fi
	@echo "Checking AWS credentials..."
	@if aws sts get-caller-identity >/dev/null 2>&1; then \
		echo "✓ AWS credentials configured"; \
		aws sts get-caller-identity --query 'Account' --output text | sed 's/^/  Account: /'; \
	else \
		echo "✗ AWS credentials not configured. Run: aws configure"; \
	fi
	@echo "Checking Textract permissions..."
	@echo "  Note: Cannot verify Textract permissions without making API calls"
	@echo "  Ensure your IAM user/role has 'textract:DetectDocumentText' permission"

# Build all examples
build-examples:
	@echo "Building all examples..."
	@cd examples && make build-all

# Clean example binaries
clean-examples:
	@echo "Cleaning example binaries..."
	@cd examples && make clean-examples

# Setup pre-commit hooks
setup-precommit:
	@echo "Setting up pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "✓ Pre-commit hooks installed"; \
	else \
		echo "✗ pre-commit not found. Install with: pip install pre-commit"; \
	fi

# Complete team setup - configuration + pre-commit + GitHub Actions
setup-team:
	@echo "🚀 Setting up Ferret Scan for your team..."
	@echo "This will configure:"
	@echo "  • Team configuration (.ferret-scan.yaml)"
	@echo "  • Pre-commit hooks (.pre-commit-config.yaml)"
	@echo "  • GitHub Actions workflow"
	@echo ""
	@./scripts/setup-team-config.sh
	@echo ""
	@./scripts/setup-pre-commit.sh
	@echo ""
	@if [ ! -d ".github/workflows" ]; then mkdir -p .github/workflows; fi
	@if [ ! -f ".github/workflows/ferret-scan.yml" ]; then \
		cp .github/workflows/ferret-scan.yml .github/workflows/ 2>/dev/null || \
		echo "⚠️  GitHub Actions workflow not found. Copy manually from examples."; \
	else \
		echo "✓ GitHub Actions workflow already exists"; \
	fi
	@echo ""
	@echo "🎉 Team setup complete!"
	@echo ""
	@echo "📋 Next steps:"
	@echo "  1. Review and commit the configuration files:"
	@echo "     git add .ferret-scan.yaml .pre-commit-config.yaml .github/workflows/ferret-scan.yml"
	@echo "     git commit -m 'Add Ferret Scan team security configuration'"
	@echo ""
	@echo "  2. Team members should run: make setup-developer"
	@echo ""
	@echo "  3. Test with a commit containing: 4111-1111-1111-1111"

# Developer setup - for team members joining the project
setup-developer:
	@echo "👨‍💻 Setting up Ferret Scan for development..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		echo "✓ pre-commit found"; \
	else \
		echo "❌ pre-commit not found. Install with:"; \
		echo "   pip install pre-commit"; \
		echo "   # or: brew install pre-commit"; \
		exit 1; \
	fi
	@if [ ! -f "./bin/ferret-scan" ]; then \
		echo "📦 Building ferret-scan..."; \
		make build; \
	else \
		echo "✓ ferret-scan binary found"; \
	fi
	@echo "🔧 Installing pre-commit hooks..."
	@pre-commit install
	@echo "✅ Developer setup complete!"
	@echo ""
	@echo "🧪 Testing setup..."
	@echo "Test credit card: 4111-1111-1111-1111" > .ferret-test.txt
	@if ./bin/ferret-scan --config config.yaml --file .ferret-test.txt --confidence high --quiet >/dev/null 2>&1; then \
		echo "✅ Ferret Scan is working correctly"; \
	else \
		echo "❌ Ferret Scan test failed"; \
	fi
	@rm -f .ferret-test.txt
	@echo ""
	@echo "🚀 Ready to go! Your commits will now be automatically scanned."
	@echo "   To bypass a scan: git commit --no-verify"

# Test pre-commit integration
test-precommit:
	@echo "🧪 Testing pre-commit integration..."
	@if [ ! -f "./bin/ferret-scan" ]; then \
		echo "📦 Building ferret-scan first..."; \
		make build; \
	fi
	@echo ""
	@echo "Creating test files with sensitive data..."
	@echo "# Test file with sensitive data" > test-sensitive.txt
	@echo "Credit card: 4111-1111-1111-1111" >> test-sensitive.txt
	@echo "SSN: 123-45-6789" >> test-sensitive.txt
	@echo "API Key: sk_test_1234567890abcdef" >> test-sensitive.txt
	@echo ""
	@echo "🔍 Testing direct scan..."
	@./bin/ferret-scan --config config.yaml --file test-sensitive.txt --confidence high,medium --no-color
	@echo ""
	@echo "🔗 Testing pre-commit mode..."
	@./bin/ferret-scan --config config.yaml --pre-commit-mode --confidence high,medium test-sensitive.txt || echo "✅ Pre-commit mode test completed"
	@echo ""
	@echo "🔗 Testing system installation..."
	@if command -v ferret-scan-precommit >/dev/null 2>&1; then \
		echo "✅ ferret-scan-precommit found in system PATH"; \
		echo "🧪 Testing system pre-commit wrapper..."; \
		FERRET_CONFIDENCE="high,medium" FERRET_FAIL_ON="none" ferret-scan-precommit test-sensitive.txt; \
	else \
		echo "⚠️  ferret-scan-precommit not found in system PATH"; \
		echo ""; \
		echo "💡 To install for pre-commit integration:"; \
		echo "   sudo make install-system"; \
		echo ""; \
		echo "This will install ferret-scan-precommit to /usr/local/bin/"; \
	fi
	@echo ""
	@echo "🧹 Cleaning up test files..."
	@rm -f test-sensitive.txt
	@echo ""
	@echo "✅ Pre-commit test completed!"
	@echo "   If you saw sensitive data detected above, the integration is working."

# Test suppression functionality
test-suppressions:
	@echo "🧪 Testing suppression functionality..."
	@if [ ! -f "./bin/ferret-scan" ]; then \
		echo "📦 Building ferret-scan first..."; \
		make build; \
	fi
	@echo ""
	@echo "Creating test file with sensitive data..."
	@echo "# Test file with known false positives" > test-suppressions.txt
	@echo "Email: user@example.com" >> test-suppressions.txt
	@echo "Test card: 4111-1111-1111-1111" >> test-suppressions.txt
	@echo ""
	@echo "🔍 Initial scan (should find 2 findings)..."
	@./bin/ferret-scan --config config.yaml --file test-suppressions.txt --confidence high,medium --no-color
	@echo ""
	@echo "📝 Generating suppressions..."
	@./bin/ferret-scan --config config.yaml --file test-suppressions.txt --generate-suppressions --quiet
	@echo ""
	@echo "📋 Suppression file contents:"
	@if [ -f ".ferret-scan-suppressions.yaml" ]; then \
		head -20 .ferret-scan-suppressions.yaml; \
	else \
		echo "❌ Suppression file not created"; \
	fi
	@echo ""
	@echo "🔧 Enabling suppressions (setting enabled: true)..."
	@if [ -f ".ferret-scan-suppressions.yaml" ]; then \
		sed -i.bak 's/enabled: false/enabled: true/g' .ferret-scan-suppressions.yaml; \
		echo "✅ Suppressions enabled"; \
	fi
	@echo ""
	@echo "🔍 Scan with suppressions (should show suppressed findings)..."
	@./bin/ferret-scan --config config.yaml --file test-suppressions.txt --show-suppressed --no-color
	@echo ""
	@echo "🔗 Testing pre-commit mode with suppressions..."
	@./bin/ferret-scan --config config.yaml --pre-commit-mode --confidence high,medium --show-suppressed --verbose test-suppressions.txt || echo "✅ Pre-commit suppression test completed"
	@echo ""
	@echo "🧹 Cleaning up..."
	@rm -f test-suppressions.txt .ferret-scan-suppressions.yaml .ferret-scan-suppressions.yaml.bak
	@echo ""
	@echo "✅ Suppression test completed!"

# Test real git commit (requires git repository)
test-git-commit:
	@echo "🧪 Testing real git commit with sensitive data..."
	@if ! git rev-parse --git-dir >/dev/null 2>&1; then \
		echo "❌ Not in a git repository. Initialize with: git init"; \
		exit 1; \
	fi
	@if [ ! -f "./bin/ferret-scan" ]; then \
		echo "📦 Building ferret-scan first..."; \
		make build; \
	fi
	@echo ""
	@echo "Creating test file with sensitive data..."
	@echo "# Test commit - should be blocked" > test-commit.txt
	@echo "Credit card for testing: 4111-1111-1111-1111" >> test-commit.txt
	@echo "API key: sk_test_abcdef123456" >> test-commit.txt
	@echo ""
	@echo "Staging file..."
	@git add test-commit.txt
	@echo ""
	@echo "🚫 Attempting commit (should be blocked by pre-commit hook)..."
	@if git commit -m "Test commit with sensitive data" 2>&1; then \
		echo "⚠️  WARNING: Commit was NOT blocked! Check your pre-commit configuration."; \
		git reset --soft HEAD~1; \
	else \
		echo "✅ SUCCESS: Commit was correctly blocked by pre-commit hook!"; \
	fi
	@echo ""
	@echo "🧹 Cleaning up..."
	@git reset HEAD test-commit.txt 2>/dev/null || true
	@rm -f test-commit.txt
	@echo ""
	@echo "💡 To bypass the hook for testing: git commit --no-verify"

# Manual pre-commit hook (without pre-commit framework)
install-git-hook:
	@echo "Installing Git pre-commit hook..."
	@cp scripts/pre-commit-ferret.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "✓ Git pre-commit hook installed"

# Direct pre-commit setup (recommended)
setup-direct-precommit:
	@echo "Setting up direct pre-commit integration..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "✓ Direct pre-commit hooks ready for installation"; \
		echo "ℹ️  Configure using examples in docs/PRE_COMMIT_INTEGRATION.md"; \
	else \
		echo "✗ pre-commit not found. Install with: pip install pre-commit"; \
	fi

# Testing targets
test: test-unit test-integration
	@echo "✓ All tests completed"

test-unit:
	@echo "Running unit tests..."
	@go test -v ./tests/unit/...

test-integration:
	@echo "Running integration tests..."
	@FERRET_TEST_MODE=true go test -v ./tests/integration/...

# Windows-specific testing targets
test-windows:
	@echo "Running Windows-specific tests..."
	@echo "Testing Windows build..."
	@make build-windows
	@echo "✓ Windows build successful"
	@echo "Running Windows platform tests (compile-only)..."
	@GOOS=windows go test -c ./internal/platform/... >/dev/null 2>&1 && echo "✓ Windows platform tests compile successfully" || echo "❌ Windows platform tests compilation failed"
	@echo "Running Windows path tests (compile-only)..."
	@GOOS=windows go test -c ./internal/paths/... >/dev/null 2>&1 && echo "✓ Windows path tests compile successfully" || echo "❌ Windows path tests compilation failed"
	@echo "Running cross-platform tests with Windows environment simulation..."
	@FERRET_TEST_PLATFORM=windows go test -v ./internal/platform/platform_test.go ./internal/platform/platform.go ./internal/platform/windows.go -run TestPlatformDetection 2>/dev/null || echo "Platform detection tests completed"
	@echo "✓ Windows-specific tests completed"

test-cross-platform:
	@echo "Running cross-platform compatibility tests..."
	@echo "Testing all platform builds..."
	@make build-all-platforms
	@echo "✓ All platform builds successful"
	@echo "Running platform abstraction tests..."
	@go test -v ./internal/platform/...
	@echo "Running path handling tests..."
	@go test -v ./internal/paths/...
	@echo "✓ Cross-platform compatibility tests completed"

test-coverage:
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./tests/...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

test-race:
	@echo "Running tests with race detection..."
	@go test -race ./tests/...

test-aws-mock:
	@echo "Running AWS integration tests with mocks..."
	@FERRET_TEST_MODE=true go test -v ./tests/integration/aws_integration_test.go

test-validators:
	@echo "Running validator unit tests..."
	@go test -v ./tests/unit/validators/...

test-clean:
	@echo "Cleaning test artifacts..."
	@rm -f coverage.out coverage.html
	@go clean -testcache

# Benchmark tests
benchmark:
	@echo "Running benchmark tests..."
	@go test -bench=. -benchmem ./tests/...

# Test with verbose output and debug logging
test-debug:
	@echo "Running tests with debug output..."
	@FERRET_DEBUG=1 FERRET_TEST_MODE=true go test -v ./tests/...

# Container targets (supports Docker and Finch)
container-build:
	@echo "Building container image with version information..."
	@./scripts/container-build.sh

container-run:
	@echo "Running container..."
	@if command -v docker >/dev/null 2>&1; then \
		docker run -p 8080:8080 --rm ferret-scan:latest; \
	elif command -v finch >/dev/null 2>&1; then \
		finch run -p 8080:8080 --rm ferret-scan:latest; \
	else \
		echo "Error: Neither Docker nor Finch found"; \
		exit 1; \
	fi

container-test:
	@echo "Testing container health..."
	@CONTAINER_CMD=""; \
	if command -v docker >/dev/null 2>&1; then \
		CONTAINER_CMD="docker"; \
	elif command -v finch >/dev/null 2>&1; then \
		CONTAINER_CMD="finch"; \
	else \
		echo "Error: Neither Docker nor Finch found"; \
		exit 1; \
	fi; \
	$$CONTAINER_CMD run -d --name ferret-test -p 8081:8080 ferret-scan:latest; \
	sleep 5; \
	curl -f http://localhost:8081/health || ($$CONTAINER_CMD stop ferret-test && $$CONTAINER_CMD rm ferret-test && exit 1); \
	$$CONTAINER_CMD stop ferret-test; \
	$$CONTAINER_CMD rm ferret-test; \
	echo "✓ Container test passed with $$CONTAINER_CMD"

# GoReleaser and versioning targets
release-snapshot:
	@echo "Building snapshot release with GoReleaser..."
	@goreleaser build --snapshot --clean

release-test:
	@echo "Testing GoReleaser configuration..."
	@goreleaser check

# Test cleanup functionality
test-cleanup:
	@echo "🧪 Testing cleanup functionality..."
	@echo ""
	@echo "📋 Available cleanup options:"
	@echo "✅ make clean              - Build artifacts only"
	@echo "✅ make clean-all          - All development artifacts"
	@echo "✅ make clean-precommit    - Pre-commit hooks from current project"
	@echo "✅ make uninstall          - System-wide installation"
	@echo "✅ make clean-everything   - Complete cleanup"
	@echo ""
	@echo "📋 Script-based cleanup:"
	@echo "✅ scripts/install-system.sh uninstall - Interactive uninstall"
	@echo ""
	@echo "📖 Documentation:"
	@echo "✅ docs/UNINSTALL.md       - Complete uninstall guide"
	@echo "✅ docs/INSTALL.md         - Includes uninstall section"
	@echo ""
	@echo "🎯 Test uninstall help:"
	@scripts/install-system.sh --help | grep -A 2 -B 2 uninstall || echo "Help text available"

# Test what files will be included in release
release-files-test:
	@echo "🧪 Testing release file inclusion..."
	@echo ""
	@echo "📦 Essential files for release:"
	@echo "✅ Binary: ferret-scan (built by GoReleaser)"
	@echo -n "✅ Installation script: "; [ -f "scripts/install-system.sh" ] && echo "scripts/install-system.sh ✓" || echo "❌ MISSING"
	@echo -n "✅ Pre-commit setup: "; [ -f "scripts/setup-pre-commit.sh" ] && echo "scripts/setup-pre-commit.sh ✓" || echo "❌ MISSING"
	@echo -n "✅ Configuration: "; [ -f "examples/ferret.yaml" ] && echo "examples/ferret.yaml → config.yaml ✓" || echo "❌ MISSING"
	@echo -n "✅ Quick install guide: "; [ -f "docs/INSTALL.md" ] && echo "docs/INSTALL.md ✓" || echo "❌ MISSING"
	@echo -n "✅ Documentation: "; [ -d "docs" ] && echo "docs/ ✓" || echo "❌ MISSING"
	@echo -n "✅ Pre-commit examples: "; [ -f ".pre-commit-config-examples.yaml" ] && echo ".pre-commit-config-examples.yaml ✓" || echo "❌ MISSING"
	@echo ""
	@echo "🎯 Release archive will contain:"
	@echo "   ferret-scan_v1.0.0_linux_amd64/"
	@echo "   ├── ferret-scan                    # Main binary"
	@echo "   ├── docs/INSTALL.md                # Quick installation guide"
	@echo "   ├── README.md                      # Full documentation"
	@echo "   ├── config.yaml                    # Ready-to-use config"
	@echo "   ├── scripts/"
	@echo "   │   ├── install-system.sh          # System installation"
	@echo "   │   └── setup-pre-commit.sh        # Pre-commit setup (deprecated)"
	@echo "   ├── docs/                          # Complete documentation"
	@echo "   ├── examples/                      # Configuration examples"
	@echo "   └── .pre-commit-config*.yaml       # Pre-commit configurations"
	@echo ""
	@echo "🚀 User workflow after download:"
	@echo "   1. tar -xzf ferret-scan_v1.0.0_linux_amd64.tar.gz"
	@echo "   2. cd ferret-scan_v1.0.0_linux_amd64"
	@echo "   3. sudo scripts/install-system.sh"
	@echo "   4. scripts/setup-pre-commit.sh"

changelog:
	@echo "Generating changelog..."
	@git-chglog --output CHANGELOG.md

changelog-next:
	@echo "Generating changelog for next version..."
	@git-chglog --next-tag $(TAG) --output CHANGELOG.md

# Version management targets
version-status:
	@echo "Checking version status..."
	@./scripts/version-helper.sh status

version-next:
	@echo "Next version:"
	@./scripts/version-helper.sh next

version-bump:
	@echo "Creating next version tag..."
	@./scripts/version-helper.sh bump

version-release:
	@echo "Creating and releasing next version..."
	@./scripts/version-helper.sh release

check-commits:
	@echo "Checking commit message format..."
	@./scripts/check-commit-format.sh 2>/dev/null || echo "Commit format checker not found"

check-commits-range:
	@echo "Checking commit message format for range: $(RANGE)"
	@./scripts/check-commit-format.sh $(RANGE) 2>/dev/null || echo "Commit format checker not found"

version:
	@echo "Current version information:"
	@./bin/ferret-scan --version 2>/dev/null || echo "Binary not built. Run 'make build' first."

# Check Go version consistency across project
check-go-version:
	@echo "🔍 Checking Go version consistency..."
	@./scripts/go-version.sh check

# Sync Go version across all project files
sync-go-version:
	@echo "🔄 Synchronizing Go version across project..."
	@./scripts/go-version.sh all
	@echo "✅ Go version synchronized"
	@echo ""
	@echo "📝 Updated files may need to be committed:"
	@echo "   git add go.mod .go-version"
	@echo "   git commit -m 'chore: sync Go version to $(shell cat .go-version)'"
