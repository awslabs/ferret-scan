.PHONY: build-all clean-examples

# Build all examples
build-all: build-validators build-text-extractors build-meta-extractors build-textract build-transcribe

# Build validators
build-validators:
	@echo "Building validators..."
	@cd validators && go build -ldflags="-s -w" -o creditcard-example creditcard-example.go
	@cd validators && go build -ldflags="-s -w" -o passport-example passport-example.go
	@cd validators && go build -ldflags="-s -w" -o ssn-example ssn-example.go
	@cd validators && go build -ldflags="-s -w" -o metadata-example metadata-example.go
	@cd validators && go build -ldflags="-s -w" -o intellectualproperty-example intellectualproperty-example.go
	@cd validators && go build -ldflags="-s -w" -o comprehend-example comprehend-example.go

# Build text extractors
build-text-extractors:
	@echo "Building text extractors..."
	@cd preprocessors/text-extractors && go build -ldflags="-s -w" -o office-text-example office-text-example.go
	@cd preprocessors/text-extractors && go build -ldflags="-s -w" -o pdf-text-example pdf-text-example.go

# Build metadata extractors
build-meta-extractors:
	@echo "Building metadata extractors..."
	@cd preprocessors/meta-extractors && go build -ldflags="-s -w" -o exif-example exif-example.go
	@cd preprocessors/meta-extractors && go build -ldflags="-s -w" -o office-meta-example office-meta-example.go
	@cd preprocessors/meta-extractors && go build -ldflags="-s -w" -o pdf-meta-example pdf-meta-example.go

# Build textract (AWS SDK v2)
build-textract:
	@echo "Building textract..."
	@cd preprocessors && go build -ldflags="-s -w" -o textract-example textract-example.go

# Build transcribe (AWS SDK v2)
build-transcribe:
	@echo "Building transcribe..."
	@cd preprocessors && go build -ldflags="-s -w" -o transcribe-example transcribe-example.go

# Clean all example binaries
clean-examples:
	@echo "Cleaning examples..."
	@find . -name "*-example" -type f -delete
