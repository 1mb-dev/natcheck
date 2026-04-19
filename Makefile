.PHONY: build test test-verbose test-coverage lint clean run install help

# Build configuration
BINARY_NAME=natcheck
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev")
BUILD_DIR=.
CMD_DIR=./cmd/natcheck
INTERNAL_PACKAGES=./internal/...

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOINSTALL=$(GOCMD) install
GOCLEAN=$(GOCMD) clean

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

## help: Display this help message
help:
	@echo "natcheck - Build Targets"
	@echo ""
	@echo "Usage:"
	@echo "  make <target>"
	@echo ""
	@echo "Targets:"
	@awk '/^## [a-zA-Z_-]+:/ { sub(/^## /, ""); split($$0, parts, ": "); printf "  %-20s %s\n", parts[1], substr($$0, length(parts[1])+3) }' $(MAKEFILE_LIST)

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

## test: Run all tests (short mode)
test:
	@echo "Running tests..."
	$(GOTEST) -race -short -timeout 60s $(INTERNAL_PACKAGES)

## test-verbose: Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	$(GOTEST) -race -v -timeout 60s $(INTERNAL_PACKAGES)

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -race -coverprofile=coverage.out $(INTERNAL_PACKAGES)
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run golangci-lint
lint:
	@echo "Running linter..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found"; exit 1; }
	golangci-lint run ./...

## run: Build and run natcheck with default flags
run: build
	./$(BINARY_NAME)

## install: Install natcheck to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	$(GOINSTALL) $(LDFLAGS) $(CMD_DIR)

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BUILD_DIR)/$(BINARY_NAME)
	rm -f coverage.out coverage.html

## tidy: Tidy go modules
tidy:
	$(GOMOD) tidy
