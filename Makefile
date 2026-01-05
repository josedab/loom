.PHONY: build test lint run clean install-deps fmt vet

APP_NAME := loom
BUILD_DIR := ./bin
VERSION := 1.0.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Build the loom binary
build:
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

# Build for multiple platforms
build-all: build-linux build-darwin build-windows

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./cmd/$(APP_NAME)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 ./cmd/$(APP_NAME)

build-darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/$(APP_NAME)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/$(APP_NAME)

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/$(APP_NAME)

# Run tests
test:
	go test -v -race -cover ./...

# Run tests with coverage report
test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...
	goimports -w .

# Run go vet
vet:
	go vet ./...

# Run the gateway
run: build
	$(BUILD_DIR)/$(APP_NAME) -config configs/loom.yaml

# Run in development mode with hot reload
dev:
	go run ./cmd/$(APP_NAME) -config configs/loom.yaml -log-level debug

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install dependencies
install-deps:
	go mod download
	go mod tidy

# Generate code (if needed)
generate:
	go generate ./...

# Tidy modules
tidy:
	go mod tidy

# Docker build
docker-build:
	docker build -t $(APP_NAME):$(VERSION) .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest

# Docker run
docker-run:
	docker run -p 8080:8080 -p 9091:9091 -v $(PWD)/configs:/etc/loom $(APP_NAME):latest

# Benchmark
bench:
	go test -bench=. -benchmem ./...

# Check for security issues
security:
	gosec ./...

# Update dependencies
update-deps:
	go get -u ./...
	go mod tidy

# Show help
help:
	@echo "Available targets:"
	@echo "  build          - Build the loom binary"
	@echo "  build-all      - Build for all platforms"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage report"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  run            - Build and run loom"
	@echo "  dev            - Run in development mode"
	@echo "  clean          - Clean build artifacts"
	@echo "  install-deps   - Install dependencies"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  bench          - Run benchmarks"
	@echo "  help           - Show this help"
