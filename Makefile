# Makefile for consent-plugin APISIX Go plugin runner

# Binary name for the plugin runner
BINARY_NAME := go-runner

# Docker image configuration
DOCKER_IMAGE := quay.io/wi_stefan/consent-plugin
DOCKER_TAG := 0.0.1

# Go build flags
GO_BUILD_FLAGS := -trimpath -ldflags="-s -w"

# Coverage output file
COVERAGE_FILE := coverage.out

.PHONY: build test test-cover lint docker-build clean

## build: Compile the go-runner binary
build:
	go build $(GO_BUILD_FLAGS) -o $(BINARY_NAME) .

## test: Run all tests
test:
	go test -race ./...

## test-cover: Run tests with coverage report
test-cover:
	go test -race -coverprofile=$(COVERAGE_FILE) ./...
	go tool cover -func=$(COVERAGE_FILE)

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## docker-build: Build the Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME) $(COVERAGE_FILE)
