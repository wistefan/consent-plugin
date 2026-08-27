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

# Minimum total statement coverage, in percent. CI and `make test-cover` fail
# below it, so a gap cannot reappear unnoticed.
COVERAGE_FLOOR := 80

.PHONY: build test test-cover coverage-floor lint license-check license-fix docker-build clean

## build: Compile the go-runner binary
build:
	go build $(GO_BUILD_FLAGS) -o $(BINARY_NAME) .

## test: Run all tests
test:
	go test -race ./...

## test-cover: Run tests with coverage report and enforce the floor
# -coverpkg=./... is required: without it the integration package's coverage of
# internal/plugin is discarded, which understated the real figure and made the
# genuinely untested functions look like measurement noise.
test-cover:
	go test -race -coverpkg=./... -coverprofile=$(COVERAGE_FILE) ./...
	go tool cover -func=$(COVERAGE_FILE)
	./hack/coverage-floor.sh $(COVERAGE_FILE) $(COVERAGE_FLOOR)

## coverage-floor: Assert an existing coverage profile meets COVERAGE_FLOOR
coverage-floor:
	./hack/coverage-floor.sh $(COVERAGE_FILE) $(COVERAGE_FLOOR)

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## license-check: Verify the Apache-2.0 copyright header on every Go file (CI runs this)
license-check:
	./hack/license-header.sh check

## license-fix: Add the copyright header to Go files that lack it
license-fix:
	./hack/license-header.sh fix

## docker-build: Build the Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME) $(COVERAGE_FILE)
