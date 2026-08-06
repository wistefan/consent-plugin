# consent-plugin

## Overview
An Apache APISIX Go plugin that intercepts HTTP responses and applies consent-based filtering for personal data. It uses the APISIX go-plugin-runner to hook into the request/response lifecycle, consult an external consent API, and manipulate or deny responses based on consent decisions.

## Tech Stack
- Language: Go 1.21+
- Framework: Apache APISIX go-plugin-runner (`github.com/apache/apisix-go-plugin-runner`)
- Test: Go standard `testing` package with `testify` for assertions
- Build: Makefile + Docker

## Project Structure
```
consent-plugin/
├── CLAUDE.md                  # This file — AI agent codebase context
├── IMPLEMENTATION_PLAN.md     # Step-by-step implementation plan
├── README.md                  # Project README
├── Makefile                   # Build, test, lint targets
├── Dockerfile                 # Build the go-runner binary
├── go.mod                     # Go module definition
├── go.sum                     # Go dependency checksums
├── main.go                    # Entry point — registers plugin, starts runner
├── internal/
│   ├── plugin/
│   │   ├── consent.go         # Plugin struct, Name(), ParseConf(), RequestFilter(), ResponseFilter()
│   │   ├── consent_test.go    # Unit tests for plugin logic
│   │   └── config.go          # Configuration schema struct and validation
│   ├── consent/
│   │   ├── client.go          # HTTP client for external consent API
│   │   ├── client_test.go     # Unit tests for consent client
│   │   └── models.go          # Request/response models for consent API
│   ├── jwt/
│   │   ├── extractor.go       # JWT extraction and parsing from request headers
│   │   └── extractor_test.go  # Unit tests for JWT extraction
│   └── filter/
│       ├── response.go        # JSON response body filtering/redaction logic
│       └── response_test.go   # Unit tests for response filtering
└── docker-compose.yaml        # Local dev with APISIX + plugin runner
```

## Build & Test
```bash
# Build the go-runner binary
make build

# Run all tests
make test

# Run tests with coverage
make test-cover

# Run linter
make lint

# Build Docker image
make docker-build
```

## Key Conventions
- All exported types and functions must have GoDoc comments.
- No magic constants — use named constants with descriptive names.
- Internal packages under `internal/` to enforce encapsulation.
- Table-driven tests with `t.Run()` subtests.
- Configuration structs use JSON tags matching APISIX plugin config format.
- Error handling: wrap errors with `fmt.Errorf("context: %w", err)`.

## Important Files
- `main.go` — Entry point; registers the consent plugin and starts the runner.
- `internal/plugin/consent.go` — Core plugin implementing the go-plugin-runner `Plugin` interface.
- `internal/plugin/config.go` — Plugin configuration schema (consent API URL, JWT settings, deny behavior, filter rules).
- `internal/consent/client.go` — HTTP client calling the external consent/authorization API.
- `internal/filter/response.go` — JSON response body manipulation (field removal/redaction).
- `go.mod` — Module path: `consent-plugin` (or as configured).
