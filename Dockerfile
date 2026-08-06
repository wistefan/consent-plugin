# Multi-stage build for the consent-plugin APISIX go-plugin-runner.
# Stage 1: Compile the Go binary.
# Stage 2: Copy into a minimal runtime image.

# --- Build stage ---
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# Cache dependency downloads by copying go.mod/go.sum first.
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build the binary.
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o go-runner .

# --- Runtime stage ---
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/go-runner /app/go-runner

# The plugin runner binary is the entrypoint.
ENTRYPOINT ["/app/go-runner"]
