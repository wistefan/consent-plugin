# Multi-stage build for the consent-plugin APISIX go-plugin-runner.
# Stage 1: compile the Go binary.
# Stage 2: copy it into a minimal runtime image.

# --- Build stage ---
FROM golang:1.27-alpine AS builder

WORKDIR /build

# Cache dependency downloads by copying go.mod/go.sum first.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code and build the binary. .dockerignore keeps .git and build
# artifacts out, so an unrelated commit does not invalidate this layer.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o go-runner .

# --- Runtime stage ---
FROM alpine:3.22

RUN apk add --no-cache ca-certificates

# The runner has no reason to be root: it binds a unix socket in a directory it
# is given and makes outbound HTTP calls. Running as root only widens what a
# compromise of it reaches. The uid is fixed so a shared socket volume can be
# given predictable ownership.
RUN addgroup -g 10001 -S runner && adduser -u 10001 -S -G runner runner

WORKDIR /app

COPY --from=builder /build/go-runner /app/go-runner

USER 10001:10001

# The runner speaks the ext-plugin protocol, not HTTP, so there is nothing to
# probe but the listener itself: a bound socket means it is accepting RPCs. A TCP
# listen address is left to the orchestrator to probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD sh -c 'case "$APISIX_LISTEN_ADDRESS" in unix:*) test -S "${APISIX_LISTEN_ADDRESS#unix:}" ;; *) exit 0 ;; esac'

# The plugin runner binary is the entrypoint.
ENTRYPOINT ["/app/go-runner"]
