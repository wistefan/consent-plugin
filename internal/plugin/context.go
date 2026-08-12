package plugin

import (
	"fmt"
	"net/http"
	"sync"
)

// RequestContext holds the captured request information that is needed
// during response filtering. It is stored during RequestFilter and
// retrieved during ResponseFilter.
type RequestContext struct {
	// Method is the HTTP method of the original request (e.g., "GET", "POST").
	Method string

	// Path is the URI path of the original request.
	Path string

	// Headers contains the HTTP headers from the original request.
	Headers http.Header

	// JWTClaims holds the decoded JWT claims extracted from the configured header.
	// The map keys are claim names and values are the claim values.
	JWTClaims map[string]interface{}
}

// requestContextStore is a package-level concurrent-safe store that maps a
// stable per-request key to its captured RequestContext. This bridges the
// RequestFilter and ResponseFilter phases, which APISIX invokes as two
// separate RPC calls (ext-plugin-pre-req and ext-plugin-post-resp).
//
// The key MUST be stable across those two phases for the same HTTP request.
// The runner's per-RPC id (Request.ID()/Response.ID()) is NOT stable between
// them, so the Nginx `$request_id` variable is used instead (see
// correlationKey in consent.go).
var requestContextStore sync.Map

// StoreRequestContext saves a RequestContext for the given request key.
// It overwrites any previously stored context for the same key.
func StoreRequestContext(requestKey string, ctx *RequestContext) {
	requestContextStore.Store(requestKey, ctx)
}

// LoadRequestContext retrieves the stored RequestContext for the given
// request key. Returns the context and true if found, or nil and false
// if no context exists for that key.
func LoadRequestContext(requestKey string) (*RequestContext, bool) {
	val, ok := requestContextStore.Load(requestKey)
	if !ok {
		return nil, false
	}

	ctx, ok := val.(*RequestContext)
	if !ok {
		return nil, false
	}

	return ctx, true
}

// DeleteRequestContext removes the stored RequestContext for the given
// request key. This should be called after the context has been consumed
// during ResponseFilter to prevent memory leaks.
func DeleteRequestContext(requestKey string) {
	requestContextStore.Delete(requestKey)
}

// LoadAndDeleteRequestContext atomically loads and removes the stored
// RequestContext for the given request key. This is the preferred method
// for consuming context during ResponseFilter as it combines retrieval
// and cleanup in a single operation.
func LoadAndDeleteRequestContext(requestKey string) (*RequestContext, bool) {
	val, ok := requestContextStore.LoadAndDelete(requestKey)
	if !ok {
		return nil, false
	}

	ctx, ok := val.(*RequestContext)
	if !ok {
		return nil, false
	}

	return ctx, true
}

// String returns a human-readable representation of the RequestContext,
// useful for logging and debugging.
func (rc *RequestContext) String() string {
	return fmt.Sprintf("RequestContext{Method: %s, Path: %s, Claims: %d, Headers: %d}",
		rc.Method, rc.Path, len(rc.JWTClaims), len(rc.Headers))
}
