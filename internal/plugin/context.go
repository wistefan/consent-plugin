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

// requestContextStore is a package-level concurrent-safe store that maps
// request IDs (uint32) to their captured RequestContext. This bridges the
// RequestFilter and ResponseFilter phases, which are called separately by
// the APISIX plugin runner.
var requestContextStore sync.Map

// StoreRequestContext saves a RequestContext for the given request ID.
// It overwrites any previously stored context for the same ID.
func StoreRequestContext(requestID uint32, ctx *RequestContext) {
	requestContextStore.Store(requestID, ctx)
}

// LoadRequestContext retrieves the stored RequestContext for the given
// request ID. Returns the context and true if found, or nil and false
// if no context exists for that ID.
func LoadRequestContext(requestID uint32) (*RequestContext, bool) {
	val, ok := requestContextStore.Load(requestID)
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
// request ID. This should be called after the context has been consumed
// during ResponseFilter to prevent memory leaks.
func DeleteRequestContext(requestID uint32) {
	requestContextStore.Delete(requestID)
}

// LoadAndDeleteRequestContext atomically loads and removes the stored
// RequestContext for the given request ID. This is the preferred method
// for consuming context during ResponseFilter as it combines retrieval
// and cleanup in a single operation.
func LoadAndDeleteRequestContext(requestID uint32) (*RequestContext, bool) {
	val, ok := requestContextStore.LoadAndDelete(requestID)
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
