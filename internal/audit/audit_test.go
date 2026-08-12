package audit

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmitExportsOTLPLog verifies an emitted event is exported to the Collector's
// /v1/logs endpoint as an OTLP log record carrying the routing service.name on
// the resource and the decision fields as attributes.
func TestEmitExportsOTLPLog(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newEmitter(Config{Endpoint: srv.URL, ServiceName: "consent-access-audit"})
	e.Emit(Event{
		Time:      time.Unix(0, 1700000000000000000),
		RequestID: "req-1",
		Subject:   "did:key:zTest",
		Resource:  "/ngsi-ld/v1/entities/x",
		Method:    "GET",
		Decision:  "deny",
		Reason:    "no granted consent",
	})
	e.Shutdown()

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, bodies, 1)
	assert.Equal(t, otlpLogsPath, paths[0], "must POST to the OTLP logs path")

	var p otlpPayload
	require.NoError(t, json.Unmarshal(bodies[0], &p))
	require.Len(t, p.ResourceLogs, 1)

	// routing marker: service.name on the resource
	resAttrs := p.ResourceLogs[0].Resource.Attributes
	require.Len(t, resAttrs, 1)
	assert.Equal(t, "service.name", resAttrs[0].Key)
	assert.Equal(t, "consent-access-audit", resAttrs[0].Value.StringValue)

	require.Len(t, p.ResourceLogs[0].ScopeLogs, 1)
	assert.Equal(t, scopeName, p.ResourceLogs[0].ScopeLogs[0].Scope.Name)
	recs := p.ResourceLogs[0].ScopeLogs[0].LogRecords
	require.Len(t, recs, 1)
	assert.Equal(t, "1700000000000000000", recs[0].TimeUnixNano, "int64 nanos must be a JSON string")

	attrs := map[string]string{}
	for _, a := range recs[0].Attributes {
		attrs[a.Key] = a.Value.StringValue
	}
	assert.Equal(t, "audit", attrs["event.domain"])
	assert.Equal(t, "consent.access.decision", attrs["event.name"])
	assert.Equal(t, "deny", attrs["consent.decision"])
	assert.Equal(t, "no granted consent", attrs["consent.reason"])
	assert.Equal(t, "did:key:zTest", attrs["enduser.id"])
	assert.Equal(t, "GET", attrs["http.request.method"])
	assert.Equal(t, "/ngsi-ld/v1/entities/x", attrs["url.path"])
	assert.Equal(t, "req-1", attrs["http.request.id"])
}

// TestEndpointNormalization verifies the base endpoint gets /v1/logs appended and
// an endpoint already ending in /v1/logs is left untouched.
func TestEndpointNormalization(t *testing.T) {
	assert.Equal(t, "http://c:4318/v1/logs", newEmitter(Config{Endpoint: "http://c:4318"}).endpoint)
	assert.Equal(t, "http://c:4318/v1/logs", newEmitter(Config{Endpoint: "http://c:4318/"}).endpoint)
	assert.Equal(t, "http://c:4318/v1/logs", newEmitter(Config{Endpoint: "http://c:4318/v1/logs"}).endpoint)
}

// TestEmitNeverBlocksWhenQueueFull verifies Emit drops (and counts) events rather
// than blocking the caller when the queue is full and nothing is draining it.
func TestEmitNeverBlocksWhenQueueFull(t *testing.T) {
	e := &Emitter{
		endpoint:    "http://unused/v1/logs",
		serviceName: "x",
		client:      &http.Client{},
		queue:       make(chan Event, 2),
		done:        make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	// no worker draining the queue
	for i := 0; i < 10; i++ {
		e.Emit(Event{})
	}
	assert.GreaterOrEqual(t, e.dropped.Load(), uint64(8), "overflow beyond the queue capacity must be dropped")
}
