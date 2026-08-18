// Package audit emits access-decision events from the consent-filter plugin to
// an OpenTelemetry Collector as OTLP/HTTP log records. Each record carries a
// dedicated resource service.name so the Collector can route audit logs to a
// separate, append-only sink, cleanly apart from traces (see the OTEL section of
// doc/CONSENT_MANAGEMENT.md).
//
// Emission is asynchronous and best-effort: Emit never blocks the request path,
// events are batched by a background worker, and the queue drops (with a counter)
// when full - so a slow or absent Collector can never stall data access. The
// Collector plus its sink provide the durability/retention guarantees; the
// plugin -> Collector hop is buffered, at-most-once.
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultServiceName is the resource service.name stamped on audit records when
// none is configured. It is the marker the Collector routes on to keep audit
// logs separate from ordinary telemetry.
const DefaultServiceName = "consent-access-audit"

// scopeName identifies the instrumentation that produced the records.
const scopeName = "consent-plugin/audit"

// otlpLogsPath is the OTLP/HTTP logs path appended to the configured base endpoint.
const otlpLogsPath = "/v1/logs"

// severityInfo is the OTLP severity number for an informational record (both
// allow and deny are normal decisions; the decision is carried as an attribute).
const severityInfo = 9

// Exporter tuning. The queue is bounded so a stalled Collector cannot grow memory
// without limit; excess events are dropped rather than blocking the request path.
const (
	defaultQueueSize     = 2048
	defaultBatchSize     = 64
	defaultFlushInterval = 2 * time.Second
	defaultTimeout       = 5 * time.Second
)

// Config configures an Emitter.
type Config struct {
	// Endpoint is the OTLP/HTTP base endpoint of the Collector (e.g.
	// http://otel-collector:4318); otlpLogsPath is appended unless already present.
	Endpoint string
	// ServiceName is the resource service.name stamped on every record (the
	// routing marker). Empty defaults to DefaultServiceName.
	ServiceName string
	// Timeout bounds a single export HTTP call. Zero defaults to defaultTimeout.
	Timeout time.Duration
}

// Event is a single access decision to record.
type Event struct {
	// Time is when the decision was made.
	Time time.Time
	// RequestID correlates the record with the request (the Nginx $request_id).
	RequestID string
	// Subject is the data subject the decision was made for (the access-token sub).
	Subject string
	// Resource is the requested path.
	Resource string
	// Method is the HTTP method.
	Method string
	// Decision is "allow" or "deny".
	Decision string
	// Reason is a short human-readable explanation of the decision.
	Reason string
}

// Emitter asynchronously exports audit Events as OTLP log records to a Collector.
type Emitter struct {
	endpoint    string
	serviceName string
	client      *http.Client
	queue       chan Event
	done        chan struct{}
	stopped     chan struct{}
	dropped     atomic.Uint64
	stopOnce    sync.Once
}

var (
	emittersMu sync.Mutex
	emitters   = map[string]*Emitter{}
)

// Get returns a shared Emitter for cfg, creating (and starting) one on first use.
// Emitters are cached by endpoint + service name, so all routes exporting to the
// same Collector share a single background worker and connection pool.
func Get(cfg Config) *Emitter {
	sn := cfg.ServiceName
	if sn == "" {
		sn = DefaultServiceName
	}
	key := cfg.Endpoint + "|" + sn

	emittersMu.Lock()
	defer emittersMu.Unlock()
	if e := emitters[key]; e != nil {
		return e
	}
	e := newEmitter(cfg)
	emitters[key] = e
	return e
}

// newEmitter builds and starts an Emitter for cfg.
func newEmitter(cfg Config) *Emitter {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = DefaultServiceName
	}
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if !strings.HasSuffix(endpoint, otlpLogsPath) {
		endpoint += otlpLogsPath
	}
	e := &Emitter{
		endpoint:    endpoint,
		serviceName: serviceName,
		client:      &http.Client{Timeout: timeout},
		queue:       make(chan Event, defaultQueueSize),
		done:        make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	go e.run()
	return e
}

// Emit queues ev for export. It never blocks: if the queue is full the event is
// dropped and a counter is incremented (data access must not wait on the audit
// pipe). Emit is safe for concurrent use.
func (e *Emitter) Emit(ev Event) {
	select {
	case e.queue <- ev:
	default:
		if n := e.dropped.Add(1); n%100 == 1 {
			log.Printf("[consent-filter] audit queue full, dropping event (total dropped %d)", n)
		}
	}
}

// Shutdown stops the background worker after flushing everything still queued.
// Intended for clean teardown and tests; the plugin runner is long-lived and
// normally never calls it.
func (e *Emitter) Shutdown() {
	e.stopOnce.Do(func() { close(e.done) })
	<-e.stopped
}

// run is the background worker: it batches queued events and exports them on a
// size or time trigger, and drains + flushes on shutdown.
func (e *Emitter) run() {
	defer close(e.stopped)
	batch := make([]Event, 0, defaultBatchSize)
	ticker := time.NewTicker(defaultFlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) > 0 {
			e.export(batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case ev := <-e.queue:
			batch = append(batch, ev)
			if len(batch) >= defaultBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-e.done:
			for {
				select {
				case ev := <-e.queue:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

// export POSTs a batch as an OTLP/HTTP logs payload. Failures are logged and
// dropped - audit export must not surface into the request path.
func (e *Emitter) export(batch []Event) {
	body, err := json.Marshal(e.buildPayload(batch))
	if err != nil {
		log.Printf("[consent-filter] audit: failed to marshal %d event(s): %v", len(batch), err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("[consent-filter] audit: failed to build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		log.Printf("[consent-filter] audit: export to %s failed: %v", e.endpoint, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= http.StatusMultipleChoices {
		log.Printf("[consent-filter] audit: export to %s returned HTTP %d", e.endpoint, resp.StatusCode)
	}
}

// --- OTLP/HTTP JSON encoding (proto3 JSON mapping) --------------------------

type otlpPayload struct {
	ResourceLogs []resourceLogs `json:"resourceLogs"`
}

type resourceLogs struct {
	Resource  otlpResource `json:"resource"`
	ScopeLogs []scopeLogs  `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []keyValue `json:"attributes"`
}

type scopeLogs struct {
	Scope      instrumentationScope `json:"scope"`
	LogRecords []logRecord          `json:"logRecords"`
}

type instrumentationScope struct {
	Name string `json:"name"`
}

type logRecord struct {
	TimeUnixNano         string     `json:"timeUnixNano"`
	ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
	SeverityNumber       int        `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 anyValue   `json:"body"`
	Attributes           []keyValue `json:"attributes"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

// anyValue is the OTLP AnyValue; only the string variant is used here.
type anyValue struct {
	StringValue string `json:"stringValue"`
}

// buildPayload maps a batch of events to a single OTLP logs payload. The routing
// marker lives on the resource (service.name); the per-decision fields are log
// attributes using OpenTelemetry semantic-convention keys where they exist.
func (e *Emitter) buildPayload(batch []Event) otlpPayload {
	records := make([]logRecord, 0, len(batch))
	for _, ev := range batch {
		ts := strconv.FormatInt(ev.Time.UnixNano(), 10)
		records = append(records, logRecord{
			TimeUnixNano:         ts,
			ObservedTimeUnixNano: ts,
			SeverityNumber:       severityInfo,
			SeverityText:         "INFO",
			Body:                 anyValue{StringValue: "consent access decision"},
			Attributes: []keyValue{
				{Key: "event.domain", Value: anyValue{StringValue: "audit"}},
				{Key: "event.name", Value: anyValue{StringValue: "consent.access.decision"}},
				{Key: "consent.decision", Value: anyValue{StringValue: ev.Decision}},
				{Key: "consent.reason", Value: anyValue{StringValue: ev.Reason}},
				{Key: "enduser.id", Value: anyValue{StringValue: ev.Subject}},
				{Key: "http.request.method", Value: anyValue{StringValue: ev.Method}},
				{Key: "url.path", Value: anyValue{StringValue: ev.Resource}},
				{Key: "http.request.id", Value: anyValue{StringValue: ev.RequestID}},
			},
		})
	}
	return otlpPayload{ResourceLogs: []resourceLogs{{
		Resource:  otlpResource{Attributes: []keyValue{{Key: "service.name", Value: anyValue{StringValue: e.serviceName}}}},
		ScopeLogs: []scopeLogs{{Scope: instrumentationScope{Name: scopeName}, LogRecords: records}},
	}}}
}
