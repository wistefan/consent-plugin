/*
 * Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package plugin

import (
	"consent-plugin/internal/logging"
	"consent-plugin/internal/metrics"
	"fmt"
	"sort"
	"sync"
	"time"
)

// RequestContext holds the captured request information the response phase
// needs. It is stored during RequestFilter and retrieved during ResponseFilter.
//
// It deliberately holds no request headers. The only thing the response phase
// needs from the request is the method, the path and the decoded claims; keeping
// a copy of every header would mean retaining the Authorization bearer token for
// the lifetime of the entry, which is precisely the wrong thing to leak when an
// entry outlives its request.
type RequestContext struct {
	// Method is the HTTP method of the original request (e.g., "GET", "POST").
	Method string

	// Path is the URI path of the original request.
	Path string

	// JWTClaims holds the decoded JWT claims extracted from the configured header.
	// The map keys are claim names and values are the claim values.
	JWTClaims map[string]interface{}
}

// Bounds on the request-context store. The store bridges two phases of the same
// HTTP request, so an entry is normally live for the duration of one upstream
// call. Anything still present well after that belongs to a request whose
// response phase will never run.
const (
	// RequestContextTTL is how long an entry may live before the janitor evicts
	// it. It must comfortably exceed the upstream response time of a gated route;
	// evicting too early only means the response phase finds no context and
	// (fail-closed) denies.
	RequestContextTTL = 60 * time.Second

	// requestContextSweepInterval is how often the janitor evicts expired entries.
	requestContextSweepInterval = 10 * time.Second

	// MaxRequestContexts caps how many entries the store may hold. The cap is the
	// backstop against an unauthenticated memory-exhaustion primitive: a client
	// that opens requests and aborts before the response leaks one entry each.
	MaxRequestContexts = 100_000

	// contextEvictionBatch is how many entries an overflow evicts at once.
	//
	// Freeing a single slot per overflow meant a full store paid a whole-map scan
	// on EVERY subsequent request, serialised behind the store's mutex — and the
	// store only reaches the cap under the leak or abort-flood the cap exists to
	// contain. The O(n) path was therefore guaranteed to engage exactly when load
	// was already pathological, converting an unbounded memory leak into an
	// unbounded latency cliff. Evicting a batch amortises the scan over the whole
	// batch, so the cost is paid once per contextEvictionBatch requests instead
	// of once per request.
	contextEvictionBatch = MaxRequestContexts / 100
)

// storedRequestContext is one entry plus the time it was stored, which is what
// makes expiry possible.
type storedRequestContext struct {
	ctx      *RequestContext
	storedAt time.Time
}

// requestContextStore maps a stable per-request key to its captured
// RequestContext. This bridges the RequestFilter and ResponseFilter phases,
// which APISIX invokes as two separate RPC calls (ext-plugin-pre-req and
// ext-plugin-post-resp).
//
// The key MUST be stable across those two phases for the same HTTP request.
// The runner's per-RPC id (Request.ID()/Response.ID()) is NOT stable between
// them, so the Nginx `$request_id` variable is used instead (see
// correlationKey in consent.go).
//
// Entries are normally removed by LoadAndDeleteRequestContext in the response
// phase. That phase does not always run — the client disconnects, the upstream
// times out, an earlier plugin short-circuits the request, ext-plugin-post-resp
// is not attached to the route — and the runner is a long-lived process, so
// without a TTL and a cap the map grows monotonically until the runner is OOM
// killed. Both are enforced here.
var (
	requestContextMu    sync.Mutex
	requestContextStore = map[string]storedRequestContext{}
	// contextsEvicted counts entries removed because they expired or because the
	// store was full, i.e. requests whose response phase never ran. A number that
	// climbs in production means requests are being lost, or the store is being
	// driven deliberately.
	contextsEvicted uint64
	janitorOnce     sync.Once
)

func init() {
	// Publish the store's size and eviction count so a leak is observable rather
	// than only inferable from memory growth.
	metrics.RegisterGauge(metrics.ContextStoreSizeGauge,
		"Request contexts currently held, i.e. gated requests in flight.",
		func() float64 { return float64(RequestContextStoreSize()) })
	metrics.RegisterCounter(metrics.ContextEvictedCounter,
		"Request contexts evicted because they expired or the store was full.",
		func() float64 { return float64(RequestContextsEvicted()) })
}

// startContextJanitor launches the background sweep exactly once. It is started
// lazily from the first Store so that importing the package (as tests and the
// runner registration do) never leaves a goroutine running for nothing.
func startContextJanitor() {
	janitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(requestContextSweepInterval)
			defer ticker.Stop()
			for range ticker.C {
				if n := sweepRequestContexts(time.Now()); n > 0 {
					logging.Warnf("request-context store: evicted %d expired entr(ies), %d remaining",
						n, RequestContextStoreSize())
				}
			}
		}()
	})
}

// StoreRequestContext saves a RequestContext for the given request key.
// It overwrites any previously stored context for the same key.
//
// The store is bounded: when it is full, expired entries are swept first and,
// failing that, a batch of the oldest entries is evicted, so a new request is
// never refused service by a leak from an older one.
func StoreRequestContext(requestKey string, ctx *RequestContext) {
	startContextJanitor()

	requestContextMu.Lock()
	defer requestContextMu.Unlock()

	now := time.Now()
	if len(requestContextStore) >= MaxRequestContexts {
		if _, replacing := requestContextStore[requestKey]; !replacing {
			evictForSpaceLocked(now)
		}
	}
	requestContextStore[requestKey] = storedRequestContext{ctx: ctx, storedAt: now}
}

// evictForSpaceLocked makes room in a full store: expired entries first and, if
// everything is still live, a batch of the oldest. Callers must hold
// requestContextMu.
//
// Both paths scan the map, which is why they free many slots rather than one:
// the next contextEvictionBatch requests then find room without scanning at all.
func evictForSpaceLocked(now time.Time) {
	if n := sweepLocked(now); n > 0 {
		logging.WarnfEvery("context-store-full", "request-context store full (%d), evicted %d expired entr(ies)", MaxRequestContexts, n)
		return
	}
	if n := evictOldestLocked(contextEvictionBatch); n > 0 {
		logging.ErrorfEvery("context-store-overflow",
			"request-context store full (%d) with no expired entries, evicted the %d oldest", MaxRequestContexts, n)
	}
}

// evictOldestLocked removes up to batch of the oldest entries and returns how
// many it removed. Callers must hold requestContextMu.
func evictOldestLocked(batch int) int {
	if batch <= 0 || len(requestContextStore) == 0 {
		return 0
	}
	type aged struct {
		key      string
		storedAt time.Time
	}
	entries := make([]aged, 0, len(requestContextStore))
	for key, entry := range requestContextStore {
		entries = append(entries, aged{key: key, storedAt: entry.storedAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].storedAt.Before(entries[j].storedAt) })

	if batch > len(entries) {
		batch = len(entries)
	}
	for _, entry := range entries[:batch] {
		delete(requestContextStore, entry.key)
	}
	contextsEvicted += uint64(batch)
	return batch
}

// sweepRequestContexts removes every entry stored more than RequestContextTTL
// before now and returns how many were removed.
func sweepRequestContexts(now time.Time) int {
	requestContextMu.Lock()
	defer requestContextMu.Unlock()
	return sweepLocked(now)
}

// sweepLocked is sweepRequestContexts for a caller already holding the mutex.
func sweepLocked(now time.Time) int {
	evicted := 0
	for key, entry := range requestContextStore {
		if now.Sub(entry.storedAt) > RequestContextTTL {
			delete(requestContextStore, key)
			evicted++
		}
	}
	contextsEvicted += uint64(evicted)
	return evicted
}

// RequestContextStoreSize reports how many request contexts are currently held.
// It is the gauge that makes a leak observable: in a healthy runner it tracks
// the number of in-flight gated requests and returns to zero when idle.
func RequestContextStoreSize() int {
	requestContextMu.Lock()
	defer requestContextMu.Unlock()
	return len(requestContextStore)
}

// RequestContextsEvicted reports how many contexts have been evicted because
// they expired or the store was full — i.e. how many requests never reached
// their response phase.
func RequestContextsEvicted() uint64 {
	requestContextMu.Lock()
	defer requestContextMu.Unlock()
	return contextsEvicted
}

// LoadAndDeleteRequestContext atomically loads and removes the stored
// RequestContext for the given request key. This is how the response phase
// consumes a context: retrieval and cleanup in a single operation. An entry that
// has outlived RequestContextTTL is reported as absent (and removed), so a
// stale context can never decide a fresh request.
func LoadAndDeleteRequestContext(requestKey string) (*RequestContext, bool) {
	requestContextMu.Lock()
	defer requestContextMu.Unlock()

	entry, ok := requestContextStore[requestKey]
	if !ok {
		return nil, false
	}
	delete(requestContextStore, requestKey)
	if time.Since(entry.storedAt) > RequestContextTTL {
		contextsEvicted++
		return nil, false
	}
	return entry.ctx, true
}

// String returns a human-readable representation of the RequestContext,
// useful for logging and debugging.
func (rc *RequestContext) String() string {
	return fmt.Sprintf("RequestContext{Method: %s, Path: %s, Claims: %d}",
		rc.Method, rc.Path, len(rc.JWTClaims))
}
