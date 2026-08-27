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
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearContextStore resets the package-level request context store between tests.
func clearContextStore() {
	requestContextMu.Lock()
	defer requestContextMu.Unlock()
	requestContextStore = map[string]storedRequestContext{}
	contextsEvicted = 0
}

// storeAt stores a context as if it had been captured at the given time, so
// expiry can be exercised without waiting for it.
func storeAt(key string, ctx *RequestContext, at time.Time) {
	requestContextMu.Lock()
	defer requestContextMu.Unlock()
	requestContextStore[key] = storedRequestContext{ctx: ctx, storedAt: at}
}

func TestStoreAndLoadAndDeleteRequestContext(t *testing.T) {
	tests := []struct {
		name      string
		requestID uint32
		ctx       *RequestContext
	}{
		{
			name:      "context with claims",
			requestID: 1,
			ctx: &RequestContext{
				Method:    "GET",
				Path:      "/api/users/123",
				JWTClaims: map[string]interface{}{"sub": "did:key:z42"},
			},
		},
		{
			name:      "context without claims",
			requestID: 2,
			ctx:       &RequestContext{Method: "POST", Path: "/api/data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearContextStore()
			defer clearContextStore()

			StoreRequestContext(testReqKey(tt.requestID), tt.ctx)
			assert.Equal(t, 1, RequestContextStoreSize())

			loaded, ok := LoadAndDeleteRequestContext(testReqKey(tt.requestID))
			require.True(t, ok)
			assert.Equal(t, tt.ctx, loaded)

			_, ok = LoadAndDeleteRequestContext(testReqKey(tt.requestID))
			assert.False(t, ok, "consuming a context must remove it")
			assert.Equal(t, 0, RequestContextStoreSize())
		})
	}
}

func TestLoadAndDeleteRequestContext_NotFound(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	loaded, ok := LoadAndDeleteRequestContext(testReqKey(999))
	assert.False(t, ok)
	assert.Nil(t, loaded)
}

func TestStoreRequestContext_OverwritesExisting(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const requestID = uint32(10)
	StoreRequestContext(testReqKey(requestID), &RequestContext{Method: "GET", Path: "/first"})
	StoreRequestContext(testReqKey(requestID), &RequestContext{Method: "POST", Path: "/second"})

	assert.Equal(t, 1, RequestContextStoreSize(), "overwriting must not grow the store")

	loaded, ok := LoadAndDeleteRequestContext(testReqKey(requestID))
	require.True(t, ok)
	assert.Equal(t, "/second", loaded.Path)
}

// TestRequestContext_ExpiredIsNotServed verifies an entry that outlived the TTL
// is reported as absent (and removed) rather than deciding a fresh request.
func TestRequestContext_ExpiredIsNotServed(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	key := testReqKey(20)
	storeAt(key, &RequestContext{Method: "GET", Path: "/stale"}, time.Now().Add(-RequestContextTTL-time.Second))

	loaded, ok := LoadAndDeleteRequestContext(key)
	assert.False(t, ok, "an expired context must not be served")
	assert.Nil(t, loaded)
	assert.Equal(t, 0, RequestContextStoreSize())
	assert.Equal(t, uint64(1), RequestContextsEvicted())
}

// TestSweepRequestContexts verifies the janitor evicts exactly the entries whose
// response phase never ran, leaving live ones alone. Without it, every aborted
// request leaks an entry for the lifetime of the runner.
func TestSweepRequestContexts(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	now := time.Now()
	storeAt("expired-1", &RequestContext{Path: "/a"}, now.Add(-RequestContextTTL-time.Second))
	storeAt("expired-2", &RequestContext{Path: "/b"}, now.Add(-2*RequestContextTTL))
	storeAt("live", &RequestContext{Path: "/c"}, now)

	assert.Equal(t, 2, sweepRequestContexts(now))
	assert.Equal(t, 1, RequestContextStoreSize())
	assert.Equal(t, uint64(2), RequestContextsEvicted())

	loaded, ok := LoadAndDeleteRequestContext("live")
	require.True(t, ok)
	assert.Equal(t, "/c", loaded.Path)
}

// TestStoreRequestContext_EnforcesCap verifies a full store makes room instead
// of growing without bound — the backstop against a client that opens requests
// and aborts before the response phase.
//
// It also pins the amortisation: an overflow evicts a BATCH, so the whole-map
// scan is paid once per contextEvictionBatch requests rather than on every
// request. Freeing one slot at a time turned the cap from a memory bound into a
// latency cliff, engaging precisely under the flood the cap exists to contain.
func TestStoreRequestContext_EnforcesCap(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	now := time.Now()
	requestContextMu.Lock()
	for i := 0; i < MaxRequestContexts; i++ {
		// All live, so no sweep can free anything: the oldest must be evicted.
		requestContextStore[fmt.Sprintf("live-%d", i)] = storedRequestContext{
			ctx:      &RequestContext{Path: "/x"},
			storedAt: now.Add(time.Duration(i) * time.Millisecond),
		}
	}
	requestContextMu.Unlock()

	StoreRequestContext("newest", &RequestContext{Path: "/new"})

	assert.Equal(t, MaxRequestContexts-contextEvictionBatch+1, RequestContextStoreSize(),
		"an overflow must evict a batch, not a single entry")
	assert.Equal(t, uint64(contextEvictionBatch), RequestContextsEvicted())

	// The batch taken is the oldest one.
	_, ok := LoadAndDeleteRequestContext("live-0")
	assert.False(t, ok, "the oldest entries are the ones evicted")
	_, ok = LoadAndDeleteRequestContext(fmt.Sprintf("live-%d", contextEvictionBatch-1))
	assert.False(t, ok, "the whole oldest batch is evicted")
	_, ok = LoadAndDeleteRequestContext(fmt.Sprintf("live-%d", contextEvictionBatch))
	assert.True(t, ok, "entries beyond the batch survive")
	_, ok = LoadAndDeleteRequestContext("newest")
	assert.True(t, ok, "the new request must still be served")
}

// TestStoreRequestContext_EvictionIsAmortised verifies the requests following an
// overflow are served from the headroom the batch freed, without evicting (and
// therefore without scanning) again.
func TestStoreRequestContext_EvictionIsAmortised(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	now := time.Now()
	requestContextMu.Lock()
	for i := 0; i < MaxRequestContexts; i++ {
		requestContextStore[fmt.Sprintf("live-%d", i)] = storedRequestContext{
			ctx:      &RequestContext{Path: "/x"},
			storedAt: now.Add(time.Duration(i) * time.Millisecond),
		}
	}
	requestContextMu.Unlock()

	StoreRequestContext("overflow", &RequestContext{Path: "/new"})
	evictedAfterFirst := RequestContextsEvicted()
	require.Equal(t, uint64(contextEvictionBatch), evictedAfterFirst)

	// The batch freed contextEvictionBatch slots and one was consumed by the
	// store above, so this many more fit without any further eviction.
	for i := 0; i < contextEvictionBatch-1; i++ {
		StoreRequestContext(fmt.Sprintf("after-%d", i), &RequestContext{Path: "/y"})
	}

	assert.Equal(t, evictedAfterFirst, RequestContextsEvicted(),
		"requests within the freed headroom must not trigger another scan")
	assert.Equal(t, MaxRequestContexts, RequestContextStoreSize())
}

// TestRequestContext_HoldsNoHeaders pins the property that made a leaked entry a
// credential leak: the context must not retain the request's Authorization
// header (or any other).
func TestRequestContext_HoldsNoHeaders(t *testing.T) {
	rc := RequestContext{}
	assert.Equal(t, 3, reflectFieldCount(rc), "RequestContext must hold only Method, Path and JWTClaims")
}

func TestRequestContext_String(t *testing.T) {
	tests := []struct {
		name     string
		ctx      *RequestContext
		expected string
	}{
		{
			name: "full context",
			ctx: &RequestContext{
				Method:    "GET",
				Path:      "/api/users",
				JWTClaims: map[string]interface{}{"sub": "u", "scope": "read"},
			},
			expected: "RequestContext{Method: GET, Path: /api/users, Claims: 2}",
		},
		{
			name:     "empty context",
			ctx:      &RequestContext{},
			expected: "RequestContext{Method: , Path: , Claims: 0}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ctx.String())
		})
	}
}

func TestConcurrentStoreLoadAndDelete(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const goroutineCount = 100
	var wg sync.WaitGroup

	for i := uint32(0); i < goroutineCount; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			StoreRequestContext(testReqKey(id), &RequestContext{
				Method:    "GET",
				Path:      fmt.Sprintf("/api/resource/%d", id),
				JWTClaims: map[string]interface{}{"sub": fmt.Sprintf("user-%d", id)},
			})
		}(i)
	}
	wg.Wait()
	assert.Equal(t, int(goroutineCount), RequestContextStoreSize())

	// Each id must be loaded successfully exactly once across all goroutines.
	results := make([]bool, goroutineCount)
	for i := uint32(0); i < goroutineCount; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			loaded, ok := LoadAndDeleteRequestContext(testReqKey(id))
			results[id] = ok && loaded.Path == fmt.Sprintf("/api/resource/%d", id)
		}(i)
	}
	wg.Wait()

	for i := uint32(0); i < goroutineCount; i++ {
		assert.True(t, results[i], "LoadAndDelete should succeed for ID %d", i)
	}
	assert.Equal(t, 0, RequestContextStoreSize())
}

// reflectFieldCount returns how many fields a struct value has.
func reflectFieldCount(v interface{}) int {
	return reflect.TypeOf(v).NumField()
}
