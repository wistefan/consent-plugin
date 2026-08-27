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
	"testing"
	"time"
)

// fillContextStore populates the store with n live entries of ascending age.
func fillContextStore(n int) {
	now := time.Now()
	requestContextMu.Lock()
	defer requestContextMu.Unlock()
	requestContextStore = make(map[string]storedRequestContext, n)
	for i := 0; i < n; i++ {
		requestContextStore[fmt.Sprintf("live-%d", i)] = storedRequestContext{
			ctx:      &RequestContext{Path: "/x"},
			storedAt: now.Add(time.Duration(i) * time.Microsecond),
		}
	}
}

// BenchmarkStoreRequestContext measures the ordinary path: a store with room.
func BenchmarkStoreRequestContext(b *testing.B) {
	fillContextStore(0)
	b.Cleanup(clearContextStore)

	ctx := &RequestContext{Method: "GET", Path: "/data"}
	for i := 0; b.Loop(); i++ {
		StoreRequestContext(fmt.Sprintf("key-%d", i), ctx)
	}
}

// BenchmarkStoreRequestContextAtCap measures the overflow path, which is the
// one that matters: the store only reaches its cap under the leak or the
// abort-flood the cap exists to contain, so this is the cost the gate pays
// exactly when it is already under pressure.
//
// Evicting one entry per overflow made every request at the cap pay two
// whole-map scans under the store's mutex. Evicting a batch amortises that over
// contextEvictionBatch requests, so the per-request cost here should stay close
// to the uncontended case above rather than scaling with MaxRequestContexts.
func BenchmarkStoreRequestContextAtCap(b *testing.B) {
	fillContextStore(MaxRequestContexts)
	b.Cleanup(clearContextStore)

	ctx := &RequestContext{Method: "GET", Path: "/data"}
	for i := 0; b.Loop(); i++ {
		StoreRequestContext(fmt.Sprintf("overflow-%d", i), ctx)
	}
}
