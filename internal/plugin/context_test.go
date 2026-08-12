package plugin

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearContextStore resets the package-level request context store between tests.
func clearContextStore() {
	requestContextStore.Range(func(key, _ interface{}) bool {
		requestContextStore.Delete(key)
		return true
	})
}

func TestStoreAndLoadRequestContext(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	tests := []struct {
		name      string
		requestID uint32
		ctx       *RequestContext
	}{
		{
			name:      "store and load basic context",
			requestID: 1,
			ctx: &RequestContext{
				Method:    "GET",
				Path:      "/api/users",
				Headers:   http.Header{"Authorization": []string{"Bearer token1"}},
				JWTClaims: map[string]interface{}{"sub": "user-1"},
			},
		},
		{
			name:      "store and load context with empty claims",
			requestID: 2,
			ctx: &RequestContext{
				Method:    "POST",
				Path:      "/api/data",
				Headers:   http.Header{},
				JWTClaims: map[string]interface{}{},
			},
		},
		{
			name:      "store and load context with nil claims",
			requestID: 3,
			ctx: &RequestContext{
				Method:    "DELETE",
				Path:      "/api/users/123",
				Headers:   nil,
				JWTClaims: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			StoreRequestContext(testReqKey(tt.requestID), tt.ctx)

			loaded, ok := LoadRequestContext(testReqKey(tt.requestID))
			require.True(t, ok, "expected context to be found")
			assert.Equal(t, tt.ctx, loaded)
		})
	}
}

func TestLoadRequestContext_NotFound(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const nonExistentID uint32 = 99999
	loaded, ok := LoadRequestContext(testReqKey(nonExistentID))
	assert.False(t, ok, "expected context not to be found")
	assert.Nil(t, loaded)
}

func TestDeleteRequestContext(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const requestID uint32 = 10
	ctx := &RequestContext{
		Method: "GET",
		Path:   "/api/test",
	}

	StoreRequestContext(testReqKey(requestID), ctx)

	// Verify it's stored.
	loaded, ok := LoadRequestContext(testReqKey(requestID))
	require.True(t, ok)
	assert.Equal(t, ctx, loaded)

	// Delete it.
	DeleteRequestContext(testReqKey(requestID))

	// Verify it's gone.
	loaded, ok = LoadRequestContext(testReqKey(requestID))
	assert.False(t, ok)
	assert.Nil(t, loaded)
}

func TestLoadAndDeleteRequestContext(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const requestID uint32 = 20
	ctx := &RequestContext{
		Method:    "PUT",
		Path:      "/api/resource",
		JWTClaims: map[string]interface{}{"sub": "user-20"},
	}

	StoreRequestContext(testReqKey(requestID), ctx)

	// LoadAndDelete should return the context.
	loaded, ok := LoadAndDeleteRequestContext(testReqKey(requestID))
	require.True(t, ok)
	assert.Equal(t, ctx, loaded)

	// Subsequent load should fail — already deleted.
	loaded, ok = LoadRequestContext(testReqKey(requestID))
	assert.False(t, ok)
	assert.Nil(t, loaded)
}

func TestLoadAndDeleteRequestContext_NotFound(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const nonExistentID uint32 = 88888
	loaded, ok := LoadAndDeleteRequestContext(testReqKey(nonExistentID))
	assert.False(t, ok)
	assert.Nil(t, loaded)
}

func TestStoreRequestContext_OverwritesExisting(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const requestID uint32 = 30
	original := &RequestContext{
		Method: "GET",
		Path:   "/original",
	}
	replacement := &RequestContext{
		Method: "POST",
		Path:   "/replacement",
	}

	StoreRequestContext(testReqKey(requestID), original)
	StoreRequestContext(testReqKey(requestID), replacement)

	loaded, ok := LoadRequestContext(testReqKey(requestID))
	require.True(t, ok)
	assert.Equal(t, replacement, loaded)
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
				Headers:   http.Header{"Auth": []string{"val"}},
				JWTClaims: map[string]interface{}{"sub": "u1", "scope": "read"},
			},
			expected: "RequestContext{Method: GET, Path: /api/users, Claims: 2, Headers: 1}",
		},
		{
			name: "empty context",
			ctx: &RequestContext{
				Method:    "",
				Path:      "",
				Headers:   nil,
				JWTClaims: nil,
			},
			expected: "RequestContext{Method: , Path: , Claims: 0, Headers: 0}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ctx.String())
		})
	}
}

func TestConcurrentStoreAndLoad(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const goroutineCount = 100
	var wg sync.WaitGroup

	// Concurrently store contexts with different IDs.
	for i := uint32(0); i < goroutineCount; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			ctx := &RequestContext{
				Method:    "GET",
				Path:      fmt.Sprintf("/api/resource/%d", id),
				JWTClaims: map[string]interface{}{"sub": fmt.Sprintf("user-%d", id)},
			}
			StoreRequestContext(testReqKey(id), ctx)
		}(i)
	}
	wg.Wait()

	// Concurrently load and verify all contexts.
	for i := uint32(0); i < goroutineCount; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			loaded, ok := LoadRequestContext(testReqKey(id))
			assert.True(t, ok, "context for ID %d should exist", id)
			if ok {
				expectedPath := fmt.Sprintf("/api/resource/%d", id)
				assert.Equal(t, expectedPath, loaded.Path)
			}
		}(i)
	}
	wg.Wait()

	// Concurrently delete all contexts.
	for i := uint32(0); i < goroutineCount; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			DeleteRequestContext(testReqKey(id))
		}(i)
	}
	wg.Wait()

	// Verify all contexts are gone.
	for i := uint32(0); i < goroutineCount; i++ {
		_, ok := LoadRequestContext(testReqKey(i))
		assert.False(t, ok, "context for ID %d should have been deleted", i)
	}
}

func TestConcurrentLoadAndDelete(t *testing.T) {
	clearContextStore()
	defer clearContextStore()

	const goroutineCount = 100
	var wg sync.WaitGroup

	// Pre-populate the store.
	for i := uint32(0); i < goroutineCount; i++ {
		StoreRequestContext(testReqKey(i), &RequestContext{
			Method: "GET",
			Path:   fmt.Sprintf("/api/%d", i),
		})
	}

	// Concurrently LoadAndDelete — each ID should be successfully loaded
	// exactly once across all goroutines.
	results := make([]bool, goroutineCount)
	for i := uint32(0); i < goroutineCount; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			_, ok := LoadAndDeleteRequestContext(testReqKey(id))
			results[id] = ok
		}(i)
	}
	wg.Wait()

	for i := uint32(0); i < goroutineCount; i++ {
		assert.True(t, results[i], "LoadAndDelete should succeed for ID %d", i)
	}

	// Verify everything is deleted.
	for i := uint32(0); i < goroutineCount; i++ {
		_, ok := LoadRequestContext(testReqKey(i))
		assert.False(t, ok, "context for ID %d should have been deleted", i)
	}
}
