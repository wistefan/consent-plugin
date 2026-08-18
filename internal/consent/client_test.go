package consent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCM is a configurable mock consent-manager covering the four endpoints the
// client uses: /participants/login, /participants/me, /users/identifier/search
// and /consents/participants/{id}.
type mockCM struct {
	mu sync.Mutex
	// behaviour
	userID             string   // identifier-search result ("" => 404)
	statuses           []string // consents statuses
	selfDescriptionURL string   // /me result
	loginStatus        int      // non-200 => login fails with this status
	failFirstConsents  bool     // first consents call 401s, then succeeds
	// recording
	loginCalls, meCalls, searchCalls, consentsCalls int
	lastConsentKey, lastSearchEmail, lastSearchSD   string
	lastConsentsAuth, lastLoginAuthClientID         string
	tokenCounter                                    int
}

func newMockCM(t *testing.T, m *mockCM) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/participants/login", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.loginCalls++
		m.lastLoginAuthClientID = body["clientID"]
		st := m.loginStatus
		m.tokenCounter++
		tok := fmt.Sprintf("token-%d", m.tokenCounter)
		m.mu.Unlock()
		if st != 0 && st != http.StatusOK {
			w.WriteHeader(st)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "jwt": tok})
	})

	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.meCalls++
		sd := m.selfDescriptionURL
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"selfDescriptionURL": sd})
	})

	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		m.mu.Lock()
		m.searchCalls++
		m.lastConsentKey = r.Header.Get(consentKeyHeader)
		m.lastSearchEmail = body["email"]
		m.lastSearchSD = body["selfDescription"]
		uid := m.userID
		m.mu.Unlock()
		if uid == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": uid})
	})

	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.consentsCalls++
		n := m.consentsCalls
		m.lastConsentsAuth = r.Header.Get("Authorization")
		fail := m.failFirstConsents
		sts := append([]string(nil), m.statuses...)
		m.mu.Unlock()
		if fail && n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		consents := make([]map[string]string, 0, len(sts))
		for _, s := range sts {
			consents = append(consents, map[string]string{"status": s})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consents})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// resetCredCache clears the package-wide credential cache between tests.
func resetCredCache() {
	credCacheMu.Lock()
	credCache = map[string]*cacheEntry{}
	credCacheMu.Unlock()
}

// TestNewClient verifies the constructor applies defaults and stores parameters.
func TestNewClient(t *testing.T) {
	c := NewClient(ClientConfig{BaseURL: "http://cm:3000", ConsentKey: "ck", ClientID: "cid", ClientSecret: "sec"})
	assert.Equal(t, "http://cm:3000", c.baseURL)
	assert.Equal(t, DefaultAPIPrefix, c.apiPrefix, "empty prefix defaults to /v1")
	assert.Equal(t, DefaultTokenTTL, c.tokenTTL, "zero ttl defaults")
	assert.Equal(t, time.Duration(DefaultTimeoutMs)*time.Millisecond, c.httpClient.Timeout, "zero timeout defaults")

	c2 := NewClient(ClientConfig{APIPrefix: "/v2", TokenTTL: time.Minute, TimeoutMs: 1234})
	assert.Equal(t, "/v2", c2.apiPrefix)
	assert.Equal(t, time.Minute, c2.tokenTTL)
	assert.Equal(t, 1234*time.Millisecond, c2.httpClient.Timeout)
}

// TestCheckConsent covers the two-call decision matrix using a static token + SD
// (no login/me involved).
func TestCheckConsent(t *testing.T) {
	const (
		subject = "did:key:zSubject"
		provSD  = "http://consent-facade:8080/participants/org-1"
		uid     = "6a71e3567917ddaef2e2c866"
	)
	tests := []struct {
		name         string
		userID       string
		statuses     []string
		wantDecision Decision
	}{
		{name: "granted -> allow", userID: uid, statuses: []string{"granted"}, wantDecision: DecisionAllow},
		{name: "one of many granted -> allow", userID: uid, statuses: []string{"revoked", "granted"}, wantDecision: DecisionAllow},
		{name: "only revoked -> deny", userID: uid, statuses: []string{"revoked"}, wantDecision: DecisionDeny},
		{name: "no consents -> deny", userID: uid, statuses: []string{}, wantDecision: DecisionDeny},
		{name: "unknown subject (404) -> deny", userID: "", statuses: nil, wantDecision: DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetCredCache()
			m := &mockCM{userID: tt.userID, statuses: tt.statuses}
			srv := newMockCM(t, m)
			c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ParticipantToken: "static-token", ProviderSD: provSD})

			resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: subject})
			require.NoError(t, err)
			assert.Equal(t, tt.wantDecision, resp.Decision)

			m.mu.Lock()
			defer m.mu.Unlock()
			assert.Equal(t, 0, m.loginCalls, "static token must not trigger login")
			assert.Equal(t, 0, m.meCalls, "static SD must not trigger /me")
			assert.Equal(t, "ck", m.lastConsentKey)
			assert.Equal(t, provSD, m.lastSearchSD)
			assert.Equal(t, subject, m.lastSearchEmail)
			if tt.userID != "" {
				assert.Equal(t, "Bearer static-token", m.lastConsentsAuth)
			}
		})
	}
}

// TestCheckConsent_ClientCredentials verifies the full client-credentials flow:
// login for a token, derive the provider SD from /me, then run the two calls.
func TestCheckConsent_ClientCredentials(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "http://facade/participants/derived"}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ClientID: "consent-demo-provider", ClientSecret: "demo"})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.loginCalls)
	assert.Equal(t, "consent-demo-provider", m.lastLoginAuthClientID)
	assert.Equal(t, 1, m.meCalls)
	assert.Equal(t, "http://facade/participants/derived", m.lastSearchSD, "SD derived from /me is used in the search")
	assert.Equal(t, "Bearer token-1", m.lastConsentsAuth, "the fetched token is used on the consents call")
}

// TestCheckConsent_TokenAndSDCached verifies the token and derived SD are cached
// across calls (login + /me happen once).
func TestCheckConsent_TokenAndSDCached(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "http://facade/participants/derived"}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ClientID: "cid", ClientSecret: "sec"})

	for i := 0; i < 3; i++ {
		resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
		require.NoError(t, err)
		assert.Equal(t, DecisionAllow, resp.Decision)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.loginCalls, "token should be cached across calls")
	assert.Equal(t, 1, m.meCalls, "provider SD should be cached across calls")
	assert.Equal(t, 3, m.consentsCalls)
}

// TestCheckConsent_401RefreshRetry verifies a 401 on the consents call triggers a
// re-login and a single retry.
func TestCheckConsent_401RefreshRetry(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "http://facade/sd", failFirstConsents: true}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ClientID: "cid", ClientSecret: "sec"})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 2, m.loginCalls, "401 should force a re-login")
	assert.Equal(t, 2, m.consentsCalls, "the consents call should be retried once")
	assert.Equal(t, "Bearer token-2", m.lastConsentsAuth, "the retry uses the refreshed token")
}

// TestCheckConsent_LoginFailure surfaces a login error.
func TestCheckConsent_LoginFailure(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, loginStatus: http.StatusNotFound}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ClientID: "cid", ClientSecret: "wrong"})

	_, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "participant login returned status 404")
}

// TestCheckConsent_ProviderSDOverride verifies an explicit provider_sd skips /me
// while still using client credentials for the token.
func TestCheckConsent_ProviderSDOverride(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ClientID: "cid", ClientSecret: "sec", ProviderSD: "http://facade/explicit"})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.loginCalls, "token still comes from login")
	assert.Equal(t, 0, m.meCalls, "explicit provider_sd skips /me")
	assert.Equal(t, "http://facade/explicit", m.lastSearchSD)
}

// TestCheckConsent_EmptySubject denies without contacting the consent-manager.
func TestCheckConsent_EmptySubject(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid", statuses: []string{"granted"}}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ClientID: "cid", ClientSecret: "sec"})

	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: ""})
	require.NoError(t, err)
	assert.Equal(t, DecisionDeny, resp.Decision)
	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 0, m.loginCalls)
	assert.Equal(t, 0, m.searchCalls)
}

// TestCheckConsent_MissingCredentials errors when neither a static token nor
// client credentials are configured.
func TestCheckConsent_MissingCredentials(t *testing.T) {
	resetCredCache()
	c := NewClient(ClientConfig{BaseURL: "http://cm:3000", ConsentKey: "ck"})
	_, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no participant_token and no client_id/client_secret")
}

// TestCheckConsent_EmptyConsentKeyOmitsHeader verifies that an empty consent key
// is allowed (it is optional — injected by the facade when present) and that the
// x-visionstrust-consent-key header is then not sent at all, rather than sent empty.
func TestCheckConsent_EmptyConsentKeyOmitsHeader(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}}
	srv := newMockCM(t, m)
	c := NewClient(ClientConfig{BaseURL: srv.URL, ParticipantToken: "t", ProviderSD: "sd"})
	resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, resp.Decision)
	assert.Empty(t, m.lastConsentKey, "empty consent key must not be sent as a header")
}

// TestCheckConsent_ConcurrentLoginCoalesced verifies that concurrent first
// requests for the same participant coalesce onto a single client-credentials
// login (no stampede) and a single /me fetch, rather than one per goroutine.
func TestCheckConsent_ConcurrentLoginCoalesced(t *testing.T) {
	resetCredCache()
	m := &mockCM{userID: "uid-1", statuses: []string{"granted"}, selfDescriptionURL: "sd"}
	srv := newMockCM(t, m)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Same base URL + client id => same cache key, so the login must coalesce.
			c := NewClient(ClientConfig{BaseURL: srv.URL, ClientID: "cid", ClientSecret: "sec"})
			resp, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
			if err != nil {
				errs <- err
			} else if resp.Decision != DecisionAllow {
				errs <- fmt.Errorf("decision = %v, want allow", resp.Decision)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	assert.Equal(t, 1, m.loginCalls, "concurrent first requests must coalesce onto one login")
	assert.Equal(t, 1, m.meCalls, "provider SD should be fetched once and cached")
}

// TestCheckConsentTransportFailure verifies an unreachable consent-manager errors.
func TestCheckConsentTransportFailure(t *testing.T) {
	resetCredCache()
	c := NewClient(ClientConfig{BaseURL: "http://localhost:1", ConsentKey: "ck", ParticipantToken: "t", ProviderSD: "sd", TimeoutMs: MinTimeoutMs})
	_, err := c.CheckConsent(context.Background(), ConsentRequest{Subject: "did:key:z"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
}

// TestCheckConsentContextCancellation verifies context cancellation is honored.
func TestCheckConsentContextCancellation(t *testing.T) {
	resetCredCache()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewClient(ClientConfig{BaseURL: srv.URL, ConsentKey: "ck", ParticipantToken: "t", ProviderSD: "sd"})
	_, err := c.CheckConsent(ctx, ConsentRequest{Subject: "did:key:z"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
}

// TestDecisionIsValid verifies the Decision.IsValid method.
func TestDecisionIsValid(t *testing.T) {
	assert.True(t, DecisionAllow.IsValid())
	assert.True(t, DecisionDeny.IsValid())
	assert.True(t, DecisionFilter.IsValid())
	assert.False(t, Decision("").IsValid())
	assert.False(t, Decision("maybe").IsValid())
}

// TestConsentResponseValidate verifies the Validate method on ConsentResponse.
func TestConsentResponseValidate(t *testing.T) {
	require.NoError(t, (&ConsentResponse{Decision: DecisionAllow}).Validate())
	require.NoError(t, (&ConsentResponse{Decision: DecisionDeny, Reason: "no consent"}).Validate())

	err := (&ConsentResponse{Decision: ""}).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decision field is empty")

	err = (&ConsentResponse{Decision: "block"}).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized decision")
}

// TestTruncateBody verifies the body truncation helper.
func TestTruncateBody(t *testing.T) {
	assert.Equal(t, "short", truncateBody([]byte("short")))
	assert.Equal(t, "", truncateBody([]byte{}))
	assert.NotContains(t, truncateBody(make([]byte, maxBodyLogLength)), "...(truncated)")

	long := truncateBody(make([]byte, maxBodyLogLength+100))
	assert.Contains(t, long, "...(truncated)")
	assert.Equal(t, maxBodyLogLength+len("...(truncated)"), len(long))
}
