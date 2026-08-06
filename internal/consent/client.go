package consent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client endpoint and timeout constants.
const (
	// CheckEndpointPath is the path appended to the base URL when calling the consent API.
	CheckEndpointPath = "/check"

	// DefaultTimeoutMs is the default HTTP client timeout in milliseconds
	// when no explicit timeout is provided to NewClient.
	DefaultTimeoutMs = 5000

	// MinTimeoutMs is the minimum allowed timeout in milliseconds.
	MinTimeoutMs = 1

	// ContentTypeJSON is the Content-Type header value used for consent API requests.
	ContentTypeJSON = "application/json"
)

// Client is an HTTP client for the external consent API. It sends consent
// check requests and parses the resulting allow/deny/filter decisions.
type Client struct {
	// baseURL is the root URL of the consent API (e.g., "http://consent-service:8080").
	baseURL string

	// httpClient is the underlying HTTP client with a configured timeout.
	httpClient *http.Client
}

// NewClient creates a new consent API Client with the given base URL and
// timeout in milliseconds. If timeoutMs is less than MinTimeoutMs, it is
// clamped to DefaultTimeoutMs.
func NewClient(baseURL string, timeoutMs int) *Client {
	if timeoutMs < MinTimeoutMs {
		timeoutMs = DefaultTimeoutMs
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutMs) * time.Millisecond,
		},
	}
}

// CheckConsent sends a consent check request to the external consent API and
// returns the parsed response. It POSTs the ConsentRequest as JSON to the
// {baseURL}/check endpoint and expects a JSON ConsentResponse in return.
//
// The provided context controls cancellation and deadlines for the HTTP call.
// Returns an error if the request cannot be created, the API returns a non-200
// status, or the response body cannot be parsed.
func (c *Client) CheckConsent(ctx context.Context, req ConsentRequest) (*ConsentResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("consent client: failed to marshal request: %w", err)
	}

	url := c.baseURL + CheckEndpointPath

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("consent client: failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", ContentTypeJSON)

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("consent client: HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("consent client: failed to read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("consent client: unexpected status code %d, body: %s",
			httpResp.StatusCode, truncateBody(respBody))
	}

	var consentResp ConsentResponse
	if err := json.Unmarshal(respBody, &consentResp); err != nil {
		return nil, fmt.Errorf("consent client: failed to unmarshal response: %w", err)
	}

	if err := consentResp.Validate(); err != nil {
		return nil, fmt.Errorf("consent client: invalid response: %w", err)
	}

	return &consentResp, nil
}

// maxBodyLogLength is the maximum number of bytes from an error response body
// to include in error messages, to avoid excessively long log entries.
const maxBodyLogLength = 256

// truncateBody returns the response body as a string, truncating it to
// maxBodyLogLength bytes if it exceeds that limit.
func truncateBody(body []byte) string {
	if len(body) <= maxBodyLogLength {
		return string(body)
	}
	return string(body[:maxBodyLogLength]) + "...(truncated)"
}
