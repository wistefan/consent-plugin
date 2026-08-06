// Package plugin implements the APISIX consent-filter plugin that intercepts
// HTTP responses and applies consent-based filtering for personal data.
package plugin

import (
	"log"
	"net/http"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"

	"consent-plugin/internal/jwt"
)

// pluginName is the registered name for this plugin in APISIX configuration.
const pluginName = "consent-filter"

func init() {
	if err := plugin.RegisterPlugin(&ConsentFilter{}); err != nil {
		panic("failed to register consent-filter plugin: " + err.Error())
	}
}

// ConsentFilter is the APISIX plugin that intercepts HTTP responses,
// consults an external consent API, and filters or denies responses
// based on consent decisions for personal data fields.
type ConsentFilter struct {
	plugin.DefaultPlugin
}

// Name returns the unique name of this plugin as registered with APISIX.
func (c *ConsentFilter) Name() string {
	return pluginName
}

// ParseConf deserializes and validates the plugin configuration from
// the JSON bytes provided by APISIX. Returns the parsed configuration
// or an error if the configuration is invalid.
func (c *ConsentFilter) ParseConf(in []byte) (interface{}, error) {
	return ParseConfig(in)
}

// RequestFilter intercepts incoming HTTP requests to capture request context
// (headers, JWT claims, path, method) for use during response filtering.
// It extracts the JWT from the configured header, decodes the requested claims,
// captures all request headers, and stores the context keyed by request ID
// for later retrieval in ResponseFilter.
func (c *ConsentFilter) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	cfg, ok := conf.(*Config)
	if !ok {
		log.Printf("[consent-filter] RequestFilter: invalid config type, skipping request %d", r.ID())
		return
	}

	reqCtx := &RequestContext{
		Method:  r.Method(),
		Path:    string(r.Path()),
		Headers: make(http.Header),
	}

	// Capture request headers from the request's Header view.
	if srcHeaders := r.Header().View(); srcHeaders != nil {
		for key, values := range srcHeaders {
			reqCtx.Headers[key] = values
		}
	}

	// Extract JWT token and decode claims from the configured header.
	jwtHeaderValue := r.Header().Get(cfg.JWTHeaderName)
	if jwtHeaderValue != "" {
		token, err := jwt.ExtractToken(jwtHeaderValue)
		if err != nil {
			log.Printf("[consent-filter] RequestFilter: failed to extract JWT from header %q for request %d: %v",
				cfg.JWTHeaderName, r.ID(), err)
		} else {
			claims, err := jwt.DecodeClaims(token, cfg.JWTClaimsToForward)
			if err != nil {
				log.Printf("[consent-filter] RequestFilter: failed to decode JWT claims for request %d: %v",
					r.ID(), err)
			} else {
				reqCtx.JWTClaims = claims
			}
		}
	}

	StoreRequestContext(r.ID(), reqCtx)
}

// ResponseFilter intercepts upstream HTTP responses, consults the consent API,
// and applies filtering or denial based on the consent decision.
func (c *ConsentFilter) ResponseFilter(conf interface{}, w pkgHTTP.Response) {
	// TODO: implement response filtering in Step 5
}
