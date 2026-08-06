// Package plugin implements the APISIX consent-filter plugin that intercepts
// HTTP responses and applies consent-based filtering for personal data.
package plugin

import (
	"net/http"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
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
	// TODO: implement configuration parsing in Step 2
	return in, nil
}

// RequestFilter intercepts incoming HTTP requests to capture request context
// (headers, JWT claims, path, method) for use during response filtering.
func (c *ConsentFilter) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	// TODO: implement request context capture in Step 3
}

// ResponseFilter intercepts upstream HTTP responses, consults the consent API,
// and applies filtering or denial based on the consent decision.
func (c *ConsentFilter) ResponseFilter(conf interface{}, w pkgHTTP.Response) {
	// TODO: implement response filtering in Step 5
}
