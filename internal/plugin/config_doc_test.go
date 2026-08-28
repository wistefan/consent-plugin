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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readmePath is the README, relative to this package, that must document the
// plugin's configuration surface.
const readmePath = "../../README.md"

// configSourcePath is the file declaring the Config struct.
const configSourcePath = "config.go"

// configSectionHeading opens the README section holding the configuration
// table; the section ends at the next top-level heading.
const configSectionHeading = "## Configuration Reference"

// readmeFieldPattern matches a config field named in the first column of the
// README's configuration table, e.g. "| `consent_api_url` | ...".
var readmeFieldPattern = regexp.MustCompile("(?m)^\\|\\s*`([a-z0-9_]+)`\\s*\\|")

// TestREADMEDocumentsEveryConfigField guards against documentation drift on a
// security control.
//
// This repository has already shipped a README describing `client_id` /
// `client_secret` months after those fields were removed from Config. Because
// json.Unmarshal silently discards unknown fields, a config copied from that
// README parsed and validated cleanly and then could not authenticate at all —
// a documentation defect that was, in effect, a security defect. Drift on this
// surface needs a machine, not discipline.
func TestREADMEDocumentsEveryConfigField(t *testing.T) {
	documented := documentedConfigFields(t)
	declared := declaredConfigFields(t)

	for _, field := range declared {
		assert.Contains(t, documented, field,
			"config field %q is not documented in the README configuration table", field)
	}
	for field := range documented {
		assert.Contains(t, declared, field,
			"the README documents %q, which is not a field of Config — a reader would configure something that is silently discarded", field)
	}
}

// documentedConfigFields returns the field names appearing in the README's
// configuration table.
func documentedConfigFields(t *testing.T) map[string]bool {
	t.Helper()
	readme, err := os.ReadFile(readmePath)
	require.NoError(t, err, "the README must be readable to check it for drift")

	// Only the configuration section counts: other tables in the README describe
	// unrelated things (compose services, release artifacts).
	_, section, found := strings.Cut(string(readme), configSectionHeading)
	require.True(t, found, "the README must have a %q section", configSectionHeading)
	if next := strings.Index(section, "\n## "); next >= 0 {
		section = section[:next]
	}

	fields := map[string]bool{}
	for _, match := range readmeFieldPattern.FindAllStringSubmatch(section, -1) {
		fields[match[1]] = true
	}
	require.NotEmpty(t, fields, "no configuration table found in the README")
	return fields
}

// declaredConfigFields returns the json tag names of every field of Config, read
// from the source rather than by reflection so that the check does not depend on
// a field being exported or populated.
func declaredConfigFields(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), configSourcePath, nil, 0)
	require.NoError(t, err)

	var fields []string
	ast.Inspect(file, func(n ast.Node) bool {
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "Config" {
			return true
		}
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range structType.Fields.List {
			if field.Tag == nil {
				continue
			}
			tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`")).Get("json")
			if name := strings.Split(tag, ",")[0]; name != "" && name != "-" {
				fields = append(fields, name)
			}
		}
		return false
	})
	require.NotEmpty(t, fields, "no json-tagged fields found on Config")
	return fields
}
