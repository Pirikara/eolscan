// Package catalog embeds reviewed upstream security support evidence.
package catalog

import _ "embed"

// Builtin contains official support evidence, without general EOL permissions
// or package version assertions. Exact versions still require verification.
//
//go:embed upstream-security.yaml
var Builtin []byte
