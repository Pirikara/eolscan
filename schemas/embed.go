// Package schemas embeds the versioned JSON contracts shipped with eolscan.
package schemas

import "embed"

//go:embed *.json
var files embed.FS

// Files returns the immutable schema files embedded in the binary.
func Files() embed.FS { return files }
