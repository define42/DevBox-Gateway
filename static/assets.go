// Package static provides the gateway's embedded browser assets.
package static

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed dashboard.css dashboard.html dashboard.js theme.css novnc vendor
var embeddedFiles embed.FS

// Files returns the embedded assets with their historical static/... paths.
func Files() fs.FS {
	return prefixedFS{FS: embeddedFiles}
}

type prefixedFS struct {
	fs.FS
}

func (f prefixedFS) Open(name string) (fs.File, error) {
	switch {
	case name == "static":
		name = "."
	case strings.HasPrefix(name, "static/"):
		name = strings.TrimPrefix(name, "static/")
	}
	return f.FS.Open(name)
}
