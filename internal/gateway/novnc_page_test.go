package gateway

import (
	"io/fs"
	"strings"
	"testing"
)

func TestNoVNCPageUsesBrowserCompatibleBundle(t *testing.T) {
	page, err := fs.ReadFile(staticFiles(), "static/novnc/vnc.html")
	if err != nil {
		t.Fatalf("read novnc page: %v", err)
	}

	html := string(page)
	if !strings.Contains(html, `src="app/ui.js"`) {
		t.Fatalf("expected the hosted noVNC viewer to load the upstream UI")
	}
	if !strings.Contains(html, `id="noVNC_control_bar"`) {
		t.Fatalf("expected the hosted noVNC viewer to include the full control bar")
	}
	if !strings.Contains(html, `<select id="noVNC_setting_resize"`) {
		t.Fatalf("expected the hosted noVNC viewer to expose the standard settings UI")
	}
}
