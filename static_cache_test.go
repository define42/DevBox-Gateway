package main

import (
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"strings"
	"testing"
)

func TestStaticFilesDisableCaching(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)

	req := httptest.NewRequest(http.MethodGet, "/static/novnc/vnc.html", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != cacheControlValue {
		t.Fatalf("expected Cache-Control %q, got %q", cacheControlValue, got)
	}
	if got := rec.Header().Get("Pragma"); got != pragmaValue {
		t.Fatalf("expected Pragma %q, got %q", pragmaValue, got)
	}
	if got := rec.Header().Get("Expires"); got != expiresValue {
		t.Fatalf("expected Expires %q, got %q", expiresValue, got)
	}
	if !strings.Contains(rec.Body.String(), `src="app/ui.js"`) {
		t.Fatalf("expected the upstream noVNC viewer assets to be served")
	}
}
