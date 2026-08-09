package main

import (
	"devboxgateway/internal/config"
	"devboxgateway/internal/session"
	"net/http"
	"net/http/httptest"
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

func TestVendoredDashboardAssetsServed(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)

	for _, path := range []string{
		"/static/vendor/bootstrap/5.3.2/bootstrap.min.css",
		"/static/vendor/xterm/5.3.0/xterm.min.css",
		"/static/vendor/xterm/5.3.0/xterm.min.js",
		"/static/vendor/xterm-addon-fit/0.8.0/xterm-addon-fit.min.js",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
			}
			if rec.Body.Len() == 0 {
				t.Fatalf("expected vendored asset %s to be non-empty", path)
			}
		})
	}
}

func TestDashboardJavaScriptUsesPostLogout(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard.js", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `method="post" action="/logout"`) {
		t.Fatal("expected dashboard JavaScript to submit logout with POST")
	}
	if strings.Contains(body, `href="/logout"`) {
		t.Fatal("dashboard JavaScript must not expose logout as a GET navigation")
	}
}

func TestDashboardJavaScriptMultiplexesVMUpdatesOnWebSocket(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)

	req := httptest.NewRequest(http.MethodGet, "/static/dashboard.js", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `new WebSocket(dashboardWebSocketURL())`) {
		t.Fatal("expected dashboard JavaScript to open the shared dashboard WebSocket")
	}
	if !strings.Contains(body, `message.type === "dashboard"`) {
		t.Fatal("expected dashboard JavaScript to handle complete dashboard snapshots")
	}
	if !strings.Contains(body, "baseImages = data.baseImages || []") {
		t.Fatal("expected WebSocket dashboard snapshots to refresh base image metadata")
	}
	if strings.Contains(body, "EventSource") {
		t.Fatal("dashboard JavaScript must not retain the SSE VM update stream")
	}
	if strings.Contains(body, "AUTO_REFRESH_INTERVAL_MS") {
		t.Fatal("dashboard JavaScript must not retain timer-based VM polling")
	}
}
