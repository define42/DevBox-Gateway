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

func TestDashboardJavaScriptShowsIdleShutdownPolicy(t *testing.T) {
	router := getRemoteGatewayRotuer(session.NewManager(), config.NewSettingType(false))
	req := httptest.NewRequest(http.MethodGet, "/static/dashboard.js", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for description, fragment := range map[string]string{
		"hidden policy banner":       `id="auto-shutdown-policy" class="alert alert-info py-2 mt-3 mb-0 d-none" role="status" hidden`,
		"disabled-policy guard":      `if (state.autoShutdownHours > 0)`,
		"auto-shutdown table column": `columns.push("Auto-shutdown")`,
		"missing timestamp fallback": `autoShutdownCell.textContent = "Due now"`,
		"invalid timestamp fallback": `autoShutdownCell.textContent = "Unknown"`,
		"blocked VM state":           `normalized === "blocked"`,
		"safe policy rendering":      `autoShutdownPolicyEl.textContent = enabled`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("expected dashboard JavaScript to include %s", description)
		}
	}
	if strings.Contains(body, "autoShutdownCell.innerHTML") || strings.Contains(body, "autoShutdownPolicyEl.innerHTML") {
		t.Fatal("auto-shutdown UI must render server-derived values with textContent")
	}
}

func TestDashboardJavaScriptStreamsCreationProgress(t *testing.T) {
	router := getRemoteGatewayRotuer(session.NewManager(), config.NewSettingType(false))
	req := httptest.NewRequest(http.MethodGet, "/static/dashboard.js", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for description, fragment := range map[string]string{
		"accessible progress bar":    `id="create-progress-bar" role="progressbar"`,
		"indeterminate spinner":      `id="create-progress-spinner" aria-hidden="true"`,
		"unfilled preparing bar":     `aria-valuetext="Preparing DevBox..." style="width: 0%"`,
		"NDJSON response request":    `"Accept": "application/x-ndjson, application/json"`,
		"stream reader":              `response.body.getReader()`,
		"incremental line buffering": `buffered.indexOf("\n")`,
		"progress event handling":    `event.type === "progress"`,
		"result event handling":      `event.type === "result"`,
		"disk byte progress":         `updateCreateDiskProgress(event.copiedBytes, event.totalBytes)`,
		"dismissible creation modal": "function closeCreate() {",
		"modal focus restoration":    `openCreateButtonEl.focus()`,
		"preparing track hidden":     `createProgressTrackEl.classList.toggle("d-none", !state.create.active || isPreparing)`,
		"terminal stream handling":   `break streamLoop`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("expected dashboard JavaScript to include %s", description)
		}
	}
	if strings.Contains(body, "createCloseEl.disabled = state.create.active") {
		t.Fatal("creation progress must not disable the modal close button")
	}
	if strings.Contains(body, "creation_id") {
		t.Fatal("direct creation progress must not retain tracker correlation IDs")
	}
}
