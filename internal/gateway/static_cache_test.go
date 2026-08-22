package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
)

func TestStaticFilesDisableCaching(t *testing.T) {
	sessionManager := session.New()
	settings := config.NewSettings(false)
	router := NewHandler(sessionManager, settings)

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
	sessionManager := session.New()
	settings := config.NewSettings(false)
	router := NewHandler(sessionManager, settings)

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
	sessionManager := session.New()
	settings := config.NewSettings(false)
	router := NewHandler(sessionManager, settings)

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
	sessionManager := session.New()
	settings := config.NewSettings(false)
	router := NewHandler(sessionManager, settings)

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

func TestDashboardJavaScriptSupportsAdminLifecycleInventory(t *testing.T) {
	router := NewHandler(session.New(), config.NewSettings(false))
	req := httptest.NewRequest(http.MethodGet, "/static/dashboard.js", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	for description, fragment := range map[string]string{
		"conditional admin navigation": `id="admin-view-link" href="/api/admin" hidden`,
		"admin data endpoint":          `"/api/admin/data"`,
		"admin websocket endpoint":     `"/api/admin/ws"`,
		"owner grouping":               `new Map()`,
		"unowned VM group":             `"Unowned"`,
		"admin lifecycle table mode":   `appendVMTable(section, vmsByOwner.get(owner) || [], { connections: false, lifecycle: true })`,
		"hidden create action":         `openCreateButtonEl.hidden = adminView`,
		"base image manager button":    `id="base-images-button" type="button" hidden`,
		"base image manager modal":     `id="base-images-modal" class="terminal-modal" hidden`,
		"available image storage":      `id="base-image-available-storage" aria-live="polite"`,
		"base image list endpoint":     `"/api/admin/base-images"`,
		"base image delete endpoint":   `"/api/admin/base-images/delete"`,
		"streamed upload form":         `const body = new FormData()`,
		"upload progress":              `xhr.upload.onprogress = (event) =>`,
		"QCOW2 upload requirement":     `QCOW2 content required; filenames may end in .img, .qcow2, or .raw.`,
		"available storage API field":  `availableStorageBytes`,
		"exact delete confirmation":    `Type the base image name "${name}" to confirm deletion:`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("expected dashboard JavaScript to include %s", description)
		}
	}
	if strings.Contains(body, `actionAreaEl.hidden = adminView`) {
		t.Fatal("administrator lifecycle action feedback must remain visible")
	}
}

func TestDashboardJavaScriptOpensConsolesOnDemand(t *testing.T) {
	router := NewHandler(session.New(), config.NewSettings(false))
	req := httptest.NewRequest(http.MethodGet, "/static/dashboard.js", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "vm.vncReady") {
		t.Fatal("dashboard JavaScript must not depend on inventory-time VNC readiness")
	}
	if strings.Contains(body, "vm.ttyReady") {
		t.Fatal("dashboard JavaScript must not depend on inventory-time serial readiness")
	}
	if !strings.Contains(body, "vncButton.disabled = state.busy || !isActive") {
		t.Fatal("expected NoVNC button availability to depend on active VM state")
	}
	if !strings.Contains(body, "terminalButton.disabled = state.busy || !isActive") {
		t.Fatal("expected Terminal button availability to depend on active VM state")
	}
	if !strings.Contains(body, "state.vnc.src = vncFrameURL(vm.name)") {
		t.Fatal("expected NoVNC to resolve its websocket only when the viewer opens")
	}
	if !strings.Contains(body, "new WebSocket(terminalWebSocketURL(vm.name))") {
		t.Fatal("expected serial console websocket to open only when the terminal opens")
	}
}

func TestDashboardJavaScriptStreamsCreationProgress(t *testing.T) {
	router := NewHandler(session.New(), config.NewSettings(false))
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
