package dashboard

import (
	"devboxgateway/internal/virt"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderDashboardPage(t *testing.T) {
	expected, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "static", "dashboard.html")))
	if err != nil {
		t.Fatalf("read dashboard page from static directory: %v", err)
	}

	rec := httptest.NewRecorder()
	RenderDashboardPage(rec, os.DirFS(filepath.Clean(filepath.Join("..", ".."))))

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html content type, got %q", ct)
	}
	if got := res.Header.Get("Cache-Control"); got != cacheControlValue {
		t.Fatalf("expected Cache-Control %q, got %q", cacheControlValue, got)
	}
	if got := res.Header.Get("Pragma"); got != pragmaValue {
		t.Fatalf("expected Pragma %q, got %q", pragmaValue, got)
	}
	if got := res.Header.Get("Expires"); got != expiresValue {
		t.Fatalf("expected Expires %q, got %q", expiresValue, got)
	}
	if body := rec.Body.String(); body != string(expected) {
		t.Fatalf("rendered dashboard page did not match embedded asset")
	}
}

func TestDashboardPageUsesVendoredAssets(t *testing.T) {
	page, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "static", "dashboard.html")))
	if err != nil {
		t.Fatalf("read dashboard page from static directory: %v", err)
	}
	body := string(page)
	if strings.Contains(body, "cdn.jsdelivr.net") || strings.Contains(body, "https://") || strings.Contains(body, "http://") {
		t.Fatalf("dashboard page must not load browser assets from external URLs")
	}
	for _, path := range []string{
		"/static/vendor/bootstrap/5.3.2/bootstrap.min.css",
		"/static/vendor/xterm/5.3.0/xterm.min.css",
		"/static/vendor/xterm/5.3.0/xterm.min.js",
		"/static/vendor/xterm-addon-fit/0.8.0/xterm-addon-fit.min.js",
	} {
		if !strings.Contains(body, path) {
			t.Fatalf("dashboard page does not reference vendored asset %q", path)
		}
	}
}

type errResponseWriter struct {
	header http.Header
	status int
}

func (w *errResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *errResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *errResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRenderDashboardPageWriteError(t *testing.T) {
	writer := &errResponseWriter{}
	RenderDashboardPage(writer, os.DirFS(filepath.Clean(filepath.Join("..", ".."))))

	if ct := writer.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html content type, got %q", ct)
	}
}

func TestRenderDashboardPageMissingTemplate(t *testing.T) {
	rec := httptest.NewRecorder()
	RenderDashboardPage(rec, embed.FS{})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d", http.StatusInternalServerError, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Dashboard template unavailable.") {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func TestDashboardHTMLPathValid(t *testing.T) {
	if valid := fs.ValidPath(DashboardHTMLPath); !valid {
		t.Fatalf("invalid dashboard HTML embedded path: %q", DashboardHTMLPath)
	}
}

func TestGenerateRDPContent(t *testing.T) {
	got := GenerateRDPContent("vm1.example.test", "alice")
	// The downloadable .rdp body is the raw text (no data: URI wrapper).
	if strings.HasPrefix(got, "data:") {
		t.Fatalf("expected raw .rdp content, got data URI: %q", got)
	}
	for _, want := range []string{
		"full address:s:vm1.example.test:443",
		"username:s:alice",
		"prompt for credentials:i:1",
		"administrative session:i:1",
		"enablecredsspsupport:i:0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected content to contain %q, got %q", want, got)
		}
	}
}

func TestBuildDashboardRows(t *testing.T) {
	rows := buildDashboardRows([]virt.VMInfo{
		{
			Name:      "alice.vm",
			Owner:     "alice",
			GuestUser: "guest",
			IP:        "192.0.2.10",
			State:     "running",
			MemoryMiB: 4096,
			VCPU:      2,
			VolumeGB:  40,
			TTYReady:  true,
			VNCReady:  false,
		},
	}, "alice")

	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.DisplayName != "vm" {
		t.Fatalf("expected display name to strip the owner prefix, got %q", row.DisplayName)
	}
	if row.User != "guest" {
		t.Fatalf("expected user %q, got %q", "guest", row.User)
	}
	if row.Name != "alice.vm" || row.IP != "192.0.2.10" || row.State != "running" {
		t.Fatalf("unexpected row data: %+v", row)
	}
	if row.RDPFilename != "alice.vm.rdp" {
		t.Fatalf("expected per-VM download filename %q, got %q", "alice.vm.rdp", row.RDPFilename)
	}
}

func TestRDPDownloadFilename(t *testing.T) {
	cases := map[string]string{
		"alice-desktop":       "alice-desktop.rdp",
		"bob_dev.box":         "bob_dev.box.rdp",
		"weird/../name space": "weird-..-name-space.rdp",
		"-edge-":              "edge.rdp",
		"":                    "rdpgw.rdp",
		"...":                 "rdpgw.rdp",
	}
	for in, want := range cases {
		if got := rdpDownloadFilename(in); got != want {
			t.Fatalf("rdpDownloadFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildDashboardRowsRDPUsername(t *testing.T) {
	rows := buildDashboardRows([]virt.VMInfo{
		{Name: "with-guest", Owner: "alice", GuestUser: "bob"},
		{Name: "legacy", Owner: "alice"},
	}, "alice")

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	// User is the RDP login surfaced in the .rdp download: the chosen guest
	// account when present.
	if rows[0].User != "bob" {
		t.Fatalf("expected RDP username %q, got %q", "bob", rows[0].User)
	}
	// Older VMs without guest-user metadata fall back to the requesting user.
	if rows[1].User != "alice" {
		t.Fatalf("expected fallback RDP username %q, got %q", "alice", rows[1].User)
	}
}

func TestBuildDashboardRowsUnownedVMDisplayName(t *testing.T) {
	// A VM without owner metadata has no "<owner>-" prefix to strip, so its
	// display name is the full name.
	rows := buildDashboardRows([]virt.VMInfo{{Name: "plain-vm"}}, "alice")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].DisplayName != "plain-vm" {
		t.Fatalf("expected full name as display name, got %q", rows[0].DisplayName)
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, ActionResponse{
		OK:      true,
		Message: "created",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
	if got := rec.Header().Get("Cache-Control"); got != cacheControlValue {
		t.Fatalf("expected Cache-Control %q, got %q", cacheControlValue, got)
	}

	var payload ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
	if !payload.OK || payload.Message != "created" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}
