package dashboard

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/virt"
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

func TestGenerateRDP(t *testing.T) {
	got := GenerateRDP("vm1.example.test", "alice")
	if !strings.HasPrefix(got, "data:application/x-rdp;base64,") {
		t.Fatalf("expected RDP data URI, got %q", got)
	}

	encoded := strings.TrimPrefix(got, "data:application/x-rdp;base64,")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode RDP payload: %v", err)
	}

	payload := string(decoded)
	for _, want := range []string{
		"full address:s:vm1.example.test:443",
		"username:s:alice",
		"prompt for credentials:i:1",
		"administrative session:i:1",
		"enablecredsspsupport:i:0",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("expected payload to contain %q, got %q", want, payload)
		}
	}
}

func TestBuildDashboardRows(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	rows := buildDashboardRows([]virt.VMInfo{
		{
			Name:      "alice-vm",
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
	}, settings, "alice")

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
	if row.Name != "alice-vm" || row.IP != "192.0.2.10" || row.State != "running" {
		t.Fatalf("unexpected row data: %+v", row)
	}
	if !strings.Contains(row.RDPConnect, "data:application/x-rdp;base64,") {
		t.Fatalf("expected RDP data URI, got %q", row.RDPConnect)
	}
	if row.RDPFilename != "alice-vm.rdp" {
		t.Fatalf("expected per-VM download filename %q, got %q", "alice-vm.rdp", row.RDPFilename)
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

func rdpUsername(t *testing.T, rdpConnect string) string {
	t.Helper()
	const prefix = "data:application/x-rdp;base64,"
	if !strings.HasPrefix(rdpConnect, prefix) {
		t.Fatalf("expected RDP data URI prefix, got %q", rdpConnect)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(rdpConnect, prefix))
	if err != nil {
		t.Fatalf("decode RDP payload: %v", err)
	}
	for _, line := range strings.Split(string(decoded), "\n") {
		if rest, ok := strings.CutPrefix(line, "username:s:"); ok {
			return rest
		}
	}
	t.Fatalf("no username line in RDP payload %q", string(decoded))
	return ""
}

func TestBuildDashboardRowsRDPUsername(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	rows := buildDashboardRows([]virt.VMInfo{
		{Name: "with-guest", Owner: "alice", GuestUser: "bob"},
		{Name: "legacy", Owner: "alice"},
	}, settings, "alice")

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	// The chosen guest account is used for RDP when present.
	if got := rdpUsername(t, rows[0].RDPConnect); got != "bob" {
		t.Fatalf("expected RDP username %q, got %q", "bob", got)
	}
	// Older VMs without guest-user metadata fall back to the requesting user.
	if got := rdpUsername(t, rows[1].RDPConnect); got != "alice" {
		t.Fatalf("expected fallback RDP username %q, got %q", "alice", got)
	}
}

func TestBuildDashboardRowsWithoutFrontDomain(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "")
	settings := config.NewSettingType(false)

	rows := buildDashboardRows([]virt.VMInfo{{Name: "plain-vm"}}, settings, "alice")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].DisplayName != "plain-vm" {
		t.Fatalf("expected display name without domain, got %q", rows[0].DisplayName)
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
