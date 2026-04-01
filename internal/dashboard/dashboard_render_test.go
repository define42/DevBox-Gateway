package dashboard

import (
	"embed"
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
