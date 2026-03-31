package main

import (
	"embed"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
	"strconv"
	"strings"
	"testing"
	"time"
)

const dashboardVMTestTimeout = 30 * time.Second

func TestRenderDashboardPage(t *testing.T) {
	expected, err := fs.ReadFile(staticFiles, dashboardHTMLPath)
	if err != nil {
		t.Fatalf("read embedded dashboard page: %v", err)
	}

	rec := httptest.NewRecorder()
	renderDashboardPage(rec)

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
	renderDashboardPage(writer)

	if ct := writer.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html content type, got %q", ct)
	}
}

func TestRenderDashboardPageMissingTemplate(t *testing.T) {
	originalStaticFiles := staticFiles
	staticFiles = embed.FS{}
	t.Cleanup(func() {
		staticFiles = originalStaticFiles
	})

	rec := httptest.NewRecorder()
	renderDashboardPage(rec)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d", http.StatusInternalServerError, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Dashboard template unavailable.") {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func waitForDashboardVM(t *testing.T, settings *config.SettingsType, user, name string, timeout time.Duration) dashboardVM {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rows, err := listDashboardVMs(settings, user)
		if err != nil {
			t.Fatalf("listDashboardVMs(%q): %v", user, err)
		}
		for _, row := range rows {
			if row.Name == name {
				if row.State == "running" && row.TTYReady && row.VNCReady {
					return row
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("VM %s was not visible in dashboard data for user %s within %s", name, user, timeout)
	return dashboardVM{}
}

func newDashboardVMSettings(t *testing.T) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.VIRT_SERIAL_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_SERIAL_SOCKET_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_VNC_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_VNC_SOCKET_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.FRONT_DOMAIN, "dashboard.test"); err != nil {
		t.Fatalf("overwrite FRONT_DOMAIN: %v", err)
	}
	return settings
}

func createDashboardVM(t *testing.T, settings *config.SettingsType) (string, string) {
	t.Helper()

	suffix := time.Now().UnixNano() % 1_000_000
	username := "dashuser" + strconv.FormatInt(suffix, 10)
	vmShortName := "dashvm" + strconv.FormatInt(suffix, 10)

	user, err := types.NewUser(username, "dogood")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	vmName, err := virt.BootNewVM(vmShortName, user, settings, 2, 4096)
	if err != nil {
		t.Fatalf("boot VM %s: %v", vmShortName, err)
	}
	t.Cleanup(func() {
		if err := virt.RemoveVM(vmName, settings); err != nil {
			t.Errorf("cleanup VM %s: %v", vmName, err)
		}
	})

	return username, vmName
}

func assertDashboardVMRow(t *testing.T, row dashboardVM, wantDisplayName string) {
	t.Helper()

	if row.DisplayName != wantDisplayName {
		t.Fatalf("expected display name %q, got %q", wantDisplayName, row.DisplayName)
	}
	if row.State != "running" {
		t.Fatalf("expected state running, got %q", row.State)
	}
	if row.MemoryMiB != 4096 {
		t.Fatalf("expected memory 4096 MiB, got %d", row.MemoryMiB)
	}
	if row.VCPU != 2 {
		t.Fatalf("expected vCPU 2, got %d", row.VCPU)
	}
	if row.VolumeGB != 40 {
		t.Fatalf("expected disk 40 GB, got %d", row.VolumeGB)
	}
	if !row.TTYReady {
		t.Fatal("expected TTYReady=true")
	}
	if !row.VNCReady {
		t.Fatal("expected VNCReady=true")
	}
}

func assertDashboardRDPConnect(t *testing.T, rdpConnect, wantDisplayName, username string) {
	t.Helper()

	const prefix = "data:application/x-rdp;base64,"
	if !strings.HasPrefix(rdpConnect, prefix) {
		t.Fatalf("expected RDP data URI prefix, got %q", rdpConnect)
	}

	decodedRDP, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(rdpConnect, prefix))
	if err != nil {
		t.Fatalf("decode RDP payload: %v", err)
	}
	rdp := string(decodedRDP)
	if !strings.Contains(rdp, "full address:s:"+wantDisplayName+":443") {
		t.Fatalf("expected RDP payload to contain display name %q, got %q", wantDisplayName, rdp)
	}
	if !strings.Contains(rdp, "username:s:"+username) {
		t.Fatalf("expected RDP payload to contain username %q, got %q", username, rdp)
	}
}

func TestListDashboardVMs(t *testing.T) {
	virt.GetInstance()

	settings := newDashboardVMSettings(t)
	username, vmName := createDashboardVM(t, settings)
	row := waitForDashboardVM(t, settings, username, vmName, dashboardVMTestTimeout)
	wantDisplayName := vmName + ".dashboard.test"

	assertDashboardVMRow(t, row, wantDisplayName)
	assertDashboardRDPConnect(t, row.RDPConnect, wantDisplayName, username)
}
