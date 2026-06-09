package console

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestDashboardConsoleRouteRejectsUnauthorizedRequests(t *testing.T) {
	sessionManager := session.NewManager()

	router := chi.NewRouter()
	router.Use(sessionManager.LoadAndSave)
	router.Get("/api/dashboard/console/{name}/ws", HandleDashboardConsoleWS(sessionManager))

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/console/alice-devbox/ws", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d with body %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Login required.") {
		t.Fatalf("expected login required message, got %q", rec.Body.String())
	}
}

func TestDashboardVNCRouteRejectsUnauthorizedRequests(t *testing.T) {
	sessionManager := session.NewManager()

	router := chi.NewRouter()
	router.Use(sessionManager.LoadAndSave)
	router.Get("/api/dashboard/vnc/{name}/ws", HandleDashboardVNCWS(sessionManager))

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/vnc/alice-devbox/ws", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d with body %s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Login required.") {
		t.Fatalf("expected login required message, got %q", rec.Body.String())
	}
}

func TestParseDashboardVMPathParam(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "valid", input: "alice-devbox", want: "alice-devbox"},
		{name: "trimmed", input: "  alice-devbox  ", want: "alice-devbox"},
		{name: "empty", input: "", wantErr: true},
		{name: "too long", input: strings.Repeat("a", 129), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDashboardVMPathParam(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

// The serial console no longer dials a socket path — virt.OpenSerialConsole
// streams it via libvirt's OpenConsole, which needs a live domain and is covered
// by the virt package's integration test (waitForSerialSocket).

func TestWriteDashboardSerialSocketError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{
			name:     "not running",
			err:      virt.ErrSerialConsoleNotRunning,
			wantCode: http.StatusConflict,
			wantBody: "VM must be running for terminal access.",
		},
		{
			name:     "not configured",
			err:      virt.ErrSerialConsoleNotConfigured,
			wantCode: http.StatusConflict,
			wantBody: "Serial terminal is not available for this VM.",
		},
		{
			name:     "not ready",
			err:      virt.ErrSerialConsoleNotReady,
			wantCode: http.StatusConflict,
			wantBody: "Serial terminal is not ready yet.",
		},
		{
			name:     "unexpected",
			err:      errors.New("boom"),
			wantCode: http.StatusInternalServerError,
			wantBody: "Failed to open serial terminal.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			writeDashboardSerialSocketError(rec, "alice-devbox", tc.err)

			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d with body %s", tc.wantCode, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("expected body to contain %q, got %q", tc.wantBody, rec.Body.String())
			}
		})
	}
}

// VNC no longer dials a socket path — virt.OpenVNCConn obtains the connection via
// libvirt's OpenGraphicsFD, which requires a live libvirt domain and is covered
// by the virt package's integration test (waitForVNCSocket). The generic
// dial+bridge behavior remains covered by the serial dashboard socket tests.

func TestWriteDashboardVNCSocketError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{
			name:     "not running",
			err:      virt.ErrVNCNotRunning,
			wantCode: http.StatusConflict,
			wantBody: "VM must be running for VNC access.",
		},
		{
			name:     "not configured",
			err:      virt.ErrVNCNotConfigured,
			wantCode: http.StatusConflict,
			wantBody: "VNC is not available for this VM.",
		},
		{
			name:     "not ready",
			err:      virt.ErrVNCNotReady,
			wantCode: http.StatusConflict,
			wantBody: "VNC is not ready yet.",
		},
		{
			name:     "unexpected",
			err:      errors.New("boom"),
			wantCode: http.StatusInternalServerError,
			wantBody: "Failed to open VNC session.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			writeDashboardVNCSocketError(rec, "alice-devbox", tc.err)

			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d with body %s", tc.wantCode, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("expected body to contain %q, got %q", tc.wantBody, rec.Body.String())
			}
		})
	}
}

func TestWriteDashboardConsoleOwnershipError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{
			name:     "not owned",
			err:      nil,
			wantCode: http.StatusForbidden,
			wantBody: "You do not have permission to access this VM terminal.",
		},
		{
			name:     "lookup failed",
			err:      errors.New("boom"),
			wantCode: http.StatusInternalServerError,
			wantBody: "Unable to verify VM ownership.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			writeDashboardConsoleOwnershipError(rec, "alice-bob-devbox", "alice", tc.err)

			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d with body %s", tc.wantCode, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("expected body to contain %q, got %q", tc.wantBody, rec.Body.String())
			}
		})
	}
}

func TestWriteDashboardVNCOwnershipError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{
			name:     "not owned",
			err:      nil,
			wantCode: http.StatusForbidden,
			wantBody: "You do not have permission to access this VM VNC session.",
		},
		{
			name:     "lookup failed",
			err:      errors.New("boom"),
			wantCode: http.StatusInternalServerError,
			wantBody: "Unable to verify VM ownership.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			writeDashboardVNCOwnershipError(rec, "alice-bob-devbox", "alice", tc.err)

			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d with body %s", tc.wantCode, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("expected body to contain %q, got %q", tc.wantBody, rec.Body.String())
			}
		})
	}
}
