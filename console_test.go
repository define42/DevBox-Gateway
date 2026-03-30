package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
)

func TestDashboardConsoleRouteRejectsUnauthorizedRequests(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)

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

func TestDashboardConsoleRouteRejectsNonOwnerVM(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")

	originalDial := dialDashboardSerialSocket
	dialDashboardSerialSocket = func(name string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("dialDashboardSerialSocket should not be called for non-owner VM %q", name)
		return nil, nil
	}
	defer func() {
		dialDashboardSerialSocket = originalDial
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/console/bob-devbox/ws", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d with body %s", http.StatusForbidden, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "You do not have permission to access this VM terminal.") {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func TestDashboardConsoleRoutePropagatesSerialAvailabilityErrors(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")

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
			originalDial := dialDashboardSerialSocket
			dialDashboardSerialSocket = func(name string, timeout time.Duration) (net.Conn, error) {
				return nil, tc.err
			}
			defer func() {
				dialDashboardSerialSocket = originalDial
			}()

			req := httptest.NewRequest(http.MethodGet, "/api/dashboard/console/alice-devbox/ws", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d with body %s", tc.wantCode, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("expected body to contain %q, got %q", tc.wantBody, rec.Body.String())
			}
		})
	}
}
