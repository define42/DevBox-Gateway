package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	stubDashboardVMOwnershipByPrefix(t)

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

func TestDialDashboardSerialSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "dashboard.serial.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	acceptedCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		acceptedCh <- conn
	}()

	clientConn, err := dialDashboardSerialSocket(socketPath, time.Second)
	if err != nil {
		t.Fatalf("dialDashboardSerialSocket(%q): %v", socketPath, err)
	}
	defer clientConn.Close()

	var serverConn net.Conn
	select {
	case serverConn = <-acceptedCh:
	case err := <-errCh:
		t.Fatalf("accept dashboard serial socket: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accepted dashboard serial socket")
	}
	defer serverConn.Close()

	want := []byte("hello from terminal")
	if _, err := clientConn.Write(want); err != nil {
		t.Fatalf("write to dashboard serial socket: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("read from accepted dashboard serial socket: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("expected payload %q, got %q", string(want), string(got))
	}
}

func TestDialDashboardSerialSocketReturnsNotReadyForMissingSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "missing.serial.sock")

	conn, err := dialDashboardSerialSocket(socketPath, time.Second)
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected missing socket dial to fail")
	}
	if !errors.Is(err, virt.ErrSerialConsoleNotReady) {
		t.Fatalf("expected ErrSerialConsoleNotReady, got %v", err)
	}
}

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

func TestDashboardVNCRejectsNonOwnerVM(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")
	stubDashboardVMOwnershipByPrefix(t)

	originalDial := dialDashboardVNCSocket
	dialDashboardVNCSocket = func(name string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("dialDashboardVNCSocket should not be called for non-owner VM %q", name)
		return nil, nil
	}
	defer func() {
		dialDashboardVNCSocket = originalDial
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/vnc/bob-devbox/ws", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d with body %s", http.StatusForbidden, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "You do not have permission to access this VM VNC session.") {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func TestDashboardVNCPropagatesAvailabilityErrors(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")
	stubDashboardVMOwnershipByPrefix(t)

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
			originalDial := dialDashboardVNCSocket
			dialDashboardVNCSocket = func(name string, timeout time.Duration) (net.Conn, error) {
				return nil, tc.err
			}
			defer func() {
				dialDashboardVNCSocket = originalDial
			}()

			req := httptest.NewRequest(http.MethodGet, "/api/dashboard/vnc/alice-devbox/ws", nil)
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

func TestDashboardConsoleRejectsPrefixCollidingVM(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")

	stubDashboardVMOwnershipCheck(t, func(name, username string) (bool, error) {
		if name != "alice-bob-devbox" || username != "alice" {
			t.Fatalf("unexpected ownership check for %q / %q", name, username)
		}
		return false, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/console/alice-bob-devbox/ws", nil)
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

func TestDashboardVNCRejectsPrefixCollidingVM(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")

	stubDashboardVMOwnershipCheck(t, func(name, username string) (bool, error) {
		if name != "alice-bob-devbox" || username != "alice" {
			t.Fatalf("unexpected ownership check for %q / %q", name, username)
		}
		return false, nil
	})

	originalDial := dialDashboardVNCSocket
	dialDashboardVNCSocket = func(name string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("dialDashboardVNCSocket should not be called for rejected VM %q", name)
		return nil, nil
	}
	defer func() {
		dialDashboardVNCSocket = originalDial
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/vnc/alice-bob-devbox/ws", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d with body %s", http.StatusForbidden, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "You do not have permission to access this VM VNC session.") {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}
