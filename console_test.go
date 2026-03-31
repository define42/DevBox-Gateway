package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
	"strings"
	"testing"
	"time"
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
	defer func() { _ = clientConn.Close() }()

	var serverConn net.Conn
	select {
	case serverConn = <-acceptedCh:
	case err := <-errCh:
		t.Fatalf("accept dashboard serial socket: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accepted dashboard serial socket")
	}
	defer func() { _ = serverConn.Close() }()

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

func TestDialDashboardVNCSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "dashboard.vnc.sock")
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

	clientConn, err := dialDashboardVNCSocket(socketPath, time.Second)
	if err != nil {
		t.Fatalf("dialDashboardVNCSocket(%q): %v", socketPath, err)
	}
	defer func() { _ = clientConn.Close() }()

	var serverConn net.Conn
	select {
	case serverConn = <-acceptedCh:
	case err := <-errCh:
		t.Fatalf("accept dashboard vnc socket: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for accepted dashboard vnc socket")
	}
	defer func() { _ = serverConn.Close() }()

	want := []byte("hello from vnc")
	if _, err := clientConn.Write(want); err != nil {
		t.Fatalf("write to dashboard vnc socket: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("read from accepted dashboard vnc socket: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("expected payload %q, got %q", string(want), string(got))
	}
}

func TestDialDashboardVNCSocketReturnsNotReadyForMissingSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "missing.vnc.sock")

	conn, err := dialDashboardVNCSocket(socketPath, time.Second)
	if err == nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("expected missing socket dial to fail")
	}
	if !errors.Is(err, virt.ErrVNCNotReady) {
		t.Fatalf("expected ErrVNCNotReady, got %v", err)
	}
}

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
