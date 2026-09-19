package console

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"

	"github.com/gorilla/websocket"
)

func TestInvalidSerialWebsocketRequestPreservesActiveConsole(t *testing.T) {
	dom := covxDefineDomain(t, "invalid-serial-upgrade")
	dom.setOwnerMetadata(covxOwnerMetadata)
	dom.startPaused()
	manager := session.New()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	tests := []struct {
		name    string
		upgrade bool
		header  http.Header
		status  int
	}{
		{name: "ordinary GET", status: http.StatusBadRequest},
		{
			name: "cross-site navigation",
			header: http.Header{
				"Sec-Fetch-Site": {"cross-site"},
				"Sec-Fetch-Mode": {"navigate"},
			},
			status: http.StatusBadRequest,
		},
		{name: "foreign origin", upgrade: true, header: http.Header{"Origin": {"https://evil.example"}}, status: http.StatusForbidden},
		{name: "missing Connection", upgrade: true, header: http.Header{"Connection": {"keep-alive"}}, status: http.StatusBadRequest},
		{name: "missing Upgrade", upgrade: true, header: http.Header{"Upgrade": {""}}, status: http.StatusBadRequest},
		{name: "unsupported version", upgrade: true, header: http.Header{"Sec-Websocket-Version": {"12"}}, status: http.StatusBadRequest},
		{name: "missing key", upgrade: true, header: http.Header{"Sec-Websocket-Key": {""}}, status: http.StatusBadRequest},
		{name: "malformed key", upgrade: true, header: http.Header{"Sec-Websocket-Key": {"invalid"}}, status: http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			active := covxOpenConsole(t, dom.name)
			t.Cleanup(func() {
				_ = active.Interrupt()
				_ = active.Close()
			})
			req := serialUpgradeRequest(t, server.URL+"/api/dashboard/console/"+dom.name+"/ws", tc.upgrade, tc.header)
			req.AddCookie(cookie)
			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("HTTP status = %d, want %d", response.StatusCode, tc.status)
			}
			if err := sendAllToConsole(active, []byte("\r")); err != nil {
				t.Fatalf("invalid request disconnected the active console: %v", err)
			}
		})
	}
}

func serialUpgradeRequest(t *testing.T, url string, upgrade bool, header http.Header) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if upgrade {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	}
	for name, values := range header {
		req.Header[name] = values
	}
	return req
}

func TestSerialWebsocketClosesWhenVMIsStopped(t *testing.T) {
	dom := covxDefineDomain(t, "stopped-serial")
	dom.setOwnerMetadata(covxOwnerMetadata)
	manager := session.New()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)
	client := covxDialWebsocket(t, server, "/api/dashboard/console/"+dom.name+"/ws", cookie)
	if err := client.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatal(err)
	}
	_, _, err := client.ReadMessage()
	if !websocket.IsCloseError(err, websocket.CloseTryAgainLater) {
		t.Fatalf("stopped VM error = %v, want a retryable WebSocket close", err)
	}
}

func TestCloseDashboardSerialSocketError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
		wantText string
	}{
		{
			name: "not running", err: virt.ErrSerialConsoleNotRunning,
			wantCode: websocket.CloseTryAgainLater, wantText: "VM must be running for terminal access.",
		},
		{
			name: "not configured", err: virt.ErrSerialConsoleNotConfigured,
			wantCode: websocket.CloseTryAgainLater, wantText: "Serial terminal is not available for this VM.",
		},
		{
			name: "not ready", err: virt.ErrSerialConsoleNotReady,
			wantCode: websocket.CloseTryAgainLater, wantText: "Serial terminal is not ready yet.",
		},
		{
			name: "unexpected", err: errors.New("boom"),
			wantCode: websocket.CloseInternalServerErr, wantText: "Failed to open serial terminal.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server, cleanup := newWebsocketPair(t)
			defer cleanup()
			closeDashboardSerialSocketError(server, "alice-devbox", tc.err)
			if err := client.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
				t.Fatal(err)
			}
			_, _, err := client.ReadMessage()
			var closeErr *websocket.CloseError
			if !errors.As(err, &closeErr) || closeErr.Code != tc.wantCode || closeErr.Text != tc.wantText {
				t.Fatalf("close error = %v, want code %d and text %q", err, tc.wantCode, tc.wantText)
			}
		})
	}
}
