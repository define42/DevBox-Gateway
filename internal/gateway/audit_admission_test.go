package gateway

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
)

func TestAuditAdmissionPressure(t *testing.T) {
	for _, tt := range []struct {
		name, method, path string
		upgrade            []string
		allowed            bool
	}{
		{name: "login", method: http.MethodPost, path: "/login"},
		{name: "VM creation", method: http.MethodPost, path: "/api/vm/create"},
		{name: "delete", method: http.MethodDelete, path: "/api/vm/example"},
		{name: "websocket", method: http.MethodGet, path: "/api/console", upgrade: []string{"websocket"}},
		{name: "upgrade token list", method: http.MethodGet, path: "/api/console", upgrade: []string{"other, WebSocket"}},
		{name: "upgrade multiple headers", method: http.MethodGet, path: "/api/console", upgrade: []string{"other", "websocket"}},
		{name: "logout", method: http.MethodPost, path: "/logout", allowed: true},
		{name: "readiness", method: http.MethodGet, path: "/api/ready", allowed: true},
		{name: "liveness", method: http.MethodGet, path: "/api/health", allowed: true},
		{name: "dashboard", method: http.MethodGet, path: "/api/dashboard", allowed: true},
		{name: "head", method: http.MethodHead, path: "/", allowed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := auditAdmissionMiddleware(func() error { return errors.New("private spool path") })(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					called = true
					w.WriteHeader(http.StatusNoContent)
				}))
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if len(tt.upgrade) > 0 {
				req.Header.Set("Connection", "keep-alive, Upgrade")
				req.Header["Upgrade"] = tt.upgrade
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if called != tt.allowed {
				t.Fatalf("handler called=%t, want %t", called, tt.allowed)
			}
			if tt.allowed {
				return
			}
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "5" ||
				!strings.Contains(rec.Header().Get("Cache-Control"), "no-store") || strings.Contains(rec.Body.String(), "private") {
				t.Fatalf("pressure response: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
			}
		})
	}
}

func TestAuditAdmissionRouterRecoversAndKeepsProbesAvailable(t *testing.T) {
	manager := session.New()
	t.Cleanup(func() { _ = manager.Close() })
	pressure := errors.New("spool pressure")
	check := func() error { return pressure }
	router := newHandlerWithAdmission(manager, config.NewSettings(false), check, check)
	for _, tt := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/login", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/ready", http.StatusServiceUnavailable},
		{http.MethodGet, "/api/health", http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
		if rec.Code != tt.want {
			t.Fatalf("%s %s: status=%d, want %d", tt.method, tt.path, rec.Code, tt.want)
		}
	}
	pressure = nil
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	if rec.Code == http.StatusServiceUnavailable {
		t.Fatal("login admission remained blocked after recovery")
	}
}

func TestAuditAdmissionClosesRDPBeforeReadingGrant(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	checked := false
	go func() {
		defer close(done)
		handleSharedConnWithAdmission(server, nil, nil, nil, config.NewSettings(false), nil, func() error {
			checked = true
			return errors.New("spool pressure")
		})
	}()
	// Only the initial TPKT byte is sent. Waiting for a complete negotiation
	// would consume the setup timeout instead of rejecting admission promptly.
	if _, err := client.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("connection was not closed promptly: %v", err)
	}
	select {
	case <-done:
		if !checked {
			t.Fatal("RDP bypassed admission")
		}
	case <-time.After(time.Second):
		t.Fatal("RDP admission did not finish")
	}
}
