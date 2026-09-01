package gateway

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"
)

func TestValidatePprofListenAddress(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		wantErr    bool
	}{
		{name: "IPv4 loopback", listenAddr: "127.0.0.1:6060"},
		{name: "IPv6 loopback", listenAddr: "[::1]:6060"},
		{name: "IPv4 wildcard", listenAddr: "0.0.0.0:6060", wantErr: true},
		{name: "IPv6 wildcard", listenAddr: "[::]:6060", wantErr: true},
		{name: "non-loopback", listenAddr: "192.0.2.10:6060", wantErr: true},
		{name: "hostname", listenAddr: "localhost:6060", wantErr: true},
		{name: "empty host", listenAddr: ":6060", wantErr: true},
		{name: "missing port", listenAddr: "127.0.0.1", wantErr: true},
		{name: "empty port", listenAddr: "127.0.0.1:", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePprofListenAddress(tt.listenAddr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePprofListenAddress(%q) error = %v, wantErr %v", tt.listenAddr, err, tt.wantErr)
			}
		})
	}
}

func TestNewPprofHandlerServesProfiles(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()

	newPprofHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("pprof index status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "Types of profiles available") {
		t.Fatalf("pprof index did not contain the profile listing: %q", rec.Body.String())
	}
}

func TestStartPprofServerDisabled(t *testing.T) {
	profiler, err := startPprofServer(config.NewSettings(false))
	if err != nil {
		t.Fatalf("startPprofServer() error = %v", err)
	}
	if profiler != nil {
		t.Fatal("startPprofServer() returned a server while disabled")
	}
}

func TestStartPprofServerRejectsNonLoopback(t *testing.T) {
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestString(config.PPROF_LISTEN_ADDR, "0.0.0.0:6060"); err != nil {
		t.Fatalf("configure pprof address: %v", err)
	}

	profiler, err := startPprofServer(settings)
	if err == nil {
		if profiler != nil {
			_ = profiler.Close()
		}
		t.Fatal("startPprofServer() accepted a wildcard listener")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("startPprofServer() error = %q, want loopback validation", err)
	}
}

func TestStartPprofServerUsesDedicatedLoopbackListener(t *testing.T) {
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestString(config.PPROF_LISTEN_ADDR, "127.0.0.1:0"); err != nil {
		t.Fatalf("configure pprof address: %v", err)
	}

	profiler, err := startPprofServer(settings)
	if err != nil {
		t.Fatalf("startPprofServer() error = %v", err)
	}
	if profiler == nil {
		t.Fatal("startPprofServer() returned nil while enabled")
	}
	t.Cleanup(func() {
		if err := profiler.Close(); err != nil {
			t.Errorf("close profiler: %v", err)
		}
	})

	tcpAddr, ok := profiler.listener.Addr().(*net.TCPAddr)
	if !ok || !tcpAddr.IP.IsLoopback() {
		t.Fatalf("pprof listener address = %v, want loopback TCP", profiler.listener.Addr())
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + profiler.listener.Addr().String() + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET pprof index: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pprof index status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read pprof response: %v", err)
	}
	if !strings.Contains(string(body), "Types of profiles available") {
		t.Fatalf("pprof index did not contain the profile listing: %q", body)
	}

	if err := profiler.Close(); err != nil {
		t.Fatalf("close profiler: %v", err)
	}
	if err := profiler.Close(); err != nil {
		t.Fatalf("close profiler a second time: %v", err)
	}
}

func TestStartGatewayRuntimeOwnsSeparatePprofServer(t *testing.T) {
	settings := config.NewSettings(false)
	for setting, value := range map[string]string{
		config.LISTEN_ADDR:       "127.0.0.1:0",
		config.PPROF_LISTEN_ADDR: "127.0.0.1:0",
	} {
		if err := settings.OverwriteForTestString(setting, value); err != nil {
			t.Fatalf("configure %s: %v", setting, err)
		}
	}

	runtime, err := startGatewayRuntime(settings, virt.NewInventory(), session.New(), nil)
	if err != nil {
		t.Fatalf("startGatewayRuntime() error = %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close gateway runtime: %v", err)
		}
	})

	if runtime.profiler == nil {
		t.Fatal("gateway runtime did not start the configured pprof server")
	}
	if runtime.listener.Addr().String() == runtime.profiler.listener.Addr().String() {
		t.Fatalf("public and pprof listeners share address %s", runtime.listener.Addr())
	}

	if err := runtime.Close(); err != nil {
		t.Fatalf("close gateway runtime: %v", err)
	}
}

func TestPublicGatewayHandlerDoesNotExposePprof(t *testing.T) {
	publicHandler := NewHandler(session.New(), config.NewSettings(false))
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rec := httptest.NewRecorder()

	publicHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("public pprof status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if strings.Contains(rec.Body.String(), "Types of profiles available") {
		t.Fatal("public gateway response exposed the pprof index")
	}
}
