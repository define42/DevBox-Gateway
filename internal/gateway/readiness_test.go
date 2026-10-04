package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
)

func TestReadinessSeparatesAuditHealthFromListenerLiveness(t *testing.T) {
	audit := &readinessTestComponent{}
	collector := &readinessTestComponent{}
	runtime := &gatewayRuntime{auditSink: audit, sauron: collector}
	manager := session.New()
	t.Cleanup(func() { _ = manager.Close() })
	router := newHandler(manager, config.NewSettings(false), runtime.readiness)
	for _, tt := range []struct {
		name                   string
		auditErr, collectorErr error
		want                   int
	}{
		{name: "healthy", want: http.StatusOK},
		{name: "audit write lost", auditErr: errors.New("private/path write failed"), want: http.StatusServiceUnavailable},
		{name: "missing guest", collectorErr: errors.New("private-vm agent missing"), want: http.StatusServiceUnavailable},
		{name: "collector recovered", want: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			audit.err, collector.err = tt.auditErr, tt.collectorErr
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ready", nil))
			if rec.Code != tt.want || strings.Contains(rec.Body.String(), "private") {
				t.Fatalf("readiness status=%d body=%s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Connection") != "close" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("readiness probe must not retain connection slots or cached results")
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
			if rec.Code != http.StatusOK {
				t.Fatal("audit failure broke the liveness contract")
			}
		})
	}
}

func TestReadinessRequiresConfiguredProviders(t *testing.T) {
	if (&gatewayRuntime{}).readiness() == nil {
		t.Fatal("missing audit providers reported ready")
	}
	w := httptest.NewRecorder()
	readinessHandler(nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ready", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured readiness = %d", w.Code)
	}
}

func TestGatewayExitsOnMandatoryCollectorFailure(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "listener error", err: errors.New("permanent accept failure")},
		{name: "unexpected clean termination"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			done := make(chan struct{})
			close(done)
			runtime := &gatewayRuntime{done: make(chan struct{}), sauron: &readinessTestComponent{done: done, err: tt.err}}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if code := runtime.wait(ctx); code != 1 {
				t.Fatalf("collector termination exit=%d, want1", code)
			}
		})
	}
}

func TestGatewayCancellationExitsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if code := (&gatewayRuntime{done: make(chan struct{})}).wait(ctx); code != 0 {
		t.Fatalf("cancel exit=%d", code)
	}
}

type readinessTestComponent struct {
	err  error
	done <-chan struct{}
}

func (c *readinessTestComponent) Close() error          { return nil }
func (c *readinessTestComponent) Readiness() error      { return c.err }
func (c *readinessTestComponent) Done() <-chan struct{} { return c.done }
func (c *readinessTestComponent) Err() error            { return c.err }
