package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
)

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := NewHandler(sessionManager, settings)

	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "SAMEORIGIN",
		"Referrer-Policy":           "same-origin",
		"Content-Security-Policy":   contentSecurityPolicy,
	}

	for _, path := range []string{"/login", "/api/health", "/static/novnc/vnc.html"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		for header, value := range want {
			if got := rec.Header().Get(header); got != value {
				t.Errorf("%s: expected %s %q, got %q", path, header, value, got)
			}
		}
	}
}
