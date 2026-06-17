package main

import (
	"devboxgateway/internal/config"
	"devboxgateway/internal/session"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)

	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
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
