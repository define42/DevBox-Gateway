package gateway_test

import (
	"devboxgateway/internal/config"
	"devboxgateway/internal/gateway"
	"devboxgateway/internal/session"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandlerHealth(t *testing.T) {
	handler := gateway.NewHandler(
		session.NewManager(),
		config.NewSettingType(false),
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/api/health", nil),
	)

	response := recorder.Result()
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read health response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if string(body) != "ok\n" {
		t.Fatalf("health body = %q, want %q", body, "ok\n")
	}
}
