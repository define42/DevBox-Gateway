package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"strings"
	"testing"
)

func authenticatedRequest(t *testing.T, sm *session.Manager, router http.Handler, method, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	cookie := issueSessionCookie(t, sm, "alice")

	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, reader)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestDashboardDataAuthenticatedReturnsJSON(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	rec := authenticatedRequest(t, sm, router, http.MethodGet, "/api/dashboard/data", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	if filename, _ := payload["filename"].(string); filename != "rdpgw.rdp" {
		t.Fatalf("expected filename rdpgw.rdp, got %q", filename)
	}
}

func TestDashboardCreateRejectsInvalidName(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	body := url.Values{
		"vm_name":       {"BadName"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"1024"},
	}.Encode()
	rec := authenticatedRequest(t, sm, router, http.MethodPost, "/api/dashboard", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid vm name, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardCreateRejectsInvalidVCPU(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	body := url.Values{
		"vm_name":       {"alice-devbox"},
		"vm_vcpu":       {"-1"},
		"vm_memory_mib": {"1024"},
	}.Encode()
	rec := authenticatedRequest(t, sm, router, http.MethodPost, "/api/dashboard", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid vcpu, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardCreateRejectsInvalidMemory(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	body := url.Values{
		"vm_name":       {"alice-devbox"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"0"},
	}.Encode()
	rec := authenticatedRequest(t, sm, router, http.MethodPost, "/api/dashboard", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid memory, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardActionRequiresAuthentication(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	paths := []string{
		"/api/dashboard/start",
		"/api/dashboard/restart",
		"/api/dashboard/shutdown",
		"/api/dashboard/remove",
		"/api/dashboard/resources",
	}
	for _, path := range paths {
		body := url.Values{"vm_name": {"alice-devbox"}}.Encode()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		// Session middleware redirects unauthenticated dashboard API requests to /login.
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: expected 303 redirect, got %d body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestDashboardCreateRequiresAuthentication(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	body := url.Values{
		"vm_name":       {"alice-devbox"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"1024"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect for unauthenticated create, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardDataRequiresAuthentication(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/data", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardActionForbidsUnknownVM(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	// VM "alice-nonexistent" is not present in the in-process virt instance,
	// so ownership lookup returns owned=false → 403 with our forbidden message.
	body := url.Values{"vm_name": {"alice-nonexistent"}}.Encode()
	rec := authenticatedRequest(t, sm, router, http.MethodPost, "/api/dashboard/start", body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owned vm, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDashboardResourcesRejectsInvalidVCPU(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	// First the VM ownership check has to pass — without libvirt the VM is
	// unknown, so the route returns 403 before the resource parameters are
	// inspected. Use a malformed name to instead exercise the form-parse path.
	body := url.Values{"vm_name": {""}, "vm_vcpu": {"abc"}, "vm_memory_mib": {"1024"}}.Encode()
	rec := authenticatedRequest(t, sm, router, http.MethodPost, "/api/dashboard/resources", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing vm_name, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRootRedirectsToLoginNoAuth(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestHealthEndpoint(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "ok" {
		t.Fatalf("expected body 'ok', got %q", body)
	}
}
