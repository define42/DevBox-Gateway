package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
)

func TestExtractCredentialsFromForm(t *testing.T) {
	form := url.Values{"username": {"alice"}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	u, p, ok, err := extractCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u != "alice" || p != "secret" {
		t.Fatalf("expected (alice, secret), got (%q, %q)", u, p)
	}
}

func TestExtractCredentialsFromBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.SetBasicAuth("bob", "pass123")

	u, p, ok, err := extractCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if u != "bob" || p != "pass123" {
		t.Fatalf("expected (bob, pass123), got (%q, %q)", u, p)
	}
}

func TestExtractCredentialsMissing(t *testing.T) {
	form := url.Values{"username": {""}, "password": {""}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, _, ok, err := extractCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for empty credentials")
	}
}

func TestExtractCredentialsPartialMissing(t *testing.T) {
	form := url.Values{"username": {"alice"}, "password": {""}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, _, ok, err := extractCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when password is empty")
	}
}

func TestServeLogin(t *testing.T) {
	rec := httptest.NewRecorder()
	serveLogin(rec, "")

	res := rec.Result()
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "DevBoxGateway") {
		t.Fatal("expected login page content")
	}
	// No error message
	if strings.Contains(body, "alert-danger") {
		t.Fatal("expected no error alert when message is empty")
	}
}

func TestServeLoginWithError(t *testing.T) {
	rec := httptest.NewRecorder()
	serveLogin(rec, "Bad credentials")

	body := rec.Body.String()
	if !strings.Contains(body, "alert-danger") {
		t.Fatal("expected error alert")
	}
	if !strings.Contains(body, "Bad credentials") {
		t.Fatal("expected error message in body")
	}
}

func TestServeLoginHTMLEscaping(t *testing.T) {
	rec := httptest.NewRecorder()
	serveLogin(rec, "<script>alert('xss')</script>")

	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatal("expected HTML-escaped script tag")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("expected escaped content")
	}
}

func TestSetNoCacheHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	setNoCacheHeaders(rec)

	if got := rec.Header().Get("Cache-Control"); got != cacheControlValue {
		t.Fatalf("expected Cache-Control %q, got %q", cacheControlValue, got)
	}
	if got := rec.Header().Get("Pragma"); got != pragmaValue {
		t.Fatalf("expected Pragma %q, got %q", pragmaValue, got)
	}
	if got := rec.Header().Get("Expires"); got != expiresValue {
		t.Fatalf("expected Expires %q, got %q", expiresValue, got)
	}
}

func TestHandleLoginGet(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)

	handleLoginGet(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "DevBoxGateway") {
		t.Fatal("expected login page content")
	}
}

func TestValidateVMName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid", "my-vm-1", "my-vm-1", false},
		{"valid simple", "test", "test", false},
		{"empty", "", "", true},
		{"whitespace only", "  ", "", true},
		{"starts with hyphen", "-bad", "", true},
		{"ends with hyphen", "bad-", "", true},
		{"uppercase", "BadVM", "", true},
		{"spaces", "my vm", "", true},
		{"special chars", "my_vm!", "", true},
		{"too long", strings.Repeat("a", 64), "", true},
		{"max length", strings.Repeat("a", 63), strings.Repeat("a", 63), false},
		{"trimmed", "  valid  ", "valid", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateVMName(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestParseDashboardVCPU(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{"valid 1", "1", 1, false},
		{"valid 2", "2", 2, false},
		{"valid 4", "4", 4, false},
		{"valid 8", "8", 8, false},
		{"empty", "", 0, true},
		{"invalid", "abc", 0, true},
		{"unsupported", "3", 0, true},
		{"negative", "-1", 0, true},
		{"zero", "0", 0, true},
		{"trimmed", " 2 ", 2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDashboardVCPU(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, got)
			}
		})
	}
}

func TestParseDashboardMemoryMiB(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{"valid 4096", "4096", 4096, false},
		{"valid 8192", "8192", 8192, false},
		{"valid 16384", "16384", 16384, false},
		{"valid 32768", "32768", 32768, false},
		{"empty", "", 0, true},
		{"invalid", "abc", 0, true},
		{"unsupported", "1024", 0, true},
		{"trimmed", " 4096 ", 4096, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDashboardMemoryMiB(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, got)
			}
		})
	}
}

func TestParseDashboardVMName(t *testing.T) {
	tests := []struct {
		name    string
		vmName  string
		wantErr bool
	}{
		{"valid", "alice-desktop", false},
		{"empty", "", true},
		{"too long", strings.Repeat("x", 129), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"vm_name": {tc.vmName}}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			_, err := parseDashboardVMName(req)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHandleDashboardFormError(t *testing.T) {
	// nil error returns false
	rec := httptest.NewRecorder()
	if handleDashboardFormError(rec, "test", nil) {
		t.Fatal("expected false for nil error")
	}

	// errInvalidDashboardForm
	rec = httptest.NewRecorder()
	if !handleDashboardFormError(rec, "test", errInvalidDashboardForm) {
		t.Fatal("expected true for errInvalidDashboardForm")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	var resp dashboardActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "Invalid form submission." {
		t.Fatalf("expected 'Invalid form submission.', got %q", resp.Error)
	}

	// generic error
	rec = httptest.NewRecorder()
	if !handleDashboardFormError(rec, "test", errForTest) {
		t.Fatal("expected true for generic error")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

var errForTest = errorString("test error")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, dashboardActionResponse{OK: true, Message: "done"})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("expected JSON content type, got %q", ct)
	}

	var resp dashboardActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.Message != "done" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestGenerateRDP(t *testing.T) {
	rdp := generateRDP("vm1.desktop.local.gd", "alice")
	if rdp == "" {
		t.Fatal("expected non-empty RDP data URI")
	}
	if !strings.HasPrefix(rdp, "data:application/x-rdp;base64,") {
		t.Fatalf("expected base64 data URI, got %q", rdp[:50])
	}
}

func TestHandleHealthEndpoint(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Fatalf("expected %q, got %q", "ok\n", got)
	}
}

func TestRootRedirectsToLogin(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestLoginGetServesPage(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "DevBoxGateway") {
		t.Fatal("expected login page content")
	}
}

func TestLogoutRedirects(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestDashboardRequiresSession(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	router.ServeHTTP(rec, req)

	// Should redirect to login since no session
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", rec.Code)
	}
}

func TestDashboardDataRequiresSession(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/data", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", rec.Code)
	}
}

func TestDashboardPostCreateVMRequiresSession(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)

	form := url.Values{
		"vm_name":       {"test-vm"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"4096"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", rec.Code)
	}
}

func TestDashboardPostInvalidVMName(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{
		"vm_name":       {"INVALID NAME!"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"4096"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardPostInvalidVCPU(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{
		"vm_name":       {"my-vm"},
		"vm_vcpu":       {"99"},
		"vm_memory_mib": {"4096"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardPostInvalidMemory(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{
		"vm_name":       {"my-vm"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"999"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardMutationEndpointsRejectMissingVMName(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	paths := []string{
		"/api/dashboard/start",
		"/api/dashboard/restart",
		"/api/dashboard/shutdown",
		"/api/dashboard/remove",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			form := url.Values{"vm_name": {""}}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestDashboardResourcesInvalidVCPU(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{
		"vm_name":       {"alice-desktop"},
		"vm_vcpu":       {"99"},
		"vm_memory_mib": {"4096"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/resources", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardResourcesInvalidMemory(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{
		"vm_name":       {"alice-desktop"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"999"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/resources", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
