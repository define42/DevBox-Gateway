package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/dashboard"
	"rdptlsgateway/internal/session"
	"strings"
	"testing"
)

func TestExtractCredentialsFromForm(t *testing.T) {
	form := url.Values{"username": {"alice"}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	u, p, ok, err := extractCredentials(rec, req)
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
	rec := httptest.NewRecorder()

	u, p, ok, err := extractCredentials(rec, req)
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
	rec := httptest.NewRecorder()

	_, _, ok, err := extractCredentials(rec, req)
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
	rec := httptest.NewRecorder()

	_, _, ok, err := extractCredentials(rec, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when password is empty")
	}
}

func TestExtractCredentialsRejectsOversizedForm(t *testing.T) {
	body := "username=" + strings.Repeat("a", maxFormBodyBytes) + "&password=secret"
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	_, _, ok, err := extractCredentials(rec, req)
	if err == nil {
		t.Fatal("expected parse error for oversized form body")
	}
	if ok {
		t.Fatal("expected ok=false for oversized form body")
	}
}

func TestServeLogin(t *testing.T) {
	rec := httptest.NewRecorder()
	serveLogin(rec, "")

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()

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
	if strings.Contains(body, "cdn.jsdelivr.net") || strings.Contains(body, "https://") || strings.Contains(body, "http://") {
		t.Fatal("login page must not load browser assets from external URLs")
	}
	if !strings.Contains(body, "/static/vendor/bootstrap/5.3.2/bootstrap.min.css") {
		t.Fatal("expected login page to reference vendored Bootstrap CSS")
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

func setSameOriginHeader(req *http.Request) {
	req.Header.Set("Origin", "http://example.com")
}

func TestSameOriginRequestAllowsMatchingHeaders(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		origin  string
		referer string
	}{
		{
			name:   "matching origin",
			target: "http://example.com/api/dashboard",
			origin: "http://example.com",
		},
		{
			name:   "matching origin with port",
			target: "http://example.com:8443/api/dashboard",
			origin: "http://example.com:8443",
		},
		{
			name:    "matching referer",
			target:  "http://example.com/api/dashboard",
			referer: "http://example.com/api/dashboard",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.target, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}

			if !sameOriginRequest(req) {
				t.Fatal("expected request to pass same-origin check")
			}
		})
	}
}

func TestSameOriginRequestRejectsInvalidHeaders(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		origin  string
		referer string
	}{
		{
			name:   "sibling host rejected",
			target: "http://example.com/api/dashboard",
			origin: "http://admin.example.com",
		},
		{
			name:   "scheme mismatch rejected",
			target: "https://example.com/api/dashboard",
			origin: "http://example.com",
		},
		{
			name:    "origin takes precedence over referer",
			target:  "http://example.com/api/dashboard",
			origin:  "http://evil.example.com",
			referer: "http://example.com/api/dashboard",
		},
		{
			name:   "null origin rejected",
			target: "http://example.com/api/dashboard",
			origin: "null",
		},
		{
			name:   "missing origin and referer rejected",
			target: "http://example.com/api/dashboard",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.target, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}

			if sameOriginRequest(req) {
				t.Fatal("expected request to fail same-origin check")
			}
		})
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

func TestValidateGuestUsername(t *testing.T) {
	const fallback = "alice"
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty falls back to owner", "", fallback, false},
		{"whitespace falls back to owner", "   ", fallback, false},
		{"trimmed override", "  bob  ", "bob", false},
		{"valid simple", "bob", "bob", false},
		{"valid with digits and hyphen", "dev-user1", "dev-user1", false},
		{"valid leading underscore", "_svc", "_svc", false},
		{"leading digit", "1bob", "", true},
		{"leading hyphen", "-bob", "", true},
		{"uppercase", "Bob", "", true},
		{"space inside", "bo b", "", true},
		{"special char", "bob$", "", true},
		{"too long", strings.Repeat("a", 33), "", true},
		{"max length", strings.Repeat("a", 32), strings.Repeat("a", 32), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateGuestUsername(tc.input, fallback)
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

func TestValidateLoginUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"simple", "johndoe", "johndoe", false},
		{"trimmed", "  johndoe  ", "johndoe", false},
		{"email/upn form", "john.doe+test@example.com", "john.doe+test@example.com", false},
		{"digits and hyphen", "dev-user1", "dev-user1", false},
		{"uppercase allowed", "JohnDoe", "JohnDoe", false},
		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"path traversal", "../../etc/passwd", "", true},
		{"forward slash", "a/b", "", true},
		{"backslash", `a\b`, "", true},
		{"xml angle bracket", "a<b", "", true},
		{"xml ampersand", "a&b", "", true},
		{"double quote", `a"b`, "", true},
		{"single quote", "a'b", "", true},
		{"inner space", "john doe", "", true},
		{"newline", "john\ndoe", "", true},
		{"too long", strings.Repeat("a", maxLoginUsernameLength+1), "", true},
		{"max length", strings.Repeat("a", maxLoginUsernameLength), strings.Repeat("a", maxLoginUsernameLength), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateLoginUsername(tc.input)
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

func TestValidateGuestPassword(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		confirm string
		want    string
		wantErr bool
	}{
		{"empty is required", "", "", "", true},
		{"confirm empty", "hunter2", "", "", true},
		{"simple match", "hunter2", "hunter2", "hunter2", false},
		{"mismatch", "hunter2", "hunter3", "", true},
		{"spaces preserved", "  pass word  ", "  pass word  ", "  pass word  ", false},
		{"whitespace mismatch", " pass ", "pass", "", true},
		{"symbols allowed", "P@ss-w0rd!#$", "P@ss-w0rd!#$", "P@ss-w0rd!#$", false},
		{"max length", strings.Repeat("a", 128), strings.Repeat("a", 128), strings.Repeat("a", 128), false},
		{"too long", strings.Repeat("a", 129), strings.Repeat("a", 129), "", true},
		{"newline rejected", "pass\nword", "pass\nword", "", true},
		{"tab rejected", "pass\tword", "pass\tword", "", true},
		{"del rejected", "pass\x7fword", "pass\x7fword", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateGuestPassword(tc.raw, tc.confirm)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q/%q", tc.raw, tc.confirm)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q/%q: %v", tc.raw, tc.confirm, err)
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
		name     string
		username string
		vmName   string
		want     string
		wantErr  bool
	}{
		{name: "valid owned vm name", username: "alice", vmName: "alice-desktop", want: "alice-desktop"},
		{name: "valid owned vm name with email prefix", username: "alice@example.com", vmName: "alice@example.com-desktop", want: "alice@example.com-desktop"},
		{name: "owned suffix too long", username: "alice", vmName: "alice-" + strings.Repeat("x", maxVMNameLength+1), wantErr: true},
		{name: "legacy unprefixed name", username: "alice", vmName: "legacy-imported-vm", want: "legacy-imported-vm"},
		{name: "empty", username: "alice", vmName: "", wantErr: true},
		{name: "too long", username: "alice", vmName: strings.Repeat("x", maxVMNameFieldLen+1), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"vm_name": {tc.vmName}}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			got, err := parseDashboardVMName(rec, req, tc.username)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestParseDashboardVMNameRejectsOversizedForm(t *testing.T) {
	body := "vm_name=" + strings.Repeat("a", maxFormBodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	_, err := parseDashboardVMName(rec, req, "alice")
	if !errors.Is(err, errInvalidDashboardForm) {
		t.Fatalf("expected invalid dashboard form error, got %v", err)
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
	var resp dashboard.ActionResponse
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
	dashboard.WriteJSON(rec, http.StatusOK, dashboard.ActionResponse{OK: true, Message: "done"})

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
	if got := rec.Header().Get("Cache-Control"); got != cacheControlValue {
		t.Fatalf("expected Cache-Control %q, got %q", cacheControlValue, got)
	}
	if got := rec.Header().Get("Pragma"); got != pragmaValue {
		t.Fatalf("expected Pragma %q, got %q", pragmaValue, got)
	}
	if got := rec.Header().Get("Expires"); got != expiresValue {
		t.Fatalf("expected Expires %q, got %q", expiresValue, got)
	}

	var resp dashboard.ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.Message != "done" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestGenerateRDP(t *testing.T) {
	rdp := dashboard.GenerateRDP("vm1.desktop.local.gd", "alice")
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

func TestLogoutRejectsGetWithoutDestroyingSession(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if !sm.UserHasActiveSessionFromIP("alice", "192.0.2.10") {
		t.Fatal("expected GET /logout to leave the session active")
	}
}

func TestLogoutRejectsMissingSameOriginHeader(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if !sm.UserHasActiveSessionFromIP("alice", "192.0.2.10") {
		t.Fatal("expected rejected logout to leave the session active")
	}
}

func TestLogoutRedirects(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	setSameOriginHeader(req)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
	if sm.UserHasActiveSessionFromIP("alice", "192.0.2.10") {
		t.Fatal("expected POST /logout to destroy the session")
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
	setSameOriginHeader(req)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", rec.Code)
	}
}

func TestDashboardPostRejectsMissingSameOriginHeader(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{"vm_name": {"alice-devbox"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp dashboard.ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK || resp.Error != forbiddenOrigin {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestDashboardPostRejectsCrossOriginHeader(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{"vm_name": {"alice-devbox"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/start", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://admin.example.com")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp dashboard.ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.OK || resp.Error != forbiddenOrigin {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestDashboardPostAllowsSameOriginReferer(t *testing.T) {
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
	req.Header.Set("Referer", "http://example.com/api/dashboard")
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected request to pass origin check and fail validation with 400, got %d: %s", rec.Code, rec.Body.String())
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
	setSameOriginHeader(req)
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
	setSameOriginHeader(req)
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
	setSameOriginHeader(req)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardPostMissingPassword(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{
		"vm_name":       {"my-vm"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"4096"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSameOriginHeader(req)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardPostPasswordMismatch(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	form := url.Values{
		"vm_name":             {"my-vm"},
		"vm_password":         {"secret-one"},
		"vm_password_confirm": {"secret-two"},
		"vm_vcpu":             {"2"},
		"vm_memory_mib":       {"4096"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSameOriginHeader(req)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDashboardPostRejectsOversizedForm(t *testing.T) {
	sm := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sm, settings)
	cookie := issueSessionCookie(t, sm, "alice")

	body := "vm_name=" + strings.Repeat("a", maxFormBodyBytes) + "&vm_vcpu=2&vm_memory_mib=4096"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSameOriginHeader(req)
	req.AddCookie(cookie)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp dashboard.ActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "Invalid form submission." {
		t.Fatalf("expected invalid form submission error, got %q", resp.Error)
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
			setSameOriginHeader(req)
			req.AddCookie(cookie)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}
