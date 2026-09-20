package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/vmname"

	scs "github.com/alexedwards/scs/v2"
)

type synchronizedLogBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedLogBuffer) Write(payload []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(payload)
}

func (b *synchronizedLogBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buffer.Bytes())
}

func (b *synchronizedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func captureStructuredLogs(t *testing.T) *synchronizedLogBuffer {
	t.Helper()

	previous := slog.Default()
	var output synchronizedLogBuffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})
	return &output
}

func requireSingleAuditRecord(t *testing.T, output *synchronizedLogBuffer) map[string]any {
	t.Helper()

	auditRecords := structuredAuditRecords(t, output)
	if len(auditRecords) != 1 {
		t.Fatalf("expected one audit record, got %d in %q", len(auditRecords), output.String())
	}
	return auditRecords[0]
}

func structuredAuditRecords(t *testing.T, output *synchronizedLogBuffer) []map[string]any {
	t.Helper()

	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	var auditRecords []map[string]any
	for {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode structured log: %v", err)
		}
		if record["msg"] == "audit" {
			auditRecords = append(auditRecords, record)
		}
	}
	return auditRecords
}

type rejectedLoginAuditTestCase struct {
	name              string
	body              string
	sensitiveInput    string
	sameOrigin        bool
	preLock           bool
	authenticationErr bool
	wantStatus        int
	wantUser          string
	wantOperation     string
	wantAuthCalls     int
}

func TestLoginPostAuditsEveryRejectedAttemptExactlyOnce(t *testing.T) {
	const remoteAddr = "192.0.2.59:4321"
	const password = "UNIQUE-LOGIN-AUDIT-PASSWORD"

	tests := []rejectedLoginAuditTestCase{
		{
			name:          "origin rejected",
			body:          url.Values{"username": {"alice"}, "password": {password}}.Encode(),
			wantStatus:    http.StatusForbidden,
			wantOperation: audit.OperationLoginOriginRejected,
		},
		{
			name:          "malformed form",
			body:          "username=alice&password=%zz-" + password,
			sameOrigin:    true,
			wantStatus:    http.StatusOK,
			wantOperation: audit.OperationLoginMalformedRequest,
		},
		{
			name:          "missing credentials",
			body:          url.Values{"username": {"alice"}}.Encode(),
			sameOrigin:    true,
			wantStatus:    http.StatusOK,
			wantUser:      "alice",
			wantOperation: audit.OperationLoginMissingCredentials,
		},
		{
			name:           "invalid username",
			body:           url.Values{"username": {"alice@example.com"}, "password": {password}}.Encode(),
			sensitiveInput: "alice@example.com",
			sameOrigin:     true,
			wantStatus:     http.StatusOK,
			wantOperation:  audit.OperationLoginInvalidUsername,
		},
		{
			name:          "rate limited",
			body:          url.Values{"username": {"alice"}, "password": {password}}.Encode(),
			sameOrigin:    true,
			preLock:       true,
			wantStatus:    http.StatusTooManyRequests,
			wantUser:      "alice",
			wantOperation: audit.OperationLoginRateLimited,
		},
		{
			name:              "identity provider rejected credentials",
			body:              url.Values{"username": {"alice"}, "password": {password}}.Encode(),
			sameOrigin:        true,
			authenticationErr: true,
			wantStatus:        http.StatusOK,
			wantUser:          "alice",
			wantOperation:     audit.OperationLoginAuthenticationFailed,
			wantAuthCalls:     1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertRejectedLoginAudit(t, test, remoteAddr, password)
		})
	}
}

func assertRejectedLoginAudit(t *testing.T, test rejectedLoginAuditTestCase, remoteAddr, password string) {
	t.Helper()

	settings := newRateLimitTestSettings(t)
	manager := session.New()
	t.Cleanup(func() { _ = manager.Close() })
	limiter := newLoginRateLimiter(settings)
	if test.preLock {
		limiter.RecordFailure("alice", remoteAddr)
		limiter.RecordFailure("alice", remoteAddr)
	}

	authCalls := 0
	authenticate := func(_ context.Context, username, suppliedPassword string, _ *config.Settings) (*identity.User, error) {
		authCalls++
		if test.authenticationErr {
			return nil, errors.New("test identity provider echoed credential: " + suppliedPassword)
		}
		return identity.New(username)
	}
	login := handleLoginPostWithAuthenticator(manager, settings, limiter, authenticate)
	handler := auditLoginOutcome(manager.LoadAndSave(manager.EnforceClientIP(login)))
	output := captureStructuredLogs(t)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(test.body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if test.sameOrigin {
		setSameOriginHeader(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != test.wantStatus {
		t.Fatalf("status = %d, want %d", rec.Code, test.wantStatus)
	}
	if authCalls != test.wantAuthCalls {
		t.Fatalf("authentication calls = %d, want %d", authCalls, test.wantAuthCalls)
	}
	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionUserLogin || record["result"] != audit.ResultFailure {
		t.Fatalf("unexpected login audit outcome: %#v", record)
	}
	if record["user"] != test.wantUser || record["source_ip"] != "192.0.2.59" {
		t.Fatalf("unexpected login audit identity: %#v", record)
	}
	if record["operation"] != test.wantOperation {
		t.Fatalf("operation = %#v, want %q", record["operation"], test.wantOperation)
	}
	if bytes.Contains(output.Bytes(), []byte(password)) || bytes.Contains(output.Bytes(), []byte("$6$")) {
		t.Fatalf("login audit exposed credential material: %q", output.String())
	}
	if test.sensitiveInput != "" && bytes.Contains(output.Bytes(), []byte(test.sensitiveInput)) {
		t.Fatalf("login audit exposed rejected input %q: %q", test.sensitiveInput, output.String())
	}
}

func TestCompleteLoginAuditsAuthenticatedUser(t *testing.T) {
	output := captureStructuredLogs(t)
	sessionManager := session.New()
	t.Cleanup(func() { _ = sessionManager.Close() })
	user := &identity.User{Name: "alice", IsAdmin: true}
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "[::ffff:192.0.2.60]:4321"
	rec := httptest.NewRecorder()

	handler := auditLoginOutcome(
		sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			completeLogin(sessionManager, config.NewSettings(false), w, r, user, "dogood")
		})),
	)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionUserLogin || record["user"] != "alice" || record["result"] != audit.ResultSuccess {
		t.Fatalf("unexpected login audit identity: %#v", record)
	}
	if record["source_ip"] != "192.0.2.60" || record["administrator"] != true {
		t.Fatalf("unexpected login audit context: %#v", record)
	}
	if _, exists := record["operation"]; exists {
		t.Fatalf("successful login unexpectedly included a failure operation: %#v", record)
	}
	if bytes.Contains(output.Bytes(), []byte("dogood")) || bytes.Contains(output.Bytes(), []byte("$6$")) {
		t.Fatalf("login audit exposed credential material: %q", output.String())
	}
}

type commitFailStore struct {
	inner scs.Store
}

func (s commitFailStore) Delete(token string) error {
	return s.inner.Delete(token)
}

func (s commitFailStore) Find(token string) ([]byte, bool, error) {
	return s.inner.Find(token)
}

func (commitFailStore) Commit(string, []byte, time.Time) error {
	return errors.New("commit failed")
}

type findFailStore struct {
	scs.Store
}

func (findFailStore) Find(string) ([]byte, bool, error) {
	return nil, false, errors.New("find failed")
}

func TestCompleteLoginAuditsSessionCommitFailure(t *testing.T) {
	output := captureStructuredLogs(t)
	sessionManager := session.New()
	t.Cleanup(func() { _ = sessionManager.Close() })
	sessionManager.Store = commitFailStore{inner: sessionManager.Store}
	user := &identity.User{Name: "alice"}
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "192.0.2.61:4321"
	rec := httptest.NewRecorder()

	handler := auditLoginOutcome(
		sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			completeLogin(sessionManager, config.NewSettings(false), w, r, user, "dogood")
		})),
	)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected session commit failure status 500, got %d", rec.Code)
	}
	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionUserLogin || record["user"] != "alice" || record["result"] != audit.ResultFailure {
		t.Fatalf("unexpected failed-login audit record: %#v", record)
	}
	if record["operation"] != audit.OperationLoginSessionFailed {
		t.Fatalf("unexpected failed-login operation: %#v", record)
	}
	if bytes.Contains(output.Bytes(), []byte("dogood")) || bytes.Contains(output.Bytes(), []byte("$6$")) {
		t.Fatalf("failed-login audit exposed credential material: %q", output.String())
	}
}

func TestLoginAuditsSessionLoadFailure(t *testing.T) {
	output := captureStructuredLogs(t)
	sessionManager := session.New()
	t.Cleanup(func() { _ = sessionManager.Close() })
	sessionManager.Store = findFailStore{Store: sessionManager.Store}
	request := httptest.NewRequest(http.MethodPost, "/login", nil)
	request.RemoteAddr = "192.0.2.62:4321"
	request.AddCookie(&http.Cookie{Name: "cv_session", Value: "unreadable-session"})
	recorder := httptest.NewRecorder()
	handlerCalled := false

	handler := auditLoginOutcome(sessionManager.LoadAndSave(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		handlerCalled = true
	})))
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError || handlerCalled {
		t.Fatalf("session load failure status=%d handlerCalled=%v", recorder.Code, handlerCalled)
	}
	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionUserLogin || record["result"] != audit.ResultFailure ||
		record["operation"] != audit.OperationLoginSessionFailed || record["source_ip"] != "192.0.2.62" {
		t.Fatalf("unexpected session-load audit record: %#v", record)
	}
}

func TestLogoutAuditsAuthenticatedUser(t *testing.T) {
	sessionManager := session.New()
	t.Cleanup(func() { _ = sessionManager.Close() })
	settings := config.NewSettings(false)
	user := &identity.User{Name: "operator", IsAdmin: true}
	cookie := issueSessionCookieForUser(t, sessionManager, user, "192.0.2.70:12345", testGuestPasswordHash)
	output := captureStructuredLogs(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.RemoteAddr = "192.0.2.70:54321"
	setSameOriginHeader(req)
	req.AddCookie(cookie)
	NewHandler(sessionManager, settings).ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected logout redirect, got %d", rec.Code)
	}
	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionUserLogout || record["user"] != "operator" {
		t.Fatalf("unexpected logout audit identity: %#v", record)
	}
	if record["source_ip"] != "192.0.2.70" || record["administrator"] != true {
		t.Fatalf("unexpected logout audit context: %#v", record)
	}
	if record["operation"] != audit.OperationLogoutExplicit {
		t.Fatalf("unexpected logout operation: %#v", record)
	}
}

func TestSessionTimeoutAuditsAuthenticatedUserExactlyOnce(t *testing.T) {
	output := captureStructuredLogs(t)
	manager := session.New()
	t.Cleanup(func() { _ = manager.Close() })
	manager.Lifetime = 25 * time.Millisecond
	user := &identity.User{Name: "timeout-user", IsAdmin: true}
	cookie := issueSessionCookieForUser(t, manager, user, "192.0.2.71:12345", testGuestPasswordHash)
	staleData, found, err := manager.Store.Find(cookie.Value)
	if err != nil || !found {
		t.Fatalf("load session before timeout: found=%v err=%v", found, err)
	}
	staleDeadline, _, err := manager.Codec.Decode(staleData)
	if err != nil {
		t.Fatalf("decode session before timeout: %v", err)
	}

	record := waitForAuditOperation(t, output, audit.ActionUserLogout, audit.OperationLogoutTimeout)
	if record["user"] != "timeout-user" || record["result"] != audit.ResultSuccess {
		t.Fatalf("unexpected timeout audit identity: %#v", record)
	}
	if record["source_ip"] != "192.0.2.71" || record["administrator"] != true {
		t.Fatalf("unexpected timeout audit context: %#v", record)
	}
	if manager.UserHasActiveSessionFromIP("timeout-user", "192.0.2.71") {
		t.Fatal("timed-out session remained active")
	}
	// A request that loaded just before the deadline can finish afterwards.
	// Its stale save must neither recreate the session nor emit another timeout.
	if err := manager.Store.Commit(cookie.Value, staleData, staleDeadline); err == nil {
		t.Fatal("stale session snapshot commit unexpectedly succeeded")
	}
	time.Sleep(50 * time.Millisecond)
	if manager.UserHasActiveSessionFromIP("timeout-user", "192.0.2.71") {
		t.Fatal("stale post-timeout commit recreated the session")
	}

	// Presenting the stale cookie after the timer fired must not produce a
	// second timeout record for the same session token.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.71:54321"
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	manager.LoadAndSave(manager.EnforceClientIP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(rec, req)
	if records := structuredAuditRecords(t, output); len(records) != 1 {
		t.Fatalf("stale timeout cookie produced %d audit records, want 1: %#v", len(records), records)
	}
}

func TestClientIPInvalidationAuditsAuthenticatedUserExactlyOnce(t *testing.T) {
	output := captureStructuredLogs(t)
	manager := session.New()
	t.Cleanup(func() { _ = manager.Close() })
	user := &identity.User{Name: "roaming-user", IsAdmin: true}
	cookie := issueSessionCookieForUser(t, manager, user, "192.0.2.72:12345", testGuestPasswordHash)
	handler := NewHandler(manager, config.NewSettings(false))

	for attempt := 0; attempt < 2; attempt++ {
		req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
		req.RemoteAddr = "198.51.100.72:54321"
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionUserLogout || record["operation"] != audit.OperationLogoutClientIPChanged {
		t.Fatalf("unexpected client-IP invalidation audit type: %#v", record)
	}
	if record["user"] != "roaming-user" || record["result"] != audit.ResultSuccess {
		t.Fatalf("unexpected client-IP invalidation outcome: %#v", record)
	}
	if record["source_ip"] != "198.51.100.72" || record["administrator"] != true {
		t.Fatalf("unexpected client-IP invalidation context: %#v", record)
	}
}

func waitForAuditOperation(
	t *testing.T,
	output *synchronizedLogBuffer,
	action string,
	operation string,
) map[string]any {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, record := range structuredAuditRecords(t, output) {
			if record["action"] == action && record["operation"] == operation {
				return record
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for audit action %q operation %q; logs: %s", action, operation, output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type createVMValidationAuditTestCase struct {
	name      string
	form      url.Values
	wantVM    string
	sensitive string
}

func TestCreateVMValidationFailuresAuditAuthenticatedUser(t *testing.T) {
	const invalidVMName = "INVALID-RAW-VM-SECRET"
	const invalidGuestUsername = "INVALID_GUEST_SECRET"

	tests := []createVMValidationAuditTestCase{
		{
			name: "oversized request omits target",
			form: url.Values{
				"vm_name": {strings.Repeat("a", maxFormBodyBytes)},
			},
		},
		{
			name: "invalid VM name omits raw value",
			form: url.Values{
				"vm_name": {invalidVMName},
			},
			sensitive: invalidVMName,
		},
		{
			name: "invalid guest username includes validated VM",
			form: url.Values{
				"vm_name":     {"desktop"},
				"vm_username": {invalidGuestUsername},
			},
			wantVM:    "alice" + vmname.Separator + "desktop",
			sensitive: invalidGuestUsername,
		},
		{
			name: "missing base image includes validated VM",
			form: url.Values{
				"vm_name": {"desktop"},
			},
			wantVM: "alice" + vmname.Separator + "desktop",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCreateVMValidationFailureAudit(t, test)
		})
	}
}

func assertCreateVMValidationFailureAudit(t *testing.T, test createVMValidationAuditTestCase) {
	t.Helper()

	sessionManager := session.New()
	cookie := issueSessionCookie(t, sessionManager, "alice")
	output := captureStructuredLogs(t)
	rec := hcovPostForm(
		t,
		NewHandler(sessionManager, config.NewSettings(false)),
		cookie,
		"/api/dashboard",
		test.form,
	)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create validation status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionVMCreate || record["user"] != "alice" || record["result"] != audit.ResultFailure {
		t.Fatalf("unexpected create-validation audit identity: %#v", record)
	}
	if record["source_ip"] != "192.0.2.1" {
		t.Errorf("create-validation source IP = %#v, want 192.0.2.1", record["source_ip"])
	}
	assertCreateVMValidationAuditTarget(t, record, test.wantVM)
	assertAuditOmitsSensitiveValue(t, output, test.sensitive)
}

func assertCreateVMValidationAuditTarget(t *testing.T, record map[string]any, wantVM string) {
	t.Helper()

	if wantVM == "" {
		if _, ok := record["vm"]; ok {
			t.Errorf("create-validation audit exposed an unsafe VM target: %#v", record)
		}
		return
	}
	if record["vm"] != wantVM {
		t.Errorf("create-validation VM = %#v, want %q", record["vm"], wantVM)
	}
}

func assertAuditOmitsSensitiveValue(t *testing.T, output *synchronizedLogBuffer, sensitive string) {
	t.Helper()

	if sensitive == "" {
		return
	}
	if bytes.Contains(output.Bytes(), []byte(sensitive)) {
		t.Errorf("audit exposed raw invalid value %q: %s", sensitive, output.String())
	}
}

func TestCreateVMValidationFailureDoesNotAuditUnauthenticatedUser(t *testing.T) {
	const invalidVMName = "UNAUTHENTICATED-RAW-VM-SECRET"
	output := captureStructuredLogs(t)
	sessionManager := session.New()
	form := url.Values{"vm_name": {invalidVMName}}
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	parsed := true
	handler := sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, parsed = parseCreateVMInput(w, r, sessionManager, config.NewSettings(false))
	}))
	handler.ServeHTTP(rec, req)
	if parsed {
		t.Fatal("unauthenticated invalid create input unexpectedly parsed successfully")
	}
	if records := structuredAuditRecords(t, output); len(records) != 0 {
		t.Fatalf("unauthenticated create validation emitted audit records: %#v", records)
	}
	if bytes.Contains(output.Bytes(), []byte(invalidVMName)) {
		t.Fatalf("unauthenticated invalid VM name was logged: %s", output.String())
	}
}
