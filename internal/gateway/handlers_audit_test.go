package gateway

import (
	"bytes"
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

func TestCompleteLoginAuditsAuthenticatedUser(t *testing.T) {
	output := captureStructuredLogs(t)
	sessionManager := session.New()
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

	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionUserLogin || record["user"] != "alice" {
		t.Fatalf("unexpected login audit identity: %#v", record)
	}
	if record["source_ip"] != "192.0.2.60" || record["administrator"] != true {
		t.Fatalf("unexpected login audit context: %#v", record)
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

func TestCompleteLoginAuditsSessionCommitFailure(t *testing.T) {
	output := captureStructuredLogs(t)
	sessionManager := session.New()
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
}

func TestLogoutAuditsAuthenticatedUser(t *testing.T) {
	sessionManager := session.New()
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
