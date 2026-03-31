package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/types"
	"testing"
)

func issueSessionCookie(t *testing.T, sessionManager *session.Manager, username string) *http.Cookie {
	t.Helper()

	user, err := types.NewUser(username, "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "192.0.2.10:12345"

	handler := sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := sessionManager.CreateSession(r.Context(), user, r.RemoteAddr); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "cv_session" {
			return cookie
		}
	}

	t.Fatal("session cookie not set")
	return nil
}

func TestCompleteLoginRecordsLoginIP(t *testing.T) {
	sessionManager := session.NewManager()
	user, err := types.NewUser("alice", "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "[::ffff:192.0.2.60]:4321"
	rec := httptest.NewRecorder()

	handler := sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		completeLogin(sessionManager, w, r, user)
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected %d, got %d", http.StatusSeeOther, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/api/dashboard" {
		t.Fatalf("expected redirect to /api/dashboard, got %q", loc)
	}
	if !sessionManager.UserHasActiveSessionFromIP("alice", "192.0.2.60") {
		t.Fatal("expected login to record the canonical client IP in session storage")
	}
}

func assertDashboardOwnershipErrorResponse(t *testing.T, verb string, err error, wantCode int, wantErr string) {
	t.Helper()

	rec := httptest.NewRecorder()
	writeDashboardVMActionOwnershipError(rec, "alice-bob-desktop", "alice", verb, err)

	if rec.Code != wantCode {
		t.Fatalf("expected %d, got %d with body %s", wantCode, rec.Code, rec.Body.String())
	}

	var resp dashboardActionResponse
	if decodeErr := json.NewDecoder(rec.Body).Decode(&resp); decodeErr != nil {
		t.Fatalf("decode response: %v", decodeErr)
	}
	if resp.OK {
		t.Fatalf("expected ok=false, got true")
	}
	if resp.Error != wantErr {
		t.Fatalf("expected error %q, got %q", wantErr, resp.Error)
	}
}

func TestWriteDashboardVMActionOwnershipError(t *testing.T) {
	tests := []struct {
		name     string
		verb     string
		err      error
		wantCode int
		wantErr  string
	}{
		{
			name:     "resources forbidden",
			verb:     "update",
			wantCode: http.StatusForbidden,
			wantErr:  "You do not have permission to update this VM.",
		},
		{
			name:     "start forbidden",
			verb:     "start",
			wantCode: http.StatusForbidden,
			wantErr:  "You do not have permission to start this VM.",
		},
		{
			name:     "restart forbidden",
			verb:     "restart",
			wantCode: http.StatusForbidden,
			wantErr:  "You do not have permission to restart this VM.",
		},
		{
			name:     "shutdown forbidden",
			verb:     "shutdown",
			wantCode: http.StatusForbidden,
			wantErr:  "You do not have permission to shutdown this VM.",
		},
		{
			name:     "remove forbidden",
			verb:     "remove",
			wantCode: http.StatusForbidden,
			wantErr:  "You do not have permission to remove this VM.",
		},
		{
			name:     "lookup failure",
			verb:     "update",
			err:      errors.New("boom"),
			wantCode: http.StatusInternalServerError,
			wantErr:  "Unable to verify VM ownership.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertDashboardOwnershipErrorResponse(t, tc.verb, tc.err, tc.wantCode, tc.wantErr)
		})
	}
}
