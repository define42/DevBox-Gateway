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
	"rdptlsgateway/internal/types"
)

func issueSessionCookie(t *testing.T, sessionManager *session.Manager, username string) *http.Cookie {
	t.Helper()

	user, err := types.NewUser(username, "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)

	handler := sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := sessionManager.CreateSession(r.Context(), user); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "cv_session" {
			return cookie
		}
	}

	t.Fatal("session cookie not set")
	return nil
}

func TestDashboardMutationEndpointsRejectNonOwnerVM(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")
	stubDashboardVMOwnershipByPrefix(t)

	tests := []struct {
		name    string
		path    string
		form    url.Values
		wantErr string
	}{
		{
			name: "resources",
			path: "/api/dashboard/resources",
			form: url.Values{
				"vm_name":       {"bob-desktop"},
				"vm_vcpu":       {"2"},
				"vm_memory_mib": {"4096"},
			},
			wantErr: "You do not have permission to update this VM.",
		},
		{
			name: "start",
			path: "/api/dashboard/start",
			form: url.Values{
				"vm_name": {"bob-desktop"},
			},
			wantErr: "You do not have permission to start this VM.",
		},
		{
			name: "restart",
			path: "/api/dashboard/restart",
			form: url.Values{
				"vm_name": {"bob-desktop"},
			},
			wantErr: "You do not have permission to restart this VM.",
		},
		{
			name: "shutdown",
			path: "/api/dashboard/shutdown",
			form: url.Values{
				"vm_name": {"bob-desktop"},
			},
			wantErr: "You do not have permission to shutdown this VM.",
		},
		{
			name: "remove",
			path: "/api/dashboard/remove",
			form: url.Values{
				"vm_name": {"bob-desktop"},
			},
			wantErr: "You do not have permission to remove this VM.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected %d, got %d with body %s", http.StatusForbidden, rec.Code, rec.Body.String())
			}

			var resp dashboardActionResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if resp.OK {
				t.Fatalf("expected ok=false, got true")
			}
			if resp.Error != tc.wantErr {
				t.Fatalf("expected error %q, got %q", tc.wantErr, resp.Error)
			}
		})
	}
}

func TestDashboardMutationEndpointsRejectPrefixCollidingVM(t *testing.T) {
	sessionManager := session.NewManager()
	settings := config.NewSettingType(false)
	router := getRemoteGatewayRotuer(sessionManager, settings)
	cookie := issueSessionCookie(t, sessionManager, "alice")

	stubDashboardVMOwnershipCheck(t, func(name, username string) (bool, error) {
		if name != "alice-bob-desktop" || username != "alice" {
			t.Fatalf("unexpected ownership check for %q / %q", name, username)
		}
		return false, nil
	})

	form := url.Values{
		"vm_name":       {"alice-bob-desktop"},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"4096"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/resources", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d with body %s", http.StatusForbidden, rec.Code, rec.Body.String())
	}

	var resp dashboardActionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "You do not have permission to update this VM." {
		t.Fatalf("expected ownership denial, got %q", resp.Error)
	}
}
