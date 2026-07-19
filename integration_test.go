package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIntegrationLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	_ = newGatewayIntegrationSettings(t, ldapURL)
	t.Setenv("LISTEN_ADDR", ":8443")

	gateway, err := bootGateway()
	if err != nil {
		t.Fatalf("Failed to boot gateway: %v", err)
	}
	defer func() {
		if err := gateway.Close(); err != nil {
			t.Fatalf("close gateway: %v", err)
		}
	}()

	baseURL := "https://127.0.0.1:8443"

	loginClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	assertLoginSuccess(ctx, t, baseURL, loginClient, "testuser", "dogood")
	assertLoginFailure(ctx, t, baseURL, loginClient, "serviceuser", "mysecret2", "Invalid credentials.")
	assertLoginFailure(ctx, t, baseURL, loginClient, "hackers", "wrongpass2", "Invalid credentials.")
	assertLoginFailure(ctx, t, baseURL, loginClient, "hackers", "", "Missing credentials.")
}

func assertLoginSuccess(ctx context.Context, t *testing.T, baseURL string, client *http.Client, username, password string) {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		// Mirror the Origin a browser sends on a same-origin form POST so the
		// login handler's same-origin (CSRF) gate admits the request.
		"Origin": baseURL,
	}
	status, _, header := doRequest(ctx, t, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
	if status != http.StatusSeeOther {
		t.Fatalf("expected 303 for login, got %d", status)
	}
	if loc := header.Get("Location"); loc != "/api/dashboard" {
		t.Fatalf("expected redirect to /api/dashboard, got %q", loc)
	}
	if !strings.Contains(header.Get("Set-Cookie"), "cv_session=") {
		t.Fatalf("expected session cookie on login")
	}
}

func doRequest(ctx context.Context, t *testing.T, baseURL string, client *http.Client, method, path, user, pass string, body io.Reader, headers map[string]string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), resp.Header.Clone()
}

func assertLoginFailure(ctx context.Context, t *testing.T, baseURL string, client *http.Client, username, password, message string) {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		// Mirror the Origin a browser sends on a same-origin form POST so the
		// login handler's same-origin (CSRF) gate admits the request.
		"Origin": baseURL,
	}
	status, body, _ := doRequest(ctx, t, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for login page, got %d: %s", status, body)
	}
	if !strings.Contains(body, message) {
		t.Fatalf("expected login message %q, got %q", message, body)
	}
}
