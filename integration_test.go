package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegrationLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanup := startGlauth(ctx, t, "")
	defer cleanup()

	os.Setenv("LDAP_URL", ldapURL)
	os.Setenv("LDAP_SKIP_TLS_VERIFY", "true")
	os.Setenv("LDAP_STARTTLS", "false")
	os.Setenv("LDAP_USER_DOMAIN", "@example.com")

	os.Setenv("LISTEN_ADDR", ":8443")

	go bootGateway()
	time.Sleep(2 * time.Second) // wait for server to start

	baseURL := "https://127.0.0.1:8443"

	loginClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	assertLoginSuccess(t, ctx, baseURL, loginClient, "testuser", "dogood")
	assertLoginFailure(t, ctx, baseURL, loginClient, "serviceuser", "mysecret2", "Invalid credentials.")
	assertLoginFailure(t, ctx, baseURL, loginClient, "hackers", "wrongpass2", "Invalid credentials.")
	assertLoginFailure(t, ctx, baseURL, loginClient, "hackers", "", "Missing credentials.")

}

func assertLoginSuccess(t *testing.T, ctx context.Context, baseURL string, client *http.Client, username, password string) {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	status, _, header := doRequest(t, ctx, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
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

func doRequest(t *testing.T, ctx context.Context, baseURL string, client *http.Client, method, path, user, pass string, body io.Reader, headers map[string]string) (int, string, http.Header) {
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
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data), resp.Header.Clone()
}

func assertLoginFailure(t *testing.T, ctx context.Context, baseURL string, client *http.Client, username, password, message string) {
	t.Helper()
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	status, body, _ := doRequest(t, ctx, baseURL, client, http.MethodPost, "/login", "", "", strings.NewReader(form.Encode()), headers)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for login page, got %d: %s", status, body)
	}
	if !strings.Contains(body, message) {
		t.Fatalf("expected login message %q, got %q", message, body)
	}
}
