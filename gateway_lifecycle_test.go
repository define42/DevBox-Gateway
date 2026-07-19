package main

import (
	"context"
	"crypto/tls"
	"devboxgateway/internal/cert"
	"devboxgateway/internal/config"
	"devboxgateway/internal/dashboard"
	"devboxgateway/internal/session"
	"devboxgateway/internal/virt"
	"devboxgateway/internal/vmname"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	gatewayRequestTimeout = 30 * time.Second
	gatewayTestTimeout    = 60 * time.Second
)

type gatewayTestServer struct {
	baseURL string
	client  *http.Client
	close   func()
}

func startGatewayTestServer(t *testing.T, settings *config.SettingsType) gatewayTestServer {
	t.Helper()

	virt.GetInstance()

	sessionManager := session.NewManager()
	mux := getRemoteGatewayRotuer(sessionManager, settings)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		serveListener(ln, mux, frontTLS, sessionManager, settings)
		close(done)
	}()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: gatewayRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cleanup := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("gateway test server did not stop in time")
		}
		if err := frontTLS.Close(); err != nil {
			t.Fatalf("close TLS manager: %v", err)
		}
	}
	t.Cleanup(cleanup)

	return gatewayTestServer{
		baseURL: "https://" + ln.Addr().String(),
		client:  client,
		close:   cleanup,
	}
}

func gatewayRequest(t *testing.T, client *http.Client, method, rawURL string, form url.Values) (*http.Response, string) {
	t.Helper()

	var bodyReader *strings.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	} else {
		bodyReader = strings.NewReader("")
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if methodRequiresSameOrigin(method) {
		req.Header.Set("Origin", req.URL.Scheme+"://"+req.URL.Host)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp, string(data)
}

func methodRequiresSameOrigin(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	default:
		return true
	}
}

func waitForDashboardVMRow(t *testing.T, client *http.Client, baseURL, vmName string, predicate func(dashboard.VM) bool) dashboard.VM {
	t.Helper()

	deadline := time.Now().Add(gatewayTestTimeout)
	for time.Now().Before(deadline) {
		resp, body := gatewayRequest(t, client, http.MethodGet, baseURL+"/api/dashboard/data", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected dashboard data 200, got %d with body %s", resp.StatusCode, body)
		}

		var payload dashboard.DataResponse
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("decode dashboard data: %v", err)
		}
		for _, row := range payload.VMs {
			if row.Name == vmName && predicate(row) {
				return row
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("VM %s did not reach expected dashboard state in time", vmName)
	return dashboard.VM{}
}

func waitForDashboardVMRemoval(t *testing.T, client *http.Client, baseURL, vmName string) {
	t.Helper()

	deadline := time.Now().Add(gatewayTestTimeout)
	for time.Now().Before(deadline) {
		resp, body := gatewayRequest(t, client, http.MethodGet, baseURL+"/api/dashboard/data", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected dashboard data 200, got %d with body %s", resp.StatusCode, body)
		}

		var payload dashboard.DataResponse
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("decode dashboard data: %v", err)
		}
		found := false
		for _, row := range payload.VMs {
			if row.Name == vmName {
				found = true
				break
			}
		}
		if !found {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("VM %s was not removed from dashboard data in time", vmName)
}

func TestGatewayRejectsDuplicateVMCreate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanupLDAP := startGlauth(ctx, t, "")
	defer cleanupLDAP()

	settings := newGatewayIntegrationSettings(t, ldapURL)
	server := startGatewayTestServer(t, settings)

	assertGatewayRedirect(t, server.client, http.MethodPost, server.baseURL+"/login", url.Values{
		"username": {"johndoe"},
		"password": {"dogood"},
	}, http.StatusSeeOther, "/api/dashboard")

	shortName := uniqueGatewayVMShortName("dup")
	fullName := "johndoe" + vmname.Separator + shortName
	t.Cleanup(func() { _ = virt.RemoveVM(fullName, settings) })

	// First create succeeds; creating again with the same name must be refused
	// with a "delete it first" message instead of clobbering the existing VM.
	createGatewayVM(t, server, shortName)
	assertGatewayVMCreateConflict(t, server, shortName)
}

func TestGatewayHTTPSLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanupLDAP := startGlauth(ctx, t, "")
	defer cleanupLDAP()

	settings := newGatewayIntegrationSettings(t, ldapURL)
	server := startGatewayTestServer(t, settings)

	assertGatewayStatus(t, server.client, http.MethodGet, server.baseURL+"/api/health", nil, http.StatusOK)
	assertGatewayRedirect(t, server.client, http.MethodGet, server.baseURL+"/", nil, http.StatusSeeOther, "/login")
	assertGatewayStatusContains(t, server.client, http.MethodGet, server.baseURL+"/static/dashboard.html", nil, http.StatusOK, "Available DevBoxes")
	assertGatewayRedirect(t, server.client, http.MethodPost, server.baseURL+"/login", url.Values{
		"username": {"johndoe"},
		"password": {"dogood"},
	}, http.StatusSeeOther, "/api/dashboard")
	assertGatewayStatusContains(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard", nil, http.StatusOK, "/static/dashboard.js")
	assertGatewayStatus(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/data", nil, http.StatusOK)

	shortName := uniqueGatewayVMShortName("api")
	fullName := "johndoe" + vmname.Separator + shortName
	t.Cleanup(func() {
		_ = virt.RemoveVM(fullName, settings)
	})

	fullName = createGatewayVM(t, server, shortName)
	row := waitForGatewayVMState(t, server, fullName, "running")
	if row.DisplayName != shortName {
		t.Fatalf("expected display name %q, got %q", shortName, row.DisplayName)
	}

	assertGatewayStatus(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/shutdown", url.Values{
		"vm_name": {fullName},
	}, http.StatusOK)
	waitForGatewayVMState(t, server, fullName, "shut off")

	assertGatewayStatus(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/resources", url.Values{
		"vm_name":       {fullName},
		"vm_vcpu":       {"1"},
		"vm_memory_mib": {"8192"},
	}, http.StatusOK)
	waitForGatewayVMResources(t, server, fullName, 1, 8192)

	assertGatewayStatus(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/start", url.Values{
		"vm_name": {fullName},
	}, http.StatusOK)
	waitForGatewayVMState(t, server, fullName, "running")

	assertGatewayStatus(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/restart", url.Values{
		"vm_name": {fullName},
	}, http.StatusOK)
	waitForGatewayVMState(t, server, fullName, "running")

	assertGatewayStatus(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/remove", url.Values{
		"vm_name": {fullName},
	}, http.StatusOK)
	waitForDashboardVMRemoval(t, server.client, server.baseURL, fullName)

	assertGatewayRedirect(t, server.client, http.MethodPost, server.baseURL+"/logout", nil, http.StatusSeeOther, "/login")
	assertGatewayRedirect(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/data", nil, http.StatusSeeOther, "/login")
}
