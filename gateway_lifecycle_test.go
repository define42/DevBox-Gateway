package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
)

const gatewayTestTimeout = 60 * time.Second

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
		serveListener(ln, mux, frontTLS, settings)
		close(done)
	}()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}

	client := &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
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

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp, string(data)
}

func waitForDashboardVMRow(t *testing.T, client *http.Client, baseURL, vmName string, predicate func(dashboardVM) bool) dashboardVM {
	t.Helper()

	deadline := time.Now().Add(gatewayTestTimeout)
	for time.Now().Before(deadline) {
		resp, body := gatewayRequest(t, client, http.MethodGet, baseURL+"/api/dashboard/data", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected dashboard data 200, got %d with body %s", resp.StatusCode, body)
		}

		var payload dashboardDataResponse
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
	return dashboardVM{}
}

func waitForDashboardVMRemoval(t *testing.T, client *http.Client, baseURL, vmName string) {
	t.Helper()

	deadline := time.Now().Add(gatewayTestTimeout)
	for time.Now().Before(deadline) {
		resp, body := gatewayRequest(t, client, http.MethodGet, baseURL+"/api/dashboard/data", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected dashboard data 200, got %d with body %s", resp.StatusCode, body)
		}

		var payload dashboardDataResponse
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

func TestGatewayHTTPSLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanupLDAP := startGlauth(ctx, t, "")
	defer cleanupLDAP()

	t.Setenv(config.LDAP_URL, ldapURL)
	t.Setenv(config.LDAP_SKIP_TLS_VERIFY, "true")
	t.Setenv(config.LDAP_STARTTLS, "false")
	t.Setenv(config.LDAP_USER_DOMAIN, "@example.com")
	t.Setenv(config.FRONT_DOMAIN, "gateway.test")
	t.Setenv(config.VIRT_SERIAL_SOCKET_DIR, t.TempDir())
	t.Setenv(config.VIRT_VNC_SOCKET_DIR, t.TempDir())

	settings := config.NewSettingType(false)
	server := startGatewayTestServer(t, settings)

	resp, _ := gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected health 200, got %d", resp.StatusCode)
	}

	resp, _ = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected root redirect 303, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/login" {
		t.Fatalf("expected root redirect to /login, got %q", loc)
	}

	resp, body := gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/static/dashboard.html", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected dashboard html 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Available DevBoxes") {
		t.Fatalf("expected dashboard html content, got %q", body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/login", url.Values{
		"username": {"johndoe"},
		"password": {"dogood"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected login redirect 303, got %d with body %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "/api/dashboard" {
		t.Fatalf("expected login redirect to /api/dashboard, got %q", loc)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected dashboard 200, got %d with body %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "/static/dashboard.js") {
		t.Fatalf("expected dashboard page body, got %q", body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/data", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected dashboard data 200, got %d with body %s", resp.StatusCode, body)
	}

	shortName := "api" + strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	fullName := "johndoe-" + shortName
	t.Cleanup(func() {
		_ = virt.RemoveVM(fullName, settings)
	})

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard", url.Values{
		"vm_name":       {shortName},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"4096"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected create VM 200, got %d with body %s", resp.StatusCode, body)
	}

	row := waitForDashboardVMRow(t, server.client, server.baseURL, fullName, func(vm dashboardVM) bool {
		return vm.State == "running"
	})
	if row.DisplayName != fullName+".gateway.test" {
		t.Fatalf("expected display name %q, got %q", fullName+".gateway.test", row.DisplayName)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/shutdown", url.Values{
		"vm_name": {fullName},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected shutdown 200, got %d with body %s", resp.StatusCode, body)
	}
	waitForDashboardVMRow(t, server.client, server.baseURL, fullName, func(vm dashboardVM) bool {
		return vm.State == "shut off"
	})

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/resources", url.Values{
		"vm_name":       {fullName},
		"vm_vcpu":       {"1"},
		"vm_memory_mib": {"8192"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected update resources 200, got %d with body %s", resp.StatusCode, body)
	}
	waitForDashboardVMRow(t, server.client, server.baseURL, fullName, func(vm dashboardVM) bool {
		return vm.State == "shut off" && vm.VCPU == 1 && vm.MemoryMiB == 8192
	})

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/start", url.Values{
		"vm_name": {fullName},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected start 200, got %d with body %s", resp.StatusCode, body)
	}
	waitForDashboardVMRow(t, server.client, server.baseURL, fullName, func(vm dashboardVM) bool {
		return vm.State == "running"
	})

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/restart", url.Values{
		"vm_name": {fullName},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected restart 200, got %d with body %s", resp.StatusCode, body)
	}
	waitForDashboardVMRow(t, server.client, server.baseURL, fullName, func(vm dashboardVM) bool {
		return vm.State == "running"
	})

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/remove", url.Values{
		"vm_name": {fullName},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected remove 200, got %d with body %s", resp.StatusCode, body)
	}
	waitForDashboardVMRemoval(t, server.client, server.baseURL, fullName)

	resp, _ = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/logout", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected logout redirect 303, got %d", resp.StatusCode)
	}

	resp, _ = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/data", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected dashboard data redirect after logout, got %d", resp.StatusCode)
	}
}
