package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/virt"

	"github.com/gorilla/websocket"
)

func loginGatewayUser(t *testing.T, server gatewayTestServer, username, password string) {
	t.Helper()

	resp, body := gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/login", url.Values{
		"username": {username},
		"password": {password},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected login redirect 303, got %d with body %s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "/api/dashboard" {
		t.Fatalf("expected login redirect to /api/dashboard, got %q", loc)
	}
}

func newInsecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func expectGatewayWebsocketPreparationResult(t *testing.T, resp *http.Response, body, failureMessage string) {
	t.Helper()

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return
	case http.StatusInternalServerError:
		if !strings.Contains(body, failureMessage) {
			t.Fatalf("expected failure body to contain %q, got %q", failureMessage, body)
		}
	default:
		t.Fatalf("expected websocket preparation status 400 or 500, got %d with body %s", resp.StatusCode, body)
	}
}

func tryGatewayWebsocketDial(t *testing.T, server gatewayTestServer, path string) (*websocket.Conn, *http.Response, string, error) {
	t.Helper()

	baseURL, err := url.Parse(server.baseURL)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}

	header := http.Header{}
	for _, cookie := range server.client.Jar.Cookies(baseURL) {
		header.Add("Cookie", cookie.Name+"="+cookie.Value)
	}

	wsURL := "wss://" + baseURL.Host + path
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn, resp, err := dialer.Dial(wsURL, header)
	if err == nil {
		return conn, resp, "", nil
	}

	body := ""
	if resp != nil && resp.Body != nil {
		data, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read websocket dial failure body: %v", readErr)
		}
		body = string(data)
	}
	return nil, resp, body, err
}

func closeGatewayWebsocket(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	if err := conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	); err != nil {
		t.Fatalf("write websocket close frame: %v", err)
	}
	_ = conn.Close()
}

func TestGatewayConsoleAndVNCFlows(t *testing.T) {
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
	loginGatewayUser(t, server, "johndoe", "dogood")

	plainClient := newInsecureHTTPClient()
	shortName := "console" + strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10)
	fullName := "johndoe-" + shortName
	t.Cleanup(func() {
		_ = virt.RemoveVM(fullName, settings)
	})

	resp, body := gatewayRequest(t, plainClient, http.MethodGet, server.baseURL+"/api/dashboard/console/"+fullName+"/ws", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected console auth failure 401, got %d with body %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Login required.") {
		t.Fatalf("expected login required body, got %q", body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/testuser-devbox/ws", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected console ownership failure 403, got %d with body %s", resp.StatusCode, body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/%20%20%20/ws", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected console VM name failure 400, got %d with body %s", resp.StatusCode, body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/testuser-devbox/ws", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected VNC ownership failure 403, got %d with body %s", resp.StatusCode, body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/%20%20%20/ws", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected VNC VM name failure 400, got %d with body %s", resp.StatusCode, body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard", url.Values{
		"vm_name":       {shortName},
		"vm_vcpu":       {"2"},
		"vm_memory_mib": {"4096"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected create VM 200, got %d with body %s", resp.StatusCode, body)
	}

	waitForDashboardVMRow(t, server.client, server.baseURL, fullName, func(vm dashboardVM) bool {
		return vm.State == "running" && vm.TTYReady && vm.VNCReady
	})

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/"+fullName+"/ws", nil)
	expectGatewayWebsocketPreparationResult(t, resp, body, "Failed to open serial terminal.")

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/"+fullName+"/ws", nil)
	expectGatewayWebsocketPreparationResult(t, resp, body, "Failed to open VNC session.")

	if consoleWS, resp, body, err := tryGatewayWebsocketDial(t, server, "/api/dashboard/console/"+fullName+"/ws"); err == nil {
		closeGatewayWebsocket(t, consoleWS)
	} else if resp == nil {
		t.Fatalf("dial console websocket: %v", err)
	} else {
		expectGatewayWebsocketPreparationResult(t, resp, body, "Failed to open serial terminal.")
	}

	if vncWS, resp, body, err := tryGatewayWebsocketDial(t, server, "/api/dashboard/vnc/"+fullName+"/ws"); err == nil {
		closeGatewayWebsocket(t, vncWS)
	} else if resp == nil {
		t.Fatalf("dial VNC websocket: %v", err)
	} else {
		expectGatewayWebsocketPreparationResult(t, resp, body, "Failed to open VNC session.")
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

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/"+fullName+"/ws", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected console stopped conflict 409, got %d with body %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "VM must be running for terminal access.") {
		t.Fatalf("unexpected console stopped body: %q", body)
	}

	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/"+fullName+"/ws", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected VNC stopped conflict 409, got %d with body %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "VM must be running for VNC access.") {
		t.Fatalf("unexpected VNC stopped body: %q", body)
	}
}
