package main

import (
	"context"
	"crypto/tls"
	"devboxgateway/internal/virt"
	"devboxgateway/internal/vmname"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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
		Timeout: gatewayRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
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

func assertGatewayConsoleAndVNCAuthChecks(t *testing.T, server gatewayTestServer, plainClient *http.Client) {
	t.Helper()

	assertGatewayStatusContains(t, plainClient, http.MethodGet, server.baseURL+"/api/dashboard/console/johndoe-console/ws", nil, http.StatusUnauthorized, "Login required.")
	assertGatewayStatus(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/testuser-devbox/ws", nil, http.StatusForbidden)
	assertGatewayStatus(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/%20%20%20/ws", nil, http.StatusBadRequest)
	assertGatewayStatus(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/testuser-devbox/ws", nil, http.StatusForbidden)
	assertGatewayStatus(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/%20%20%20/ws", nil, http.StatusBadRequest)
}

func assertGatewayWebsocketDialOrPreparation(t *testing.T, server gatewayTestServer, path, failureMessage string) {
	t.Helper()

	if ws, resp, body, err := tryGatewayWebsocketDial(t, server, path); err == nil {
		closeGatewayWebsocket(t, ws)
		return
	} else if resp == nil {
		t.Fatalf("dial websocket %s: %v", path, err)
	} else {
		expectGatewayWebsocketPreparationResult(t, resp, body, failureMessage)
	}
}

func assertGatewayStoppedConsoleAndVNC(t *testing.T, server gatewayTestServer, fullName string) {
	t.Helper()

	assertGatewayStatusContains(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/"+fullName+"/ws", nil, http.StatusConflict, "VM must be running for terminal access.")
	assertGatewayStatusContains(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/"+fullName+"/ws", nil, http.StatusConflict, "VM must be running for VNC access.")
}

func TestGatewayConsoleAndVNCFlows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, cleanupLDAP := startGlauth(ctx, t, "")
	defer cleanupLDAP()

	settings := newGatewayIntegrationSettings(t, ldapURL)
	server := startGatewayTestServer(t, settings)
	loginGatewayUser(t, server, "johndoe", "dogood")

	plainClient := newInsecureHTTPClient()
	shortName := uniqueGatewayVMShortName("console")
	fullName := "johndoe" + vmname.Separator + shortName
	t.Cleanup(func() {
		_ = virt.RemoveVM(fullName, settings)
	})

	assertGatewayConsoleAndVNCAuthChecks(t, server, plainClient)
	fullName = createGatewayVM(t, server, shortName)
	waitForGatewayVMReady(t, server, fullName)

	resp, body := gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/console/"+fullName+"/ws", nil)
	expectGatewayWebsocketPreparationResult(t, resp, body, "Failed to open serial terminal.")
	resp, body = gatewayRequest(t, server.client, http.MethodGet, server.baseURL+"/api/dashboard/vnc/"+fullName+"/ws", nil)
	expectGatewayWebsocketPreparationResult(t, resp, body, "Failed to open VNC session.")

	assertGatewayWebsocketDialOrPreparation(t, server, "/api/dashboard/console/"+fullName+"/ws", "Failed to open serial terminal.")
	assertGatewayWebsocketDialOrPreparation(t, server, "/api/dashboard/vnc/"+fullName+"/ws", "Failed to open VNC session.")

	assertGatewayStatus(t, server.client, http.MethodPost, server.baseURL+"/api/dashboard/shutdown", url.Values{
		"vm_name": {fullName},
	}, http.StatusOK)
	waitForGatewayVMState(t, server, fullName, "shut off")
	assertGatewayStoppedConsoleAndVNC(t, server, fullName)
}
