package rdp

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/session"
	"github.com/tomatome/grdp/protocol/x224"
)

// buildTokenClientCRQ places loadbalanceinfo in the X.224 routingToken field,
// before the optional RDP negotiation request, as desktop clients send it.
func buildTokenClientCRQ(token string) []byte {
	crq := buildClientCRQ(x224.PROTOCOL_SSL)
	payload := append([]byte(nil), crq[:7]...)
	payload = append(payload, token...)
	payload = append(payload, '\r', '\n')
	payload = append(payload, crq[7:]...)
	payload[0] = byte(len(payload) - 1)
	return payload
}

func performTokenFrontHandshake(t *testing.T, client net.Conn, serverName, token string) *tls.Conn {
	t.Helper()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	request := buildClientCRQ(x224.PROTOCOL_SSL)
	if token != "" {
		request = buildTokenClientCRQ(token)
	}
	if err := writeTPKT(client, request); err != nil {
		t.Fatalf("write client CRQ: %v", err)
	}
	if _, err := readTPKT(client); err != nil {
		t.Fatalf("read front CCF: %v", err)
	}

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true, // Test-only self-signed frontend certificate.
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("front TLS handshake: %v", err)
	}
	return tlsClient
}

func assertTokenProxyEcho(t *testing.T, client *tls.Conn) {
	t.Helper()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write proxied client bytes: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read proxied backend bytes: %v", err)
	}
	if string(reply) != "ping" {
		t.Fatalf("backend echo = %q, want ping", reply)
	}
}

func TestHandleRoutingTokenSuccessfulProxy(t *testing.T) {
	InitLogging()

	const (
		vmName      = "vm-token-proxy"
		backendHost = "127.0.0.61"
	)
	stubVMIPs(t, map[string]string{vmName: backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{vmName: "alice"})
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	identity, certificate, _ := backendTLSFixture(t)

	tests := []struct {
		name       string
		serverName string
	}{
		{name: "shared gateway hostname", serverName: "example.test"},
		{name: "no SNI", serverName: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopBackend := startTLSServingBackend(t, backendHost, certificate, func(tlsConn *tls.Conn) {
				payload := make([]byte, 4)
				if _, err := io.ReadFull(tlsConn, payload); err != nil {
					t.Errorf("backend read proxied bytes: %v", err)
					return
				}
				if _, err := tlsConn.Write(payload); err != nil {
					t.Errorf("backend echo proxied bytes: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, tlsConn)
			})
			defer stopBackend()

			sessionManager := session.New()
			token := issueUserSession(t, sessionManager, "alice", "192.0.2.160:5000", vmName)[vmName]
			client, done := startHandleTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.160", identity)
			tlsClient := performTokenFrontHandshake(t, client, tt.serverName, token)
			defer func() { _ = tlsClient.Close() }()
			assertTokenProxyEcho(t, tlsClient)
			drainRDPTestConnections(t, sessionManager, 1)
			waitDone(t, done)
			if sessionManager.ConsumeRDPConnectGrant(token, "alice", "192.0.2.160", vmName) {
				t.Fatal("successful token connection did not consume its Connect grant")
			}
		})
	}
}

type routingTokenDenial struct {
	name         string
	serverName   string
	clientIP     string
	grant        bool
	consumeGrant bool
	logout       bool
	missingToken bool
	unknownToken bool
}

func newRoutingTokenTestSession(t *testing.T, vmName string, tt routingTokenDenial) (*session.Manager, string, string) {
	t.Helper()

	manager := session.New()
	var grants []string
	if tt.grant {
		grants = []string{vmName}
	}
	token := issueUserSession(t, manager, "alice", "192.0.2.161:5000", grants...)[vmName]
	if tt.consumeGrant && !manager.ConsumeRDPConnectGrant(token, "alice", "192.0.2.161", vmName) {
		t.Fatal("consume initial Connect token")
	}
	if tt.logout {
		if err := manager.DestroyAllSessionsForUser("alice"); err != nil {
			t.Fatalf("revoke issuing session: %v", err)
		}
	}
	requestToken := token
	if !tt.grant || tt.unknownToken {
		requestToken = strings.Repeat("0", 32)
	}
	if tt.missingToken {
		requestToken = ""
	}
	return manager, token, requestToken
}

func TestHandleRoutingTokenRejectsBeforeBackendDial(t *testing.T) {
	InitLogging()

	const (
		vmName      = "vm-token-reject"
		backendHost = "127.0.0.62"
	)
	stubVMIPs(t, map[string]string{vmName: backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{vmName: "alice"})
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	identity, _, _ := backendTLSFixture(t)

	tests := []routingTokenDenial{
		{name: "no Connect grant", serverName: "example.test", clientIP: "192.0.2.161"},
		{name: "wrong client IP", serverName: "example.test", clientIP: "192.0.2.162", grant: true},
		{name: "consumed token", serverName: "example.test", clientIP: "192.0.2.161", grant: true, consumeGrant: true},
		{name: "issuing session logged out", serverName: "example.test", clientIP: "192.0.2.161", grant: true, logout: true},
		{name: "unknown token", serverName: "example.test", clientIP: "192.0.2.161", grant: true, unknownToken: true},
		{name: "missing token", serverName: "example.test", clientIP: "192.0.2.161", grant: true, missingToken: true},
		{name: "legacy hostname without token", serverName: strings.Repeat("1", 32) + ".example.test", clientIP: "192.0.2.161", grant: true, missingToken: true},
		{name: "legacy hostname with token", serverName: strings.Repeat("1", 32) + ".example.test", clientIP: "192.0.2.161", grant: true},
		{name: "foreign SNI", serverName: "other.test", clientIP: "192.0.2.161", grant: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stopTracker := startBackendDialTracker(t, backendHost)
			defer func() {
				if stopTracker() {
					t.Error("rejected token connection reached the backend")
				}
			}()
			manager, token, requestToken := newRoutingTokenTestSession(t, vmName, tt)
			client, done := startHandleTestConnection(t, frontTLS, manager, settings, tt.clientIP, identity)
			tlsClient := performTokenFrontHandshake(t, client, tt.serverName, requestToken)
			defer func() { _ = tlsClient.Close() }()
			var reply [1]byte
			if n, err := tlsClient.Read(reply[:]); n != 0 || err == nil {
				t.Fatalf("rejected token connection returned %d bytes and error %v", n, err)
			}
			waitDone(t, done)
			if tt.grant && !tt.consumeGrant && !tt.logout && !manager.ConsumeRDPConnectGrant(token, "alice", "192.0.2.161", vmName) {
				t.Error("rejected token connection consumed the valid client's Connect token")
			}
		})
	}
}

func TestHandleConsumedTokenCannotUseNewConnectGrant(t *testing.T) {
	InitLogging()
	const vmName = "vm-token-replay"
	const backendHost = "127.0.0.63"
	stubVMIPs(t, map[string]string{vmName: backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{vmName: "alice"})
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	identity, _, _ := backendTLSFixture(t)
	manager := session.New()
	oldToken := issueUserSession(t, manager, "alice", "192.0.2.163:5000", vmName)[vmName]
	if !manager.ConsumeRDPConnectGrant(oldToken, "alice", "192.0.2.163", vmName) {
		t.Fatal("consume original token")
	}
	newToken := issueUserSession(t, manager, "alice", "192.0.2.163:5001", vmName)[vmName]
	if oldToken == newToken {
		t.Fatal("fresh Connect action returned the old token")
	}
	stopTracker := startBackendDialTracker(t, backendHost)
	defer func() {
		if stopTracker() {
			t.Error("replayed token reached the backend using a new Connect grant")
		}
	}()
	client, done := startHandleTestConnection(t, frontTLS, manager, settings, "192.0.2.163", identity)
	tlsClient := performTokenFrontHandshake(t, client, "example.test", oldToken)
	defer func() { _ = tlsClient.Close() }()
	var reply [1]byte
	if n, err := tlsClient.Read(reply[:]); n != 0 || err == nil {
		t.Fatalf("replayed token returned %d bytes and error %v", n, err)
	}
	waitDone(t, done)
	if !manager.ConsumeRDPConnectGrant(newToken, "alice", "192.0.2.163", vmName) {
		t.Error("replayed token consumed the fresh Connect grant")
	}
}
