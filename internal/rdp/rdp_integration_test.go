package rdp

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/types"
	"rdptlsgateway/internal/virt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomatome/grdp/protocol/x224"
	"libvirt.org/go/libvirt"
)

type addrOverrideConn struct {
	net.Conn

	remote net.Addr
	local  net.Addr
}

func (c *addrOverrideConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *addrOverrideConn) LocalAddr() net.Addr {
	return c.local
}

func newServerConnWithRemoteIP(conn net.Conn, remoteIP string) net.Conn {
	return &addrOverrideConn{
		Conn:   conn,
		remote: &net.TCPAddr{IP: net.ParseIP(remoteIP), Port: 42424},
		local:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	}
}

func issueUserSession(t *testing.T, sessionManager *session.Manager, username, remoteAddr string) {
	t.Helper()

	user, err := types.NewUser(username, "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr

	handler := sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := sessionManager.CreateSession(r.Context(), user, r.RemoteAddr); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rec, req)
}

const (
	testDomainOwnerMetadataNamespace = "urn:rdptlsgateway:domain:owner"
	testDomainOwnerMetadataPrefix    = "rdptlsgateway"
)

type testDomainOwnerMetadata struct {
	XMLName xml.Name `xml:"owner"`
	Value   string   `xml:",chardata"`
}

func defineOwnedRDPTestDomains(t *testing.T, owners map[string]string) {
	t.Helper()

	for name := range owners {
		cleanupOwnedRDPTestDomain(t, name)
	}

	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	for name, owner := range owners {
		dom, err := conn.DomainDefineXML(minimalRDPTestDomainXML(name))
		if err != nil {
			t.Fatalf("define test domain %q: %v", name, err)
		}

		payload, err := xml.Marshal(testDomainOwnerMetadata{Value: owner})
		if err != nil {
			_ = dom.Free()
			t.Fatalf("marshal owner metadata for %q: %v", name, err)
		}

		if err := dom.SetMetadata(
			libvirt.DOMAIN_METADATA_ELEMENT,
			string(payload),
			testDomainOwnerMetadataPrefix,
			testDomainOwnerMetadataNamespace,
			libvirt.DOMAIN_AFFECT_CONFIG,
		); err != nil {
			_ = dom.Free()
			t.Fatalf("set owner metadata for %q: %v", name, err)
		}

		if err := dom.Free(); err != nil {
			t.Fatalf("free test domain %q: %v", name, err)
		}
	}

	t.Cleanup(func() {
		for name := range owners {
			cleanupOwnedRDPTestDomain(t, name)
		}
	})
}

func cleanupOwnedRDPTestDomain(t *testing.T, name string) {
	t.Helper()

	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt for cleanup: %v", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
			return
		}
		t.Fatalf("lookup test domain %q for cleanup: %v", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err == nil && active {
		_ = dom.Destroy()
	}
	if err := dom.Undefine(); err != nil && !errors.Is(err, libvirt.ERR_NO_DOMAIN) {
		t.Fatalf("undefine test domain %q: %v", name, err)
	}
}

func minimalRDPTestDomainXML(name string) string {
	return fmt.Sprintf(`<domain type='kvm'>
  <name>%s</name>
  <memory unit='MiB'>64</memory>
  <currentMemory unit='MiB'>64</currentMemory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
  </os>
</domain>`, name)
}

func stubVMIPs(t *testing.T, entries map[string]string) {
	t.Helper()

	originalLookup := vmIPAddressLookup
	vmIPAddressLookup = func(name string) (string, error) {
		ip, ok := entries[name]
		if !ok {
			return "", fmt.Errorf("vm %s not found", name)
		}
		return ip, nil
	}
	t.Cleanup(func() {
		vmIPAddressLookup = originalLookup
	})
}

func startBackendDialTracker(t *testing.T, host string) func() bool {
	t.Helper()

	ln, err := net.Listen("tcp", net.JoinHostPort(host, "3389"))
	if err != nil {
		t.Fatalf("listen backend tracker: %v", err)
	}

	var accepted atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted.Store(true)
		_ = conn.Close()
	}()

	return func() bool {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("backend dial tracker did not stop in time")
		}
		return accepted.Load()
	}
}

func buildServerCCFForProtocol(protocol uint32) []byte {
	neg := x224.Negotiation{
		Type:   x224.TYPE_RDP_NEG_RSP,
		Flag:   0,
		Length: 8,
		Result: protocol,
	}

	li := uint8(6 + neg.Length)
	payload := make([]byte, 0, int(li)+1)
	payload = append(payload,
		li,
		byte(x224.TPDU_CONNECTION_CONFIRM),
		0x00, 0x00,
		0x12, 0x34,
		0x00,
		byte(neg.Type),
		neg.Flag,
	)

	lengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBytes, neg.Length)
	payload = append(payload, lengthBytes...)

	resultBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(resultBytes, neg.Result)
	payload = append(payload, resultBytes...)

	return payload
}

func startBackendServer(t *testing.T, host string, handler func(net.Conn)) func() {
	t.Helper()

	ln, err := net.Listen("tcp", net.JoinHostPort(host, "3389"))
	if err != nil {
		t.Fatalf("listen backend server: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		handler(conn)
	}()

	return func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("backend server did not stop in time")
		}
	}
}

func newFrontTLSManager(t *testing.T, frontDomain string) (*cert.TLSManager, *config.SettingsType) {
	t.Helper()

	t.Setenv(config.ACME_ENABLE, "false")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.FRONT_DOMAIN, frontDomain)

	settings := config.NewSettingType(false)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}
	t.Cleanup(func() {
		if err := frontTLS.Close(); err != nil {
			t.Fatalf("close TLS manager: %v", err)
		}
	})
	return frontTLS, settings
}

func backendTLSCert(t *testing.T) tls.Certificate {
	t.Helper()

	settings := config.NewSettingType(false)
	certificate, err := cert.LoadOrGenerateCert(settings)
	if err != nil {
		t.Fatalf("load backend certificate: %v", err)
	}
	return certificate
}

func performFrontHandshake(t *testing.T, client net.Conn, serverName string) *tls.Conn {
	t.Helper()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	if err := writeTPKT(client, buildClientCRQ(x224.PROTOCOL_SSL)); err != nil {
		t.Fatalf("write client CRQ: %v", err)
	}
	if _, err := readTPKT(client); err != nil {
		t.Fatalf("read front CCF: %v", err)
	}

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("front TLS handshake: %v", err)
	}
	return tlsClient
}

func startTLSServingBackend(t *testing.T, host string, handler func(*tls.Conn)) func() {
	t.Helper()

	return startBackendServer(t, host, func(raw net.Conn) {
		if !expectTLSOnlyBackendCRQ(t, raw) {
			return
		}
		if err := writeTPKT(raw, buildServerCCFForProtocol(x224.PROTOCOL_SSL)); err != nil {
			t.Errorf("backend write CCF: %v", err)
			return
		}

		tlsConn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{backendTLSCert(t)},
			MinVersion:   tls.VersionTLS10,
		})
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("backend TLS handshake: %v", err)
			return
		}
		defer func() { _ = tlsConn.Close() }()

		handler(tlsConn)
	})
}

func expectTLSOnlyBackendCRQ(t *testing.T, raw net.Conn) bool {
	t.Helper()

	req, err := readTPKT(raw)
	if err != nil {
		t.Errorf("backend read CRQ: %v", err)
		return false
	}
	if proto, ok := findClientRequestedProtocols(req); !ok || proto != x224.PROTOCOL_SSL {
		t.Errorf("backend expected TLS-only CRQ, got ok=%v proto=0x%08x", ok, proto)
		return false
	}
	return true
}

func startHandleRDPTestConnection(t *testing.T, frontTLS *cert.TLSManager, sessionManager *session.Manager, settings *config.SettingsType, remoteIP string) (net.Conn, <-chan struct{}) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	server = newServerConnWithRemoteIP(server, remoteIP)

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, sessionManager, settings)
		close(done)
	}()

	return client, done
}

func TestHandleRDPSuccessfulProxy(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.42"
	stubVMIPs(t, map[string]string{"vm1": backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{"vm1": "alice"})

	stopBackend := startTLSServingBackend(t, backendHost, func(tlsConn *tls.Conn) {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(tlsConn, buf); err != nil {
			t.Errorf("backend read proxied bytes: %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("expected proxied payload %q, got %q", "ping", string(buf))
			return
		}
		if _, err := tlsConn.Write([]byte("pong")); err != nil {
			t.Errorf("backend write proxied bytes: %v", err)
		}
	})
	defer stopBackend()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.100:5000")

	client, done := startHandleRDPTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.100")
	tlsClient := performFrontHandshake(t, client, "vm1.example.test")
	defer func() { _ = tlsClient.Close() }()

	if _, err := tlsClient.Write([]byte("ping")); err != nil {
		t.Fatalf("write proxied client bytes: %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(tlsClient, reply); err != nil {
		t.Fatalf("read proxied backend bytes: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("expected backend reply %q, got %q", "pong", string(reply))
	}

	_ = tlsClient.Close()
	waitDone(t, done)
}

func TestHandleRDPRejectsMissingSubdomain(t *testing.T) {
	InitLogging()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, nil, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}

func TestHandleRDPRejectsMissingRoute(t *testing.T) {
	InitLogging()

	stubVMIPs(t, map[string]string{})
	defineOwnedRDPTestDomains(t, map[string]string{"missing": "alice"})
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.101:5000")
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	server = newServerConnWithRemoteIP(server, "192.0.2.101")

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, sessionManager, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "missing.example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}

func TestHandleRDPBackendDialFailure(t *testing.T) {
	InitLogging()

	stubVMIPs(t, map[string]string{"vmdial": "127.0.0.43"})
	defineOwnedRDPTestDomains(t, map[string]string{"vmdial": "alice"})
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.102:5000")
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	server = newServerConnWithRemoteIP(server, "192.0.2.102")

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, sessionManager, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vmdial.example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}

func TestHandleRDPRejectsBackendWithoutTLS(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.44"
	stubVMIPs(t, map[string]string{"vmbad": backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{"vmbad": "alice"})

	stopBackend := startBackendServer(t, backendHost, func(raw net.Conn) {
		if _, err := readTPKT(raw); err != nil {
			t.Errorf("backend read CRQ: %v", err)
			return
		}
		if err := writeTPKT(raw, buildServerCCFForProtocol(x224.PROTOCOL_RDP)); err != nil {
			t.Errorf("backend write non-TLS CCF: %v", err)
		}
	})
	defer stopBackend()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.103:5000")
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	server = newServerConnWithRemoteIP(server, "192.0.2.103")

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, sessionManager, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vmbad.example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}

func TestHandleRDPRejectsWithoutOwnerSessionBeforeDial(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.45"
	stubVMIPs(t, map[string]string{"vmnosession": backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{"vmnosession": "alice"})

	stopTracker := startBackendDialTracker(t, backendHost)
	defer func() {
		if accepted := stopTracker(); accepted {
			t.Fatal("expected unauthorized RDP connection to be rejected before backend dial")
		}
	}()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	server = newServerConnWithRemoteIP(server, "192.0.2.104")

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, sessionManager, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vmnosession.example.test")
	defer func() { _ = tlsClient.Close() }()
	_ = tlsClient.Close()

	waitDone(t, done)
}

func TestHandleRDPRejectsDifferentOwnerSessionIPBeforeDial(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.46"
	stubVMIPs(t, map[string]string{"vmdiffip": backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{"vmdiffip": "alice"})

	stopTracker := startBackendDialTracker(t, backendHost)
	defer func() {
		if accepted := stopTracker(); accepted {
			t.Fatal("expected mismatched session IP to be rejected before backend dial")
		}
	}()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.200:5000")

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	server = newServerConnWithRemoteIP(server, "192.0.2.105")

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, sessionManager, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vmdiffip.example.test")
	defer func() { _ = tlsClient.Close() }()
	_ = tlsClient.Close()

	waitDone(t, done)
}

func TestHandleRDPRejectsOtherUserSessionFromSameIPBeforeDial(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.47"
	stubVMIPs(t, map[string]string{"vmotheruser": backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{"vmotheruser": "alice"})

	stopTracker := startBackendDialTracker(t, backendHost)
	defer func() {
		if accepted := stopTracker(); accepted {
			t.Fatal("expected different user session to be rejected before backend dial")
		}
	}()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "bob", "192.0.2.106:5000")

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	server = newServerConnWithRemoteIP(server, "192.0.2.106")

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, sessionManager, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vmotheruser.example.test")
	defer func() { _ = tlsClient.Close() }()
	_ = tlsClient.Close()

	waitDone(t, done)
}

func TestHandleRDPAllowsAnyMatchingOwnerSessionIP(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.48"
	stubVMIPs(t, map[string]string{"vmmulti": backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{"vmmulti": "alice"})

	stopBackend := startTLSServingBackend(t, backendHost, func(tlsConn *tls.Conn) {
		if _, err := tlsConn.Write([]byte("ok")); err != nil {
			t.Errorf("backend write proxied bytes: %v", err)
		}
	})
	defer stopBackend()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.201:5000")
	issueUserSession(t, sessionManager, "alice", "192.0.2.107:5001")

	client, done := startHandleRDPTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.107")
	tlsClient := performFrontHandshake(t, client, "vmmulti.example.test")
	defer func() { _ = tlsClient.Close() }()

	reply := make([]byte, 2)
	if _, err := io.ReadFull(tlsClient, reply); err != nil {
		t.Fatalf("read proxied backend bytes: %v", err)
	}
	if string(reply) != "ok" {
		t.Fatalf("expected backend reply %q, got %q", "ok", string(reply))
	}
	_ = tlsClient.Close()

	waitDone(t, done)
}
