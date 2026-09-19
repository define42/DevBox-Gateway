package rdp

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/backendidentity"
	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/tomatome/grdp/protocol/x224"
)

func backendTLSFixture(t *testing.T) (backendidentity.Credentials, tls.Certificate, *tls.Config) {
	t.Helper()
	identity, err := backendidentity.Generate("test-backend")
	if err != nil {
		t.Fatalf("generate backend identity: %v", err)
	}
	certificate, err := tls.X509KeyPair([]byte(identity.CertificatePEM), []byte(identity.PrivateKeyPEM))
	if err != nil {
		t.Fatalf("parse backend key pair: %v", err)
	}
	configuration, err := backendidentity.TLSConfig(identity.CertificatePEM, identity.ServerName)
	if err != nil {
		t.Fatalf("create backend TLS config: %v", err)
	}
	return identity, certificate, configuration
}

func testBackendTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	_, _, configuration := backendTLSFixture(t)
	return configuration
}

func testBackendIdentityLookup(identity backendidentity.Credentials) backendIdentityLookup {
	return func(string) (string, string, error) {
		return identity.CertificatePEM, identity.ServerName, nil
	}
}

func TestBackendTLSConfigUsesProvisionedIdentity(t *testing.T) {
	identity, _, _ := backendTLSFixture(t)
	lookup := func(name string) (string, string, error) {
		if name != "authorized-vm" {
			t.Errorf("identity lookup name = %q, want authorized-vm", name)
		}
		return identity.CertificatePEM, identity.ServerName, nil
	}
	cfg, err := backendTLSConfig("authorized-vm", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InsecureSkipVerify || cfg.RootCAs == nil || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatal("backend must use normal TLS verification and its own trusted certificate")
	}
	if cfg.ServerName != identity.ServerName {
		t.Fatalf("backend ServerName = %q, want provisioned identity %q", cfg.ServerName, identity.ServerName)
	}
	if cfg.ClientSessionCache != nil {
		t.Fatal("backend TLS must reverify identity on every connection")
	}
}

func TestBackendTLSConfigRejectsMissingIdentity(t *testing.T) {
	tests := []struct {
		name   string
		lookup func(string) (string, string, error)
	}{
		{"missing lookup", nil},
		{"lookup failure", func(string) (string, string, error) { return "", "", errors.New("missing metadata") }},
		{"empty metadata", func(string) (string, string, error) { return "", "", nil }},
		{"malformed certificate", func(string) (string, string, error) { return "invalid", "vm.test", nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if cfg, err := backendTLSConfig("authorized-vm", tt.lookup); err == nil || cfg != nil {
				t.Fatal("expected invalid identity to fail closed")
			}
		})
	}
}

func TestDialBackendRDPRejectsMissingIdentityBeforeConnecting(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	lookup := func(string) (string, string, error) {
		return "", "", errors.New("missing provisioned identity")
	}
	connection, ok := dialBackendRDP(listener.Addr().String(), "unprovisioned-vm", config.NewSettings(false), lookup)
	if ok || connection != nil {
		t.Fatal("unprovisioned VM must be rejected")
	}
	if err := listener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err == nil {
		_ = accepted.Close()
		t.Fatal("gateway contacted backend before verifying its provisioned identity")
	}
	var networkError net.Error
	if !errors.As(err, &networkError) || !networkError.Timeout() {
		t.Fatalf("accept failed unexpectedly: %v", err)
	}
}

func TestHandleRejectsImpostorBackendBeforeForwardingCredentials(t *testing.T) {
	InitLogging()
	name := covxUniqueName("impostor")
	const backendHost = "127.0.0.76"
	stubVMIPs(t, map[string]string{name: backendHost})
	covxDefineOwnedDomain(t, name)
	trustedIdentity, _, _ := backendTLSFixture(t)
	_, impostorCertificate, _ := backendTLSFixture(t)
	received := startImpostorBackend(t, backendHost, impostorCertificate)
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	manager := session.New()
	issueUserSession(t, manager, "alice", "192.0.2.187:5000", name)
	client, done := startHandleTestConnection(t, frontTLS, manager, settings, "192.0.2.187", trustedIdentity)
	tlsClient := performFrontHandshake(t, client, name+".example.test")
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		_, _ = tlsClient.Write([]byte("sensitive RDP credentials"))
	}()
	_, _ = io.Copy(io.Discard, tlsClient)
	_ = client.Close()
	waitDone(t, done)
	waitDone(t, writeDone)
	select {
	case data := <-received:
		if len(data) != 0 {
			t.Fatalf("impostor received client credentials: %q", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("impostor backend did not finish")
	}
}

func startImpostorBackend(t *testing.T, host string, certificate tls.Certificate) <-chan []byte {
	t.Helper()
	received := make(chan []byte, 1)
	stop := startBackendServer(t, host, func(raw net.Conn) {
		defer close(received)
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		if !expectTLSOnlyBackendCRQ(t, raw) {
			return
		}
		if err := writeTPKT(raw, buildServerCCFSelectTLS()); err != nil {
			t.Errorf("send backend TLS negotiation: %v", err)
			return
		}
		connection := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
		if err := connection.Handshake(); err != nil {
			received <- nil
			return
		}
		t.Error("gateway authenticated an impostor's certificate")
		data := make([]byte, 128)
		n, _ := connection.Read(data)
		received <- data[:n]
	})
	t.Cleanup(stop)
	return received
}

func TestNegotiateBackendTLSRejectsMissingConfiguration(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	if _, err := negotiateBackendTLS(client, "backend:3389", nil); err == nil {
		t.Fatal("missing TLS configuration must fail before contacting the backend")
	}
}

// TestNegotiateBackendTLSWriteFailure asserts that the function returns an error
// when the underlying connection cannot accept the CRQ write.
func TestNegotiateBackendTLSWriteFailure(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	// Closing the server side ensures the write on the client side will fail.
	_ = server.Close()
	_ = client.Close()

	if _, err := negotiateBackendTLS(client, "127.0.0.1:3389", testBackendTLSConfig(t)); err == nil {
		t.Fatal("expected error when backend connection is closed")
	}
}

// TestNegotiateBackendTLSReadFailure asserts a read error after a successful
// CRQ write is propagated back to the caller.
func TestNegotiateBackendTLSReadFailure(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Drain the CRQ then close so the read of the CCF reply fails.
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
		_ = server.Close()
	}()

	_, err := negotiateBackendTLS(client, "127.0.0.1:3389", testBackendTLSConfig(t))
	<-done
	if err == nil {
		t.Fatal("expected error when CCF cannot be read")
	}
	_ = client.Close()
}

// TestNegotiateBackendTLSBackendDidNotSelectTLS verifies the function rejects
// backends that respond with a non-TLS RDP_NEG_RSP selection.
func TestNegotiateBackendTLSBackendDidNotSelectTLS(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
		// Send back a CCF that selects standard RDP (no TLS).
		ccf := buildServerCCFSelectProtocol(x224.PROTOCOL_RDP)
		total := len(ccf) + 4
		tpkt := make([]byte, total)
		tpkt[0] = 0x03
		tpkt[1] = 0x00
		tpkt[2] = byte(total >> 8)
		tpkt[3] = byte(total)
		copy(tpkt[4:], ccf)
		_, _ = server.Write(tpkt)
		_ = server.Close()
	}()

	_, err := negotiateBackendTLS(client, "127.0.0.1:3389", testBackendTLSConfig(t))
	<-done
	if err == nil {
		t.Fatal("expected error when backend selects non-TLS protocol")
	}
	_ = client.Close()
}

// buildServerCCFSelectProtocol mirrors buildServerCCFSelectTLS but allows the
// test to control which protocol the synthetic backend advertises.
func buildServerCCFSelectProtocol(protocol uint32) []byte {
	ccf := buildServerCCFSelectTLS()
	// The selected protocol lives in the last 4 bytes (little-endian uint32).
	if len(ccf) < 4 {
		return ccf
	}
	ccf[len(ccf)-4] = byte(protocol)
	ccf[len(ccf)-3] = byte(protocol >> 8)
	ccf[len(ccf)-2] = byte(protocol >> 16)
	ccf[len(ccf)-1] = byte(protocol >> 24)
	return ccf
}
