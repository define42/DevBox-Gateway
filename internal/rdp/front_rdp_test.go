package rdp

import (
	"net"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"

	"github.com/tomatome/grdp/protocol/x224"
)

func TestClientOfferedTLSWithStandardTLS(t *testing.T) {
	crq := &clientConnectionRequest{requestedProtocols: x224.PROTOCOL_SSL}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if !clientOfferedTLS(addr, crq) {
		t.Fatal("expected clientOfferedTLS=true for PROTOCOL_SSL request")
	}
}

func TestClientOfferedTLSWithHybridFallsBackToTLS(t *testing.T) {
	crq := &clientConnectionRequest{requestedProtocols: x224.PROTOCOL_HYBRID | x224.PROTOCOL_SSL}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if !clientOfferedTLS(addr, crq) {
		t.Fatal("expected clientOfferedTLS=true when both HYBRID and SSL are offered")
	}
}

func TestClientOfferedTLSWithRDPOnly(t *testing.T) {
	crq := &clientConnectionRequest{requestedProtocols: x224.PROTOCOL_RDP}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if clientOfferedTLS(addr, crq) {
		t.Fatal("expected clientOfferedTLS=false when only standard RDP is offered")
	}
}

func TestClientOfferedTLSMalformed(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if clientOfferedTLS(addr, nil) {
		t.Fatal("expected clientOfferedTLS=false for malformed CRQ")
	}
}

func TestWriteFrontConnectionConfirmSuccess(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Drain whatever the gateway writes.
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
	}()
	if !writeFrontConnectionConfirm(client) {
		t.Fatal("expected writeFrontConnectionConfirm to succeed against an open pipe")
	}
	_ = client.Close()
	<-done
	_ = server.Close()
}

func TestWriteFrontConnectionConfirmFailure(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	_ = client.Close()
	_ = server.Close()
	if writeFrontConnectionConfirm(client) {
		t.Fatal("expected writeFrontConnectionConfirm to fail when the connection is closed")
	}
}

func TestDialBackendTCPFailureReturnsError(t *testing.T) {
	t.Setenv(config.TIMEOUT, "200ms")
	settings := config.NewSettings(false)

	// Find a port nobody is listening on by binding then immediately closing.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	_, err = dialBackendTCP(addr, settings)
	if err == nil {
		t.Fatal("expected dial error for closed port")
	}
}

func TestDialBackendRDPReturnsFalseOnDialFailure(t *testing.T) {
	identity, _, _ := backendTLSFixture(t)
	t.Setenv(config.TIMEOUT, "200ms")
	settings := config.NewSettings(false)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	conn, ok := dialBackendRDP(addr, "test-backend", settings, testBackendIdentityLookup(identity))
	if ok {
		_ = conn.Close()
		t.Fatal("expected dialBackendRDP to fail when backend is unreachable")
	}
}

func TestDialBackendRDPReturnsFalseOnTLSNegotiationFailure(t *testing.T) {
	identity, _, _ := backendTLSFixture(t)
	InitLogging()
	t.Setenv(config.TIMEOUT, "2s")
	settings := config.NewSettings(false)

	// Accept a TCP connection but close it immediately so the CRQ write fails.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, ok := dialBackendRDP(listener.Addr().String(), "test-backend", settings, testBackendIdentityLookup(identity))
		if ok {
			_ = conn.Close()
			t.Fatal("expected dialBackendRDP to fail when backend closes immediately")
		}
		// Reset listener accept loop terminated; success path achieved.
		break
	}
	select {
	case <-done:
	case <-time.After(time.Until(deadline)):
	}
}

func TestAuthorizeRDPAccessRejectsNilSessionManager(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if _, ok := authorizeRDPAccess(addr, nil, "vm", ""); ok {
		t.Fatal("expected authorizeRDPAccess to return false when session manager is nil")
	}
}
