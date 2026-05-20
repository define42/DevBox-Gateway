package rdp

import (
	"net"
	"rdptlsgateway/internal/config"
	"strings"
	"testing"
	"time"

	"github.com/tomatome/grdp/protocol/x224"
)

func TestClientOfferedTLSWithStandardTLS(t *testing.T) {
	crq := wrapTPKT(buildClientCRQ(x224.PROTOCOL_SSL))
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if !clientOfferedTLS(addr, crq) {
		t.Fatal("expected clientOfferedTLS=true for PROTOCOL_SSL request")
	}
}

func TestClientOfferedTLSWithHybridFallsBackToTLS(t *testing.T) {
	crq := wrapTPKT(buildClientCRQ(x224.PROTOCOL_HYBRID | x224.PROTOCOL_SSL))
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if !clientOfferedTLS(addr, crq) {
		t.Fatal("expected clientOfferedTLS=true when both HYBRID and SSL are offered")
	}
}

func TestClientOfferedTLSWithRDPOnly(t *testing.T) {
	crq := wrapTPKT(buildClientCRQ(x224.PROTOCOL_RDP))
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if clientOfferedTLS(addr, crq) {
		t.Fatal("expected clientOfferedTLS=false when only standard RDP is offered")
	}
}

func TestClientOfferedTLSMalformed(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if clientOfferedTLS(addr, []byte{0x03, 0x00, 0x00, 0x04}) {
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
	settings := config.NewSettingType(false)

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
	t.Setenv(config.TIMEOUT, "200ms")
	settings := config.NewSettingType(false)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	conn, ok := dialBackendRDP(addr, "", settings)
	if ok {
		_ = conn.Close()
		t.Fatal("expected dialBackendRDP to fail when backend is unreachable")
	}
}

func TestDialBackendRDPReturnsFalseOnTLSNegotiationFailure(t *testing.T) {
	InitLogging()
	t.Setenv(config.TIMEOUT, "2s")
	settings := config.NewSettingType(false)

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
		conn, ok := dialBackendRDP(listener.Addr().String(), "", settings)
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

func TestValidateFrontSNIRejectsMismatch(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "example.test")
	settings := config.NewSettingType(false)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	_, ok := validateFrontSNI(strings.ToLower("vm.other.example"), addr, settings)
	if ok {
		t.Fatal("expected SNI not matching the front domain to be rejected")
	}
}

func TestValidateFrontSNIRequiresSubdomain(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "example.test")
	settings := config.NewSettingType(false)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	_, ok := validateFrontSNI("example.test", addr, settings)
	if ok {
		t.Fatal("expected bare front domain (no subdomain) to be rejected")
	}
}

func TestValidateFrontSNIAcceptsValidSubdomain(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, "example.test")
	settings := config.NewSettingType(false)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	got, ok := validateFrontSNI("vm.example.test", addr, settings)
	if !ok {
		t.Fatal("expected valid subdomain to be accepted")
	}
	if got != "vm" {
		t.Fatalf("expected hostname %q, got %q", "vm", got)
	}
}

func TestAuthorizeRDPAccessRejectsNilSessionManager(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if authorizeRDPAccess(addr, nil, "vm.example.test", "vm") {
		t.Fatal("expected authorizeRDPAccess to return false when session manager is nil")
	}
}
