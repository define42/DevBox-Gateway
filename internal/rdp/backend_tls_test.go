package rdp

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/tomatome/grdp/protocol/x224"
)

func TestBackendTLSConfigDefaultsServerNameEmpty(t *testing.T) {
	cfg := backendTLSConfig("")
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify true for backend cert handling")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS1.2, got 0x%04x", cfg.MinVersion)
	}
	if cfg.ServerName != "" {
		t.Fatalf("expected empty ServerName, got %q", cfg.ServerName)
	}
}

func TestBackendTLSConfigSetsServerNameForRealSNI(t *testing.T) {
	cfg := backendTLSConfig("vm.example.test")
	if cfg.ServerName != "vm.example.test" {
		t.Fatalf("expected ServerName to be set, got %q", cfg.ServerName)
	}
}

func TestBackendTLSConfigIgnoresWildcardSNI(t *testing.T) {
	cfg := backendTLSConfig("*")
	if cfg.ServerName != "" {
		t.Fatalf("expected ServerName to be empty for %q SNI, got %q", "*", cfg.ServerName)
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

	if _, err := negotiateBackendTLS(client, "127.0.0.1:3389", ""); err == nil {
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

	_, err := negotiateBackendTLS(client, "127.0.0.1:3389", "")
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

	_, err := negotiateBackendTLS(client, "127.0.0.1:3389", "")
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
