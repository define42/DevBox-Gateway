package rdp

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tomatome/grdp/protocol/x224"
)

func TestGetSubdomain(t *testing.T) {
	tests := []struct {
		host, root string
		wantSub    string
		wantOK     bool
	}{
		{"vm1.example.com", "example.com", "vm1", true},
		{"deep.sub.example.com", "example.com", "deep.sub", true},
		{"example.com", "example.com", "", false},
		{"other.test", "example.com", "", false},
		{"", "example.com", "", false},
		{".example.com", "example.com", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.host+"/"+tc.root, func(t *testing.T) {
			sub, ok := getSubdomain(tc.host, tc.root)
			if ok != tc.wantOK {
				t.Fatalf("getSubdomain(%q, %q) ok=%v, want %v", tc.host, tc.root, ok, tc.wantOK)
			}
			if sub != tc.wantSub {
				t.Fatalf("getSubdomain(%q, %q) = %q, want %q", tc.host, tc.root, sub, tc.wantSub)
			}
		})
	}
}

func TestTlsVersionLabel(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
		{0x9999, "0x9999"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tlsVersionLabel(tc.version); got != tc.want {
				t.Fatalf("tlsVersionLabel(0x%04x) = %q, want %q", tc.version, got, tc.want)
			}
		})
	}
}

func TestBuildServerCCFSelectTLS(t *testing.T) {
	payload := buildServerCCFSelectTLS()
	if len(payload) == 0 {
		t.Fatal("expected non-empty payload")
	}

	// The response type should be Connection Confirm
	if payload[1] != byte(x224.TPDU_CONNECTION_CONFIRM) {
		t.Fatalf("expected CC TPDU type, got 0x%02x", payload[1])
	}
}

func TestBuildClientCRQSelectTLS(t *testing.T) {
	payload := buildClientCRQSelectTLS()
	if len(payload) == 0 {
		t.Fatal("expected non-empty payload")
	}
}

// wrapTPKT wraps an X.224 payload in a TPKT header for testing.
func wrapTPKT(payload []byte) []byte {
	total := len(payload) + 4
	tpkt := make([]byte, total)
	tpkt[0] = 0x03 // TPKT version
	tpkt[1] = 0x00
	tpkt[2] = byte(total >> 8)
	tpkt[3] = byte(total)
	copy(tpkt[4:], payload)
	return tpkt
}

func TestFindClientRequestedProtocolsValid(t *testing.T) {
	crq := wrapTPKT(buildClientCRQ(x224.PROTOCOL_SSL))
	proto, ok := findClientRequestedProtocols(crq)
	if !ok {
		t.Fatal("expected ok=true for valid CRQ")
	}
	if proto != x224.PROTOCOL_SSL {
		t.Fatalf("expected PROTOCOL_SSL (0x%08x), got 0x%08x", x224.PROTOCOL_SSL, proto)
	}
}

func TestFindClientRequestedProtocolsHybrid(t *testing.T) {
	crq := wrapTPKT(buildClientCRQ(x224.PROTOCOL_HYBRID | x224.PROTOCOL_SSL))
	proto, ok := findClientRequestedProtocols(crq)
	if !ok {
		t.Fatal("expected ok=true for valid CRQ")
	}
	if proto&x224.PROTOCOL_SSL == 0 {
		t.Fatalf("expected PROTOCOL_SSL bit set, got 0x%08x", proto)
	}
}

func TestFindClientRequestedProtocolsTooShort(t *testing.T) {
	_, ok := findClientRequestedProtocols([]byte{0x03, 0x00, 0x00, 0x04})
	if ok {
		t.Fatal("expected ok=false for too-short payload")
	}
}

func TestFindServerSelectedProtocol(t *testing.T) {
	ccf := buildServerCCFSelectTLS()
	// Wrap with TPKT header
	total := len(ccf) + 4
	tpkt := make([]byte, total)
	tpkt[0] = 0x03 // TPKT version
	tpkt[1] = 0x00
	tpkt[2] = byte(total >> 8)
	tpkt[3] = byte(total)
	copy(tpkt[4:], ccf)

	sel, ok := findServerSelectedProtocol(tpkt)
	if !ok {
		t.Fatal("expected ok=true for valid CCF")
	}
	if sel != x224.PROTOCOL_SSL {
		t.Fatalf("expected PROTOCOL_SSL, got 0x%08x", sel)
	}
}

func TestFindX224NegotiationTooShort(t *testing.T) {
	_, ok := findX224Negotiation([]byte{1, 2, 3}, x224.TYPE_RDP_NEG_REQ)
	if ok {
		t.Fatal("expected ok=false for too-short payload")
	}
}

func TestProxyBidirectional(t *testing.T) {
	clientA, serverA := net.Pipe()
	clientB, serverB := net.Pipe()

	done := make(chan struct{})
	go func() {
		proxyBidirectional(serverA, serverB)
		close(done)
	}()

	// Write from side A, read from side B
	testData := []byte("hello proxy")
	go func() {
		_, _ = clientA.Write(testData)
		_ = clientA.Close()
	}()

	buf, err := io.ReadAll(clientB)
	if err != nil {
		t.Fatalf("read from B: %v", err)
	}
	if string(buf) != string(testData) {
		t.Fatalf("expected %q, got %q", testData, buf)
	}

	_ = clientB.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("proxyBidirectional did not return in time")
	}
}

func TestReadTPKTInvalidVersion(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte{0x00, 0x00, 0x00, 0x04}) // wrong version
	}()

	_, err := readTPKT(client)
	if err == nil {
		t.Fatal("expected error for invalid TPKT version")
	}
}

func TestReadTPKTInvalidLength(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte{0x03, 0x00, 0x00, 0x02}) // length too small
	}()

	_, err := readTPKT(client)
	if err == nil {
		t.Fatal("expected error for invalid TPKT length")
	}
}
