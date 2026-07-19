package rdp

import (
	"bytes"
	"crypto/tls"
	"devboxgateway/internal/config"
	"devboxgateway/internal/session"
	"devboxgateway/internal/virt"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tomatome/grdp/protocol/x224"
	"libvirt.org/go/libvirt"
)

// covxDomainXML is a minimal TCG (type='qemu') domain so the tests can define
// owned domains both locally (no /dev/kvm) and in CI.
const covxDomainXML = `<domain type='qemu'>
  <name>%s</name>
  <memory unit='MiB'>32</memory>
  <currentMemory unit='MiB'>32</currentMemory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
  </os>
</domain>`

func covxUniqueName(tag string) string {
	return fmt.Sprintf("covx%s%d", tag, time.Now().UnixNano())
}

// covxDefineOwnedDomain defines a transient-config TCG domain owned by "alice"
// and registers cleanup that destroys and undefines it.
func covxDefineOwnedDomain(t *testing.T, name string) {
	t.Helper()

	conn, err := libvirt.NewConnect(virt.LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.DomainDefineXML(fmt.Sprintf(covxDomainXML, name))
	if err != nil {
		t.Fatalf("define covx domain %q: %v", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()
	t.Cleanup(func() { cleanupOwnedRDPTestDomain(t, name) })

	payload, err := xml.Marshal(testDomainOwnerMetadata{Value: "alice"})
	if err != nil {
		t.Fatalf("marshal owner metadata for %q: %v", name, err)
	}
	if err := dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		string(payload),
		testDomainOwnerMetadataPrefix,
		testDomainOwnerMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	); err != nil {
		t.Fatalf("set owner metadata for %q: %v", name, err)
	}
}

// covxAddr is a net.Addr whose textual form is not a parseable client address.
type covxAddr struct{}

func (covxAddr) Network() string { return "tcp" }
func (covxAddr) String() string  { return "not-a-client-ip" }

func TestCovxDebugfRespectsToggle(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	SetDebugLogging(true)
	t.Cleanup(func() { SetDebugLogging(false) })
	debugf("covx toggle %d", 7)
	if !strings.Contains(buf.String(), "rdp debug: covx toggle 7") {
		t.Fatalf("expected debug line to be logged, got %q", buf.String())
	}

	SetDebugLogging(false)
	buf.Reset()
	debugf("covx hidden")
	if buf.Len() != 0 {
		t.Fatalf("expected no output while disabled, got %q", buf.String())
	}
}

func TestCovxReadTPKTErrors(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
	}{
		{"invalid version", []byte{0x00, 0x00, 0x00, 0x04}},
		{"length below minimum", []byte{0x03, 0x00, 0x00, 0x02}},
		// Valid header announcing a 16-byte PDU, then EOF mid-payload.
		{"payload truncated", []byte{0x03, 0x00, 0x00, 0x10}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() {
				_ = client.Close()
			}()
			go func() {
				_, _ = server.Write(tc.header)
				_ = server.Close()
			}()

			if _, err := readTPKT(client); err == nil {
				t.Fatalf("expected readTPKT error for %s", tc.name)
			}
		})
	}
}

func TestCovxFindServerSelectedProtocolMissing(t *testing.T) {
	if _, ok := findServerSelectedProtocol([]byte{0x03, 0x00, 0x00, 0x0b}); ok {
		t.Fatal("expected ok=false when the CCF carries no RDP_NEG_RSP")
	}
}

func TestCovxFindX224NegotiationSkipsWrongLengthThenFinds(t *testing.T) {
	tpktPayload := make([]byte, 4+7+9+8)
	payload := tpktPayload[4:]
	// First candidate at i=7 has the right type but a bogus length of 16.
	payload[7] = byte(x224.TYPE_RDP_NEG_RSP)
	payload[9] = 0x10
	// Second candidate at i=16 is well formed and selects PROTOCOL_SSL.
	payload[16] = byte(x224.TYPE_RDP_NEG_RSP)
	payload[18] = 8
	payload[20] = 1

	neg, ok := findX224Negotiation(tpktPayload, x224.TYPE_RDP_NEG_RSP)
	if !ok {
		t.Fatal("expected the scanner to skip the malformed block and find the valid one")
	}
	if neg.Result != x224.PROTOCOL_SSL {
		t.Fatalf("expected PROTOCOL_SSL, got 0x%08x", neg.Result)
	}
}

// covxCSNetCandidate builds a buffer holding a single CS_NET-looking header
// with the given length/count and no channel data after it.
func covxCSNetCandidate(length uint16, count uint32) []byte {
	buf := make([]byte, 7, 15)
	buf = append(buf, csNetTypeLow, csNetTypeHigh)
	buf = binary.LittleEndian.AppendUint16(buf, length)
	buf = binary.LittleEndian.AppendUint32(buf, count)
	return buf
}

func TestCovxFindCSNetBlockEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{"buffer shorter than minimum", make([]byte, 10)},
		// length must equal 8 + 12*count (= 20 for one channel); 255 does not.
		{"length count mismatch", covxCSNetCandidate(0xff, 1)},
		// length matches the count but the block runs past the end of the buffer.
		{"block truncated", covxCSNetCandidate(20, 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := findCSNetBlock(tc.buf); ok {
				t.Fatalf("expected findCSNetBlock to reject case %q", tc.name)
			}
		})
	}
}

func TestCovxForwardMCSNoCSNetBlockForwardsUnchanged(t *testing.T) {
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	settings := config.NewSettingType(false)

	client, clientPeer := net.Pipe()
	backend, backendPeer := net.Pipe()
	defer func() {
		_ = client.Close()
		_ = clientPeer.Close()
		_ = backend.Close()
		_ = backendPeer.Close()
	}()

	pdu := wrapTPKT(make([]byte, 16)) // valid TPKT, no CS_NET signature
	go func() {
		_, _ = clientPeer.Write(pdu)
	}()
	forwarded := make(chan []byte, 1)
	go func() {
		buf, err := readTPKT(backendPeer)
		if err != nil {
			forwarded <- nil
			return
		}
		forwarded <- buf
	}()

	if !forwardClientMCSConnectInitial(client, backend, newChannelFilter(settings), settings) {
		t.Fatal("expected forward to succeed for a PDU without CS_NET")
	}
	select {
	case got := <-forwarded:
		if len(got) != len(pdu) {
			t.Fatalf("expected %d forwarded bytes, got %d", len(pdu), len(got))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received the forwarded PDU")
	}
}

func TestCovxForwardMCSBackendWriteError(t *testing.T) {
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	settings := config.NewSettingType(false)

	client, clientPeer := net.Pipe()
	backend, backendPeer := net.Pipe()
	_ = backend.Close()
	_ = backendPeer.Close()
	defer func() {
		_ = client.Close()
		_ = clientPeer.Close()
	}()

	go func() {
		_, _ = clientPeer.Write(wrapTPKT(make([]byte, 16)))
	}()

	if forwardClientMCSConnectInitial(client, backend, newChannelFilter(settings), settings) {
		t.Fatal("expected forward to fail when the backend connection is closed")
	}
}

func TestCovxNegotiateBackendTLSMissingNegotiationRSP(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	go func() {
		if _, err := readTPKT(server); err != nil {
			return
		}
		// A well-formed TPKT whose payload has no RDP_NEG_RSP structure.
		_, _ = server.Write(wrapTPKT(make([]byte, 7)))
		_ = server.Close()
	}()

	if _, err := negotiateBackendTLS(client, "backend:3389", ""); err == nil {
		t.Fatal("expected error when the backend CCF lacks RDP_NEG_RSP")
	}
	_ = client.Close()
}

func TestCovxNegotiateBackendTLSHandshakeFailure(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	go func() {
		if _, err := readTPKT(server); err != nil {
			return
		}
		// Confirm TLS, then slam the connection shut so the handshake fails.
		_, _ = server.Write(wrapTPKT(buildServerCCFSelectTLS()))
		_ = server.Close()
	}()

	if _, err := negotiateBackendTLS(client, "backend:3389", "vm.example.test"); err == nil {
		t.Fatal("expected TLS handshake error after the backend closes")
	}
	_ = client.Close()
}

func TestCovxNegotiateBackendTLSTransportErrors(t *testing.T) {
	InitLogging()
	tests := []struct {
		name   string
		server func(net.Conn)
	}{
		{"crq write fails", func(c net.Conn) { _ = c.Close() }},
		{"ccf read fails", func(c net.Conn) {
			_, _ = readTPKT(c)
			_ = c.Close()
		}},
		{"backend selects plain rdp", func(c net.Conn) {
			_, _ = readTPKT(c)
			_, _ = c.Write(wrapTPKT(buildServerCCFForProtocol(x224.PROTOCOL_RDP)))
			_ = c.Close()
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.server(server)
			}()

			if _, err := negotiateBackendTLS(client, "backend:3389", ""); err == nil {
				t.Fatalf("expected negotiateBackendTLS error for %s", tc.name)
			}
			_ = client.Close()
			<-done
		})
	}
}

func TestCovxHandshakeFrontTLSFailure(t *testing.T) {
	InitLogging()
	frontTLS, _ := newFrontTLSManager(t, "example.test")

	client, server := net.Pipe()
	go func() {
		_, _ = client.Write([]byte{'n', 'o', 't', 'l', 's'})
		_ = client.Close()
	}()

	if _, _, ok := handshakeFrontTLS(server, frontTLS, time.Now()); ok {
		t.Fatal("expected front TLS handshake to fail on non-TLS bytes")
	}
	_ = server.Close()
}

func TestCovxNegotiateFrontRDPReadCRQFailure(t *testing.T) {
	InitLogging()
	settings := config.NewSettingType(false)
	client, server := net.Pipe()
	_ = client.Close()

	if _, ok := negotiateFrontRDP(server, nil, settings, time.Now()); ok {
		t.Fatal("expected failure when the client closes before sending a CRQ")
	}
	_ = server.Close()
}

func TestCovxNegotiateFrontRDPWriteCCFFailure(t *testing.T) {
	InitLogging()
	settings := config.NewSettingType(false)
	client, server := net.Pipe()
	go func() {
		if err := writeTPKT(client, buildClientCRQ(x224.PROTOCOL_SSL)); err != nil {
			return
		}
		// Close before reading the CCF so the gateway's write fails.
		_ = client.Close()
	}()

	if _, ok := negotiateFrontRDP(server, nil, settings, time.Now()); ok {
		t.Fatal("expected failure when the CCF cannot be written")
	}
	_ = server.Close()
}

func TestCovxNegotiateFrontRDPHandshakeFailure(t *testing.T) {
	InitLogging()
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	client, server := net.Pipe()
	go func() {
		if err := writeTPKT(client, buildClientCRQ(x224.PROTOCOL_SSL)); err != nil {
			return
		}
		if _, err := readTPKT(client); err != nil {
			return
		}
		_, _ = client.Write([]byte{'n', 'o', 't', 'l', 's'})
		_ = client.Close()
	}()

	if _, ok := negotiateFrontRDP(server, frontTLS, settings, time.Now()); ok {
		t.Fatal("expected failure when the front TLS handshake fails")
	}
	_ = server.Close()
}

func TestCovxAuthorizeRDPAccessOwnerLookupError(t *testing.T) {
	t.Setenv("LIBVIRT_URI", "qemu+unix:///system?socket=/nonexistent/covx-libvirt.sock")
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	if _, ok := authorizeRDPAccess(addr, session.NewManager(), "covx.example.test", "covxvm"); ok {
		t.Fatal("expected denial when the owner lookup errors")
	}
}

func TestCovxAuthorizeRDPAccessMissingOwner(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	// An empty hostname resolves to "no owner" without a libvirt round trip.
	if _, ok := authorizeRDPAccess(addr, session.NewManager(), "covx.example.test", ""); ok {
		t.Fatal("expected denial for a VM without owner metadata")
	}
}

func TestCovxAuthorizeRDPAccessInvalidClientAddr(t *testing.T) {
	name := covxUniqueName("addr")
	covxDefineOwnedDomain(t, name)

	if _, ok := authorizeRDPAccess(covxAddr{}, session.NewManager(), name+".example.test", name); ok {
		t.Fatal("expected denial for an unparseable client address")
	}
}

func TestCovxAuthorizeRDPAccessWithoutGrant(t *testing.T) {
	name := covxUniqueName("grnt")
	covxDefineOwnedDomain(t, name)
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 90), Port: 42424}

	// Owner and client IP resolve fine, but no Connect grant was recorded.
	if _, ok := authorizeRDPAccess(addr, session.NewManager(), name+".example.test", name); ok {
		t.Fatal("expected denial without an unused Connect authorization")
	}
}

func TestCovxForwardMCSRewritesBlockedChannel(t *testing.T) {
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	settings := config.NewSettingType(false)

	client, clientPeer := net.Pipe()
	backend, backendPeer := net.Pipe()
	defer func() {
		_ = client.Close()
		_ = clientPeer.Close()
		_ = backend.Close()
		_ = backendPeer.Close()
	}()

	pdu := buildCSNetPDU(t, []string{"cliprdr", "rdpsnd"})
	go func() {
		_, _ = clientPeer.Write(pdu)
	}()
	forwarded := make(chan []byte, 1)
	go func() {
		buf, err := readTPKT(backendPeer)
		if err != nil {
			forwarded <- nil
			return
		}
		forwarded <- buf
	}()

	if !forwardClientMCSConnectInitial(client, backend, newChannelFilter(settings), settings) {
		t.Fatal("expected forward to succeed while stripping channels")
	}
	select {
	case got := <-forwarded:
		offset, _, ok := findCSNetBlock(got)
		if !ok {
			t.Fatal("forwarded PDU lost its CS_NET block")
		}
		if name := channelNameAt(got, offset); strings.EqualFold(name, "cliprdr") {
			t.Fatalf("clipboard channel was not stripped, got %q", name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend never received the rewritten PDU")
	}
}

func TestCovxResolveBackendAddrBranches(t *testing.T) {
	stubVMIPs(t, map[string]string{"covxgood": "127.0.0.9", "covxempty": ""})
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	if _, ok := resolveBackendAddr(addr, "sni", "covxmissing"); ok {
		t.Fatal("expected failure when the IP lookup errors")
	}
	if _, ok := resolveBackendAddr(addr, "sni", "covxempty"); ok {
		t.Fatal("expected failure when the VM has no trusted route")
	}
	got, ok := resolveBackendAddr(addr, "sni", "covxgood")
	if !ok {
		t.Fatal("expected success for a routable VM")
	}
	if got != "127.0.0.9:3389" {
		t.Fatalf("expected backend addr %q, got %q", "127.0.0.9:3389", got)
	}
}

func TestCovxHandleRDPClientClosesBeforeCRQ(t *testing.T) {
	InitLogging()
	settings := config.NewSettingType(false)
	client, server := net.Pipe()

	done := make(chan struct{})
	go func() {
		HandleRDP(server, nil, nil, settings)
		close(done)
	}()

	_ = client.Close()
	waitDone(t, done)
}

func TestCovxHandleRDPRejectsUnknownRoutingLabel(t *testing.T) {
	InitLogging()
	stubVMIPs(t, map[string]string{})
	frontTLS, settings := newFrontTLSManager(t, "example.test")

	client, done := startHandleRDPTestConnection(t, frontTLS, nil, settings, "192.0.2.184")
	tlsClient := performFrontHandshake(t, client, "covxunknown.example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() { _, _ = io.Copy(io.Discard, tlsClient) }()

	waitDone(t, done)
}

func TestCovxHandleRDPDeniesWhenVMHasNoOwner(t *testing.T) {
	InitLogging()
	name := covxUniqueName("noown")
	// Route the label, but never define the domain: owner resolution denies.
	stubVMIPs(t, map[string]string{name: "127.0.0.71"})
	frontTLS, settings := newFrontTLSManager(t, "example.test")

	client, done := startHandleRDPTestConnection(t, frontTLS, session.NewManager(), settings, "192.0.2.180")
	tlsClient := performFrontHandshake(t, client, name+".example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() { _, _ = io.Copy(io.Discard, tlsClient) }()

	waitDone(t, done)
}

func TestCovxHandleRDPNoRouteForVM(t *testing.T) {
	InitLogging()
	name := covxUniqueName("norte")
	// Empty IP means "no trusted route" once authorization has passed.
	stubVMIPs(t, map[string]string{name: ""})
	covxDefineOwnedDomain(t, name)
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.181:5000", name)

	client, done := startHandleRDPTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.181")
	tlsClient := performFrontHandshake(t, client, name+".example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() { _, _ = io.Copy(io.Discard, tlsClient) }()

	waitDone(t, done)
}

func TestCovxHandleRDPBackendDialRefused(t *testing.T) {
	InitLogging()
	name := covxUniqueName("dial")
	// Nothing listens on this loopback alias, so the dial is refused instantly.
	stubVMIPs(t, map[string]string{name: "127.0.0.72"})
	covxDefineOwnedDomain(t, name)
	t.Setenv(config.TIMEOUT, "2s")
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.182:5000", name)

	client, done := startHandleRDPTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.182")
	tlsClient := performFrontHandshake(t, client, name+".example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() { _, _ = io.Copy(io.Discard, tlsClient) }()

	waitDone(t, done)
}

func TestCovxHandleRDPChannelFilterForwardFailure(t *testing.T) {
	InitLogging()
	name := covxUniqueName("filt")
	backendHost := "127.0.0.73"
	stubVMIPs(t, map[string]string{name: backendHost})
	covxDefineOwnedDomain(t, name)
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")

	stopBackend := startTLSServingBackend(t, backendHost, func(tlsConn *tls.Conn) {
		_, _ = readTPKT(tlsConn) // returns once the gateway tears the connection down
	})
	defer stopBackend()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.183:5000", name)

	client, done := startHandleRDPTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.183")
	tlsClient := performFrontHandshake(t, client, name+".example.test")
	// Kill the raw front connection before sending the MCS Connect Initial so
	// the channel-filter forward fails and HandleRDP tears everything down.
	_ = client.Close()
	_ = tlsClient.Close()

	waitDone(t, done)
}

func TestCovxHandleRDPRevocationClosesActiveProxy(t *testing.T) {
	InitLogging()
	name := covxUniqueName("revk")
	backendHost := "127.0.0.74"
	stubVMIPs(t, map[string]string{name: backendHost})
	covxDefineOwnedDomain(t, name)

	stopBackend := startTLSServingBackend(t, backendHost, func(tlsConn *tls.Conn) {
		_, _ = readTPKT(tlsConn) // block until revocation closes the proxy
	})
	defer stopBackend()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.185:5000", name)

	client, done := startHandleRDPTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.185")
	tlsClient := performFrontHandshake(t, client, name+".example.test")
	defer func() { _ = tlsClient.Close() }()
	go func() { _, _ = io.Copy(io.Discard, tlsClient) }()

	// Wait for the proxy to register the connection, then revoke it: the
	// registered close callback must terminate HandleRDP.
	deadline := time.Now().Add(5 * time.Second)
	for sessionManager.CloseUserConnections("alice") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("RDP connection was never registered for revocation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitDone(t, done)
}
