package rdp

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"strings"
	"testing"
	"time"
)

// buildCSNetPDU returns a synthetic TPKT/X.224-Data PDU that contains a CS_NET
// block listing the given channel names. The bytes before the CS_NET block are
// arbitrary filler – the rewriter must locate CS_NET by its signature.
func buildCSNetPDU(t *testing.T, names []string) []byte {
	t.Helper()

	// Padding to simulate a real MCS Connect Initial preamble (callingDomainSelector,
	// calledDomainSelector, BER tags, GCC user data prefix, CS_CORE, CS_SECURITY).
	prefix := []byte{
		0x03, 0x00, 0x00, 0x00, // TPKT placeholder (length set later)
		0x02, 0xf0, 0x80, // X.224 Data TPDU header (LI=2, code=DT, EOT)
		// Arbitrary filler bytes that should NOT trip the CS_NET signature scan.
		0x7f, 0x65, 0x82, 0x00, 0x00,
		0x04, 0x01, 0x00, 0x04, 0x01, 0x00, 0x01, 0x01, 0xff,
		// A trap byte sequence that looks like a CS_NET type but with implausible
		// lengths/counts to ensure the scanner rejects it.
		csNetTypeLow, csNetTypeHigh, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	count := uint32(len(names))
	csNetLen := uint16(csNetHeaderByteLen + int(count)*channelDefByteLen)

	csNet := make([]byte, 0, csNetLen)
	csNet = append(csNet, csNetTypeLow, csNetTypeHigh)
	csNet = binary.LittleEndian.AppendUint16(csNet, csNetLen)
	csNet = binary.LittleEndian.AppendUint32(csNet, count)
	for _, n := range names {
		nameBuf := make([]byte, channelNameByteLen)
		copy(nameBuf, n)
		csNet = append(csNet, nameBuf...)
		csNet = binary.LittleEndian.AppendUint32(csNet, 0x80000000)
	}

	body := make([]byte, 0, len(prefix)+len(csNet))
	body = append(body, prefix...)
	body = append(body, csNet...)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)))
	return body
}

func channelNameAt(buf []byte, offset int) string {
	return strings.TrimRight(string(buf[offset:offset+channelNameByteLen]), "\x00")
}

func TestChannelFilterDisabledByDefault(t *testing.T) {
	settings := config.NewSettingType(false)
	f := newChannelFilter(settings)
	if f.enabled() {
		t.Fatalf("expected filter to be disabled by default")
	}
	pdu := buildCSNetPDU(t, []string{"cliprdr", "rdpdr", "rdpsnd"})
	original := append([]byte(nil), pdu...)
	if got := f.rewriteMCSConnectInitial(pdu); len(got) != 0 {
		t.Fatalf("disabled filter should not rewrite, got %v", got)
	}
	if string(pdu) != string(original) {
		t.Fatalf("disabled filter must not mutate buffer")
	}
}

func TestChannelFilterRewritesClipboardAndDrives(t *testing.T) {
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	t.Setenv(config.RDP_DISABLE_DRIVES, "true")
	settings := config.NewSettingType(false)
	f := newChannelFilter(settings)
	if !f.enabled() {
		t.Fatalf("expected filter to be enabled")
	}

	pdu := buildCSNetPDU(t, []string{"CLIPRDR", "rdpsnd", "rdpdr"})
	rewritten := f.rewriteMCSConnectInitial(pdu)
	if len(rewritten) != 2 {
		t.Fatalf("expected 2 rewrites, got %v", rewritten)
	}

	offset, count, ok := findCSNetBlock(pdu)
	if !ok {
		t.Fatalf("CS_NET block missing after rewrite")
	}
	if count != 3 {
		t.Fatalf("channel count changed: %d", count)
	}
	names := []string{
		channelNameAt(pdu, offset+0*channelDefByteLen),
		channelNameAt(pdu, offset+1*channelDefByteLen),
		channelNameAt(pdu, offset+2*channelDefByteLen),
	}
	if names[0] == "CLIPRDR" || strings.EqualFold(names[0], "cliprdr") {
		t.Fatalf("clipboard channel was not renamed: %q", names[0])
	}
	if names[2] == "rdpdr" {
		t.Fatalf("drive channel was not renamed: %q", names[2])
	}
	if names[1] != "rdpsnd" {
		t.Fatalf("unrelated channel name should be preserved, got %q", names[1])
	}
}

func TestChannelFilterClipboardOnly(t *testing.T) {
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	settings := config.NewSettingType(false)
	f := newChannelFilter(settings)

	pdu := buildCSNetPDU(t, []string{"cliprdr", "rdpdr"})
	rewritten := f.rewriteMCSConnectInitial(pdu)
	if len(rewritten) != 1 || rewritten[0] != "cliprdr" {
		t.Fatalf("expected only cliprdr to be rewritten, got %v", rewritten)
	}
	offset, _, _ := findCSNetBlock(pdu)
	if name := channelNameAt(pdu, offset+1*channelDefByteLen); name != "rdpdr" {
		t.Fatalf("drives channel should remain untouched, got %q", name)
	}
}

func TestChannelFilterIgnoresPDUWithoutCSNet(t *testing.T) {
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	settings := config.NewSettingType(false)
	f := newChannelFilter(settings)

	// A buffer with no valid CS_NET signature.
	buf := []byte{0x03, 0x00, 0x00, 0x10, 0x02, 0xf0, 0x80, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00}
	got := f.rewriteMCSConnectInitial(buf)
	if len(got) != 0 {
		t.Fatalf("expected no rewrites, got %v", got)
	}
}

func TestChannelFilterPreservesLengths(t *testing.T) {
	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	t.Setenv(config.RDP_DISABLE_DRIVES, "true")
	settings := config.NewSettingType(false)
	f := newChannelFilter(settings)

	pdu := buildCSNetPDU(t, []string{"cliprdr", "rdpdr", "rdpsnd"})
	originalLen := len(pdu)
	originalTPKTLen := binary.BigEndian.Uint16(pdu[2:4])

	_ = f.rewriteMCSConnectInitial(pdu)

	if len(pdu) != originalLen {
		t.Fatalf("buffer length changed: %d -> %d", originalLen, len(pdu))
	}
	if got := binary.BigEndian.Uint16(pdu[2:4]); got != originalTPKTLen {
		t.Fatalf("TPKT length changed: %d -> %d", originalTPKTLen, got)
	}
}

// TestHandleRDPStripsBlockedChannelsEndToEnd exercises HandleRDP with the
// channel filter enabled and asserts that the backend sees the rewritten
// MCS Connect Initial.
func TestHandleRDPStripsBlockedChannelsEndToEnd(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.61"
	stubVMIPs(t, map[string]string{"vmfilter": backendHost})
	defineOwnedRDPTestDomains(t, map[string]string{"vmfilter": "alice"})

	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	t.Setenv(config.RDP_DISABLE_DRIVES, "true")

	receivedPDU := startEchoBackendCapturingPDU(t, backendHost)
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	sessionManager := session.NewManager()
	issueUserSession(t, sessionManager, "alice", "192.0.2.150:5000")

	client, done := startHandleRDPTestConnection(t, frontTLS, sessionManager, settings, "192.0.2.150")
	tlsClient := performFrontHandshake(t, client, "vmfilter.example.test")
	defer func() { _ = tlsClient.Close() }()

	pdu := buildCSNetPDU(t, []string{"cliprdr", "rdpsnd", "rdpdr"})
	if _, err := tlsClient.Write(pdu); err != nil {
		t.Fatalf("write client MCS Connect Initial: %v", err)
	}

	backendPDU := waitForBackendPDU(t, receivedPDU)
	assertChannelsStripped(t, backendPDU)

	go func() { _, _ = io.Copy(io.Discard, tlsClient) }()
	_ = tlsClient.Close()
	waitDone(t, done)
}

func startEchoBackendCapturingPDU(t *testing.T, backendHost string) <-chan []byte {
	t.Helper()
	received := make(chan []byte, 1)
	stopBackend := startTLSServingBackend(t, backendHost, func(tlsConn *tls.Conn) {
		buf, err := readTPKT(tlsConn)
		if err != nil {
			t.Errorf("backend read MCS Connect Initial: %v", err)
			return
		}
		received <- buf
		_, _ = tlsConn.Write([]byte("ok"))
	})
	t.Cleanup(stopBackend)
	return received
}

func waitForBackendPDU(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case buf := <-ch:
		return buf
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not receive forwarded PDU in time")
		return nil
	}
}

func assertChannelsStripped(t *testing.T, backendPDU []byte) {
	t.Helper()
	offset, count, ok := findCSNetBlock(backendPDU)
	if !ok {
		t.Fatalf("backend PDU missing CS_NET block")
	}
	if count != 3 {
		t.Fatalf("expected 3 channels in backend PDU, got %d", count)
	}
	if name := channelNameAt(backendPDU, offset+0*channelDefByteLen); strings.EqualFold(name, "cliprdr") {
		t.Fatalf("clipboard channel was not stripped on the wire: %q", name)
	}
	if name := channelNameAt(backendPDU, offset+2*channelDefByteLen); name == "rdpdr" {
		t.Fatalf("drive channel was not stripped on the wire: %q", name)
	}
	if name := channelNameAt(backendPDU, offset+1*channelDefByteLen); name != "rdpsnd" {
		t.Fatalf("rdpsnd should pass through, got %q", name)
	}
}

// TestForwardClientMCSConnectInitialReadError ensures the helper bails out and
// returns false when the upstream connection cannot supply a PDU.
func TestForwardClientMCSConnectInitialReadError(t *testing.T) {
	clientA, serverA := net.Pipe()
	_ = serverA.Close()
	defer func() { _ = clientA.Close() }()

	clientB, serverB := net.Pipe()
	defer func() {
		_ = clientB.Close()
		_ = serverB.Close()
	}()

	t.Setenv(config.RDP_DISABLE_CLIPBOARD, "true")
	settings := config.NewSettingType(false)
	if ok := forwardClientMCSConnectInitial(clientA, clientB, newChannelFilter(settings), settings); ok {
		t.Fatal("expected forward to fail on closed client connection")
	}
}
