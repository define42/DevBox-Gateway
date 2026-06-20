// Package rdp implements the TLS-terminating RDP proxy logic.
package rdp

import (
	"crypto/tls"
	"devboxgateway/internal/cert"
	"devboxgateway/internal/config"
	"devboxgateway/internal/session"
	"devboxgateway/internal/virt"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
)

// InitLogging configures grdp's logger to use the standard logger.
func InitLogging() {
	glog.SetLogger(log.New(os.Stdout, "", 0))
	glog.SetLevel(glog.ERROR)
}

// debugLogging gates the verbose per-connection "rdp debug:" diagnostics. It is
// enabled from main when DEBUG_CONNECTIONS is set so the noisy step-by-step
// negotiation/proxy logging — which includes resolved VM names and backend IPs —
// stays off in normal operation, matching the console/VNC packages.
var debugLogging atomic.Bool //nolint:gochecknoglobals // package-level debug toggle set once at startup

// SetDebugLogging toggles verbose "rdp debug:" connection logging.
func SetDebugLogging(enabled bool) {
	debugLogging.Store(enabled)
}

// debugf emits a verbose "rdp debug:" line only when debug logging is enabled.
func debugf(format string, args ...any) {
	if debugLogging.Load() {
		log.Printf("rdp debug: "+format, args...)
	}
}

//nolint:gochecknoglobals // package-level singleton needed for one-time registration
var vmIPAddressLookup = func(hostname string) (string, error) {
	return virt.GetInstance().GetIPOfVM(hostname)
}

//nolint:gochecknoglobals // package-level singleton needed for one-time registration
var vmNameByLabelLookup = func(secret []byte, label string) (string, bool) {
	return virt.GetInstance().ResolveVMNameByLabel(secret, label)
}

func getSubdomain(host, root string) (string, bool) {
	suffix := "." + root

	if !strings.HasSuffix(host, suffix) {
		return "", false
	}

	sub := strings.TrimSuffix(host, suffix)

	if sub == "" {
		return "", false // no subdomain
	}

	return sub, true
}

type frontRDPConnection struct {
	tlsConn  *tls.Conn
	sni      string
	hostname string
}

// HandleRDP handles a single RDP connection over TLS.
func HandleRDP(raw net.Conn, frontTLS *cert.TLSManager, sessionManager *session.Manager, settings *config.SettingsType) {
	started := time.Now()
	debugf("new connection remote=%s local=%s", raw.RemoteAddr(), raw.LocalAddr())

	clientConn, ok := negotiateFrontRDP(raw, frontTLS, settings, started)
	if !ok {
		return
	}
	owner, ok := authorizeRDPAccess(raw.RemoteAddr(), sessionManager, clientConn.sni, clientConn.hostname)
	if !ok {
		_ = clientConn.tlsConn.Close()
		return
	}

	backendAddr, ok := resolveBackendAddr(raw.RemoteAddr(), clientConn.sni, clientConn.hostname)
	if !ok {
		_ = clientConn.tlsConn.Close()
		return
	}

	backendTLS, ok := dialBackendRDP(backendAddr, clientConn.sni, settings)
	if !ok {
		_ = clientConn.tlsConn.Close()
		return
	}
	unregisterConnection := sessionManager.RegisterUserConnection(owner, func() {
		_ = clientConn.tlsConn.Close()
		_ = backendTLS.Close()
	})
	defer unregisterConnection()

	_ = clientConn.tlsConn.SetDeadline(time.Time{})
	_ = backendTLS.SetDeadline(time.Time{})

	if filter := newChannelFilter(settings); filter.enabled() {
		if !forwardClientMCSConnectInitial(clientConn.tlsConn, backendTLS, filter, settings) {
			_ = clientConn.tlsConn.Close()
			_ = backendTLS.Close()
			return
		}
	}

	debugf("starting bidirectional proxy")
	proxyBidirectional(clientConn.tlsConn, backendTLS)
}

// forwardClientMCSConnectInitial reads exactly one TPKT PDU from the client
// (expected to be the MCS Connect Initial that follows the front-side TLS
// handshake), applies the channel filter to its CS_NET block in place, and
// forwards it to the backend. It returns false on a transport error so the
// caller can tear the connection down.
func forwardClientMCSConnectInitial(client, backend net.Conn, filter channelFilter, settings *config.SettingsType) bool {
	timeout := settings.GetDuration(config.TIMEOUT)
	if timeout > 0 {
		_ = client.SetReadDeadline(time.Now().Add(timeout))
		_ = backend.SetWriteDeadline(time.Now().Add(timeout))
	}

	buf, err := readTPKT(client)
	if err != nil {
		log.Printf("rdp channel filter: read MCS Connect Initial: %v", err)
		return false
	}

	if rewritten := filter.rewriteMCSConnectInitial(buf); len(rewritten) > 0 {
		log.Printf("rdp channel filter: stripped channels %v", rewritten)
	} else {
		log.Printf("rdp channel filter: no CS_NET block found, forwarding unchanged")
	}

	if _, err := backend.Write(buf); err != nil {
		log.Printf("rdp channel filter: forward MCS Connect Initial: %v", err)
		return false
	}

	_ = client.SetReadDeadline(time.Time{})
	_ = backend.SetWriteDeadline(time.Time{})
	return true
}

func proxyBidirectional(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	debugf(
		"proxy start a_local=%s a_remote=%s b_local=%s b_remote=%s",
		a.LocalAddr(),
		a.RemoteAddr(),
		b.LocalAddr(),
		b.RemoteAddr(),
	)

	started := time.Now()
	go func() {
		n, err := io.Copy(b, a)
		debugf(
			"proxy a->b done bytes=%d err=%v elapsed=%s",
			n,
			err,
			time.Since(started),
		)
		closeBoth()
	}()
	n, err := io.Copy(a, b)
	debugf(
		"proxy b->a done bytes=%d err=%v elapsed=%s",
		n,
		err,
		time.Since(started),
	)
	closeBoth()
}

// readTPKT reads one TPKT-framed PDU (4-byte header + payload).
func readTPKT(c net.Conn) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, err
	}
	if h[0] != tpkt.FASTPATH_ACTION_X224 || h[1] != 0x00 {
		return nil, fmt.Errorf("not TPKT (v=%02x r=%02x)", h[0], h[1])
	}
	n := int(binary.BigEndian.Uint16(h[2:4]))
	if n < 4 || n > 64*1024 {
		return nil, fmt.Errorf("invalid TPKT length %d", n)
	}
	b := make([]byte, n)
	copy(b[:4], h)
	if _, err := io.ReadFull(c, b[4:]); err != nil {
		return nil, err
	}
	return b, nil
}

// findClientRequestedProtocols finds an embedded RDP_NEG_REQ and returns requestedProtocols.
// We scan the payload for the 8-byte structure: type=0x01, len=8, then uint32 LE protocols.
func findClientRequestedProtocols(tpktPayload []byte) (uint32, bool) {
	neg, ok := findX224Negotiation(tpktPayload, x224.TYPE_RDP_NEG_REQ)
	if !ok {
		return 0, false
	}
	return neg.Result, true
}

// findServerSelectedProtocol finds an embedded RDP_NEG_RSP and returns selectedProtocol.
func findServerSelectedProtocol(tpktPayload []byte) (uint32, bool) {
	neg, ok := findX224Negotiation(tpktPayload, x224.TYPE_RDP_NEG_RSP)
	if !ok {
		return 0, false
	}
	return neg.Result, true
}

// buildServerCCFSelectTLS returns a minimal X.224 Connection Confirm payload selecting TLS (PROTOCOL_SSL).
func buildServerCCFSelectTLS() []byte {
	neg := x224.Negotiation{
		Type:   x224.TYPE_RDP_NEG_RSP,
		Flag:   0,
		Length: 8,
		Result: x224.PROTOCOL_SSL,
	}

	li := uint8(6 + neg.Length) // CC header (6) + negotiation (8)
	payload := make([]byte, 0, int(li)+1)
	payload = append(payload,
		li,
		byte(x224.TPDU_CONNECTION_CONFIRM),
		0x00, 0x00, // dst ref
		0x12, 0x34, // src ref (arbitrary)
		0x00, // class/options
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

func buildClientCRQSelectTLS() []byte {
	pdu := x224.NewClientConnectionRequestPDU(nil)
	pdu.ProtocolNeg.Type = x224.TYPE_RDP_NEG_REQ
	pdu.ProtocolNeg.Flag = 0
	pdu.ProtocolNeg.Length = 8
	pdu.ProtocolNeg.Result = x224.PROTOCOL_SSL
	pdu.Len = uint8(len(pdu.Serialize()) - 1)
	return pdu.Serialize()
}

func findX224Negotiation(tpktPayload []byte, wantType x224.NegotiationType) (*x224.Negotiation, bool) {
	if len(tpktPayload) < 11 { // TPKT(4) + X.224 header(7)
		return nil, false
	}
	payload := tpktPayload[4:]
	if len(payload) < 7 {
		return nil, false
	}
	for i := 7; i+8 <= len(payload); i++ {
		if payload[i] != byte(wantType) {
			continue
		}
		neg := &x224.Negotiation{
			Type:   x224.NegotiationType(payload[i]),
			Flag:   payload[i+1],
			Length: binary.LittleEndian.Uint16(payload[i+2 : i+4]),
			Result: binary.LittleEndian.Uint32(payload[i+4 : i+8]),
		}
		if neg.Length != 8 {
			continue
		}
		return neg, true
	}
	return nil, false
}

func writeTPKT(conn net.Conn, payload []byte) error {
	t := &tpkt.TPKT{Conn: core.NewSocketLayer(conn)}
	_, err := t.Write(payload)
	return err
}

func tlsVersionLabel(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func negotiateFrontRDP(raw net.Conn, frontTLS *cert.TLSManager, settings *config.SettingsType, started time.Time) (*frontRDPConnection, bool) {
	crq, ok := readClientConnectionRequest(raw)
	if !ok {
		return nil, false
	}
	if !clientOfferedTLS(raw.RemoteAddr(), crq) {
		return nil, false
	}
	if !writeFrontConnectionConfirm(raw) {
		return nil, false
	}

	clientTLS, sni, ok := handshakeFrontTLS(raw, frontTLS, started)
	if !ok {
		return nil, false
	}

	hostname, ok := validateFrontSNI(sni, raw.RemoteAddr(), settings)
	if !ok {
		_ = clientTLS.Close()
		return nil, false
	}

	return &frontRDPConnection{
		tlsConn:  clientTLS,
		sni:      sni,
		hostname: hostname,
	}, true
}

func readClientConnectionRequest(raw net.Conn) ([]byte, bool) {
	crq, err := readTPKT(raw)
	if err != nil {
		log.Printf("read client CRQ: %v", err)
		return nil, false
	}
	debugf("client CRQ len=%d", len(crq))
	return crq, true
}

func clientOfferedTLS(remoteAddr net.Addr, crq []byte) bool {
	reqProto, ok := findClientRequestedProtocols(crq)
	debugf("client requested protocols ok=%v value=0x%08x", ok, reqProto)
	if reqProto&(x224.PROTOCOL_HYBRID|x224.PROTOCOL_HYBRID_EX) != 0 {
		debugf("client offered NLA (HYBRID/HYBRID_EX); gateway only supports TLS (PROTOCOL_SSL)")
	}
	if ok && (reqProto&x224.PROTOCOL_SSL) != 0 {
		return true
	}

	log.Printf("client did not offer TLS (ok=%v requested=0x%08x) from %s", ok, reqProto, remoteAddr)
	return false
}

func writeFrontConnectionConfirm(raw net.Conn) bool {
	debugf("sending server CCF select TLS")
	if err := writeTPKT(raw, buildServerCCFSelectTLS()); err != nil {
		log.Printf("write CCF(TLS): %v", err)
		return false
	}
	return true
}

func handshakeFrontTLS(raw net.Conn, frontTLS *cert.TLSManager, started time.Time) (*tls.Conn, string, bool) {
	clientTLS := tls.Server(raw, frontTLS.GetTLSConfig())
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("client tls handshake: %v", err)
		return nil, "", false
	}

	clientState := clientTLS.ConnectionState()
	sni := strings.ToLower(strings.TrimSpace(clientState.ServerName))
	debugf(
		"client TLS established version=%s cipher=0x%04x sni=%q elapsed=%s",
		tlsVersionLabel(clientState.Version),
		clientState.CipherSuite,
		sni,
		time.Since(started),
	)
	return clientTLS, sni, true
}

func validateFrontSNI(sni string, remoteAddr net.Addr, settings *config.SettingsType) (string, bool) {
	frontDomain := strings.TrimSpace(settings.Get(config.FRONT_DOMAIN))
	if frontDomain != "" {
		debugf("enforcing front domain %q", frontDomain)
	}
	if frontDomain != "" && !strings.HasSuffix(sni, frontDomain) {
		log.Printf("client SNI=%q does not match required domain %q from %s", sni, frontDomain, remoteAddr)
		return "", false
	}

	label, ok := getSubdomain(sni, frontDomain)
	if !ok {
		log.Printf("client SNI=%q does not have valid subdomain for domain %q from %s", sni, frontDomain, remoteAddr)
		return "", false
	}

	// The subdomain is an opaque HMAC routing label, not the VM name. Map it
	// back to the real name via the cached VM list; an unknown label is denied.
	secret := []byte(settings.Get(config.SNI_HASH_SECRET))
	hostname, ok := vmNameByLabelLookup(secret, label)
	if !ok {
		log.Printf("client SNI=%q routing label %q from %s did not match any VM", sni, label, remoteAddr)
		return "", false
	}

	debugf("resolved routing label %q to vm=%q", label, hostname)
	return hostname, true
}

func authorizeRDPAccess(remoteAddr net.Addr, sessionManager *session.Manager, sni, hostname string) (string, bool) {
	if sessionManager == nil {
		log.Printf("rdp denied SNI=%q vm=%q remote=%s: session manager unavailable", sni, hostname, remoteAddr)
		return "", false
	}

	owner, hasOwner, err := virt.VMOwner(hostname)
	if err != nil {
		log.Printf("resolve owner for VM %s: %v", hostname, err)
		return "", false
	}
	if !hasOwner {
		log.Printf("rdp denied SNI=%q vm=%q remote=%s: missing VM owner", sni, hostname, remoteAddr)
		return "", false
	}

	clientIP, ok := session.CanonicalClientIP(remoteAddr.String())
	if !ok {
		log.Printf("rdp denied SNI=%q vm=%q remote=%s: invalid client IP", sni, hostname, remoteAddr)
		return "", false
	}
	if !sessionManager.ConsumeRDPConnectGrant(owner, clientIP, hostname) {
		log.Printf("rdp denied SNI=%q vm=%q owner=%q client_ip=%q remote=%s: no unused Connect authorization (owner must click Connect in the dashboard for each connection)", sni, hostname, owner, clientIP, remoteAddr)
		return "", false
	}

	debugf("authorized owner=%q client_ip=%q vm=%q", owner, clientIP, hostname)
	return owner, true
}

func resolveBackendAddr(remoteAddr net.Addr, sni, hostname string) (string, bool) {
	backendIP, err := vmIPAddressLookup(hostname)
	if err != nil {
		log.Printf("get IP of VM %s: %v", hostname, err)
		return "", false
	}
	debugf("resolved VM %q to IP %q", hostname, backendIP)
	// The virt layer only returns an authoritative DHCP-lease address inside the
	// VM NAT subnet here (see domainRoutingIP); an empty result means there is no
	// trusted route, so fail closed rather than dial a guest-supplied address.
	if backendIP == "" {
		log.Printf("no route for SNI=%q from %s", sni, remoteAddr)
		return "", false
	}

	backendAddr := net.JoinHostPort(backendIP, "3389")
	log.Printf("client %s SNI=%q -> %s", remoteAddr, sni, backendAddr)
	return backendAddr, true
}

func dialBackendRDP(backendAddr, sni string, settings *config.SettingsType) (*tls.Conn, bool) {
	backendRaw, err := dialBackendTCP(backendAddr, settings)
	if err != nil {
		return nil, false
	}

	backendTLS, err := negotiateBackendTLS(backendRaw, backendAddr, sni)
	if err != nil {
		_ = backendRaw.Close()
		return nil, false
	}
	return backendTLS, true
}

func dialBackendTCP(backendAddr string, settings *config.SettingsType) (net.Conn, error) {
	d := net.Dialer{Timeout: settings.GetDuration(config.TIMEOUT)}
	debugf("dialing backend %s", backendAddr)

	backendRaw, err := d.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("dial backend %s: %v", backendAddr, err)
		return nil, err
	}

	debugf("backend TCP connected to %s", backendAddr)
	_ = backendRaw.SetDeadline(time.Now().Add(settings.GetDuration(config.TIMEOUT)))
	return backendRaw, nil
}

func negotiateBackendTLS(backendRaw net.Conn, backendAddr, sni string) (*tls.Conn, error) {
	debugf("sending backend CRQ select TLS")
	if err := writeTPKT(backendRaw, buildClientCRQSelectTLS()); err != nil {
		log.Printf("write backend CRQ: %v", err)
		return nil, err
	}

	ccfBackend, err := readTPKT(backendRaw)
	if err != nil {
		log.Printf("read backend CCF: %v", err)
		return nil, err
	}

	sel, ok := findServerSelectedProtocol(ccfBackend)
	debugf("backend selected protocol ok=%v value=0x%08x", ok, sel)
	if !ok {
		log.Printf("backend did not include RDP_NEG_RSP (cannot confirm TLS); backend=%s", backendAddr)
		return nil, fmt.Errorf("backend did not confirm TLS")
	}
	if sel != x224.PROTOCOL_SSL {
		log.Printf("backend did not select TLS (selected=0x%08x) backend=%s", sel, backendAddr)
		return nil, fmt.Errorf("backend did not select TLS")
	}

	backendTLS := tls.Client(backendRaw, backendTLSConfig(sni))
	if err := backendTLS.Handshake(); err != nil {
		log.Printf("backend tls handshake: %v (backend=%s)", err, backendAddr)
		return nil, err
	}

	backendState := backendTLS.ConnectionState()
	debugf(
		"backend TLS established version=%s cipher=0x%04x server_name=%q",
		tlsVersionLabel(backendState.Version),
		backendState.CipherSuite,
		backendState.ServerName,
	)
	return backendTLS, nil
}

func backendTLSConfig(sni string) *tls.Config {
	backendTLSCfg := &tls.Config{
		InsecureSkipVerify: true, // ignore backend cert chain + hostname
		MinVersion:         tls.VersionTLS12,
	}
	if sni != "" && sni != "*" {
		backendTLSCfg.ServerName = sni
	}
	return backendTLSCfg
}
