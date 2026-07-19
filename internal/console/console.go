// Package console handles dashboard terminal and VNC websocket endpoints.
package console

import (
	"bufio"
	"devboxgateway/internal/session"
	"devboxgateway/internal/virt"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

// debugLogging gates verbose per-connection serial/VNC console diagnostics. It is
// enabled from main when DEBUG_CONNECTIONS is set so the noisy step-by-step and
// byte-count logging stays off in normal operation.
var debugLogging atomic.Bool //nolint:gochecknoglobals // package-level debug toggle set once at startup

// SetDebugLogging toggles verbose serial/VNC console debug logging.
func SetDebugLogging(enabled bool) {
	debugLogging.Store(enabled)
}

func debugf(format string, args ...any) {
	if debugLogging.Load() {
		log.Printf("console-debug: "+format, args...)
	}
}

// bridgeBufferSize is the read-chunk size when streaming console/VNC data to the
// websocket. It matches the SSH channel's max packet (32 KiB), so a framebuffer
// update is copied in far fewer reads/websocket frames than the previous 4 KiB,
// reducing per-frame overhead over the tunnel without exceeding a single SSH
// packet.
const bridgeBufferSize = 32 * 1024

const (
	// wsWriteWait bounds a single websocket write — a data frame or a keepalive
	// ping. A write that stalls longer than this (a dead or wedged peer, or a
	// full send buffer) fails the pump and tears the bridge down instead of
	// blocking a goroutine and its libvirt stream indefinitely. This is the only
	// liveness bound over the SSH reverse tunnel, where socket-level deadlines are
	// no-ops (see internal/sshtunnel).
	wsWriteWait = 15 * time.Second

	// wsPongWait bounds how long the gateway waits to hear anything from the peer
	// (a data frame or a pong). The read deadline is refreshed on every pong and
	// every received message; if it elapses the read fails and the bridge closes,
	// reclaiming the goroutines and the backend console/VNC connection.
	wsPongWait = 60 * time.Second

	// wsPingPeriod is how often the gateway sends a keepalive ping. It is shorter
	// than wsPongWait so a live peer always answers before the read deadline; the
	// conventional gorilla ratio is ~9/10.
	wsPingPeriod = (wsPongWait * 9) / 10
)

const (
	// serialReadLimit caps a single inbound serial-console frame. Terminal input
	// is keystrokes, so a modest ceiling is ample while preventing an
	// authenticated client from forcing the gateway to buffer an arbitrarily large
	// frame in memory (a single-user OOM DoS). gorilla defaults to no limit.
	serialReadLimit = 1 << 20 // 1 MiB
	// vncReadLimit caps a single inbound VNC client frame. noVNC input events
	// (pointer/keyboard, clipboard cut-text) are small; the ceiling only bounds
	// worst-case memory.
	vncReadLimit = 1 << 20 // 1 MiB
)

// configureWebsocketKeepalive installs the inbound frame-size cap, an initial
// read deadline, and a pong handler that refreshes it. Pair it with
// pingWebsocketUntil (run in its own goroutine) so a peer that vanishes without
// a TCP FIN — laptop sleep, dropped network, half-open NAT — is detected and the
// bridge is torn down instead of leaking the goroutines and the libvirt stream.
func configureWebsocketKeepalive(ws *websocket.Conn, readLimit int64) {
	ws.SetReadLimit(readLimit)
	_ = ws.SetReadDeadline(time.Now().Add(wsPongWait))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(wsPongWait))
	})
}

// pingWebsocketUntil sends a keepalive ping every wsPingPeriod until done is
// closed. A ping that cannot be written within wsWriteWait closes the socket so
// the read/write pumps unblock and the bridge tears down. WriteControl is safe
// to call concurrently with the single data writer, per gorilla's contract.
func pingWebsocketUntil(ws *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(wsPingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(wsWriteWait)); err != nil {
				_ = ws.Close()
				return
			}
		}
	}
}

// HandleDashboardConsoleWS serves the serial console websocket endpoint.
func HandleDashboardConsoleWS(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessionManager.UserFromContext(r.Context())
		if !ok {
			log.Printf("reject serial console websocket from %s: no authenticated session", r.RemoteAddr)
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}

		name, err := parseDashboardVMPathParam(chi.URLParam(r, "name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		debugf("serial: request from %s user=%q vm=%q", r.RemoteAddr, user.GetName(), name)

		owned, err := virt.UserOwnsVM(name, user.GetName())
		if err != nil {
			writeDashboardConsoleOwnershipError(w, name, user.GetName(), err)
			return
		}
		if !owned {
			writeDashboardConsoleOwnershipError(w, name, user.GetName(), nil)
			return
		}
		debugf("serial: ownership confirmed for vm %q; opening libvirt console", name)

		// The serial socket is libvirt-managed; the gateway cannot connect to its
		// path directly, so OpenSerialConsole has libvirt stream the console (same
		// reason VNC uses OpenVNCConn).
		console, err := virt.OpenSerialConsole(name)
		if err != nil {
			writeDashboardSerialSocketError(w, name, err)
			return
		}
		debugf("serial: libvirt console opened for vm %q; upgrading websocket", name)

		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin: sameOriginWebsocketRequest,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(upgradeResponseWriter("serial", name, w), r, nil)
		if err != nil {
			_ = console.Close()
			log.Printf("upgrade dashboard websocket for vm %q failed: %v", name, err)
			return
		}
		debugf("serial: websocket upgraded for vm %q (remote %s)", name, r.RemoteAddr)
		unregisterConnection := sessionManager.RegisterUserConnection(user.GetName(), func() {
			_ = ws.Close()
			_ = console.Interrupt()
		})
		defer unregisterConnection()

		bridgeSerialConsole(name, ws, console)
	}
}

func writeDashboardSerialSocketError(w http.ResponseWriter, name string, err error) {
	switch {
	case errors.Is(err, virt.ErrSerialConsoleNotRunning):
		log.Printf("reject serial console for vm %q: VM is not running", name)
		http.Error(w, "VM must be running for terminal access.", http.StatusConflict)
	case errors.Is(err, virt.ErrSerialConsoleNotConfigured):
		log.Printf("reject serial console for vm %q: no serial console device configured", name)
		http.Error(w, "Serial terminal is not available for this VM.", http.StatusConflict)
	case errors.Is(err, virt.ErrSerialConsoleNotReady):
		log.Printf("reject serial console for vm %q: console not ready yet", name)
		http.Error(w, "Serial terminal is not ready yet.", http.StatusConflict)
	default:
		log.Printf("open serial console for vm %q failed: %v", name, err)
		http.Error(w, "Failed to open serial terminal.", http.StatusInternalServerError)
	}
}

// HandleDashboardVNCWS serves the VNC websocket endpoint.
func HandleDashboardVNCWS(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessionManager.UserFromContext(r.Context())
		if !ok {
			log.Printf("reject VNC websocket from %s: no authenticated session", r.RemoteAddr)
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}

		name, err := parseDashboardVMPathParam(chi.URLParam(r, "name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		debugf("vnc: request from %s user=%q vm=%q", r.RemoteAddr, user.GetName(), name)

		owned, err := virt.UserOwnsVM(name, user.GetName())
		if err != nil {
			writeDashboardVNCOwnershipError(w, name, user.GetName(), err)
			return
		}
		if !owned {
			writeDashboardVNCOwnershipError(w, name, user.GetName(), nil)
			return
		}
		debugf("vnc: ownership confirmed for vm %q; opening VNC backend", name)

		vncConn, err := openDashboardVNCSocket(name)
		if err != nil {
			writeDashboardVNCSocketError(w, name, err)
			return
		}
		debugf("vnc: backend connected for vm %q (%s); upgrading websocket", name, vncConn.RemoteAddr())

		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin: sameOriginWebsocketRequest,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(upgradeResponseWriter("vnc", name, w), r, nil)
		if err != nil {
			_ = vncConn.Close()
			log.Printf("upgrade dashboard websocket for vm %q failed: %v", name, err)
			return
		}
		debugf("vnc: websocket upgraded for vm %q (remote %s)", name, r.RemoteAddr)
		unregisterConnection := sessionManager.RegisterUserConnection(user.GetName(), func() {
			_ = ws.Close()
			_ = vncConn.Close()
		})
		defer unregisterConnection()

		bridgeDashboardSocket("vnc", name, ws, vncConn)
	}
}

// pingReadLimit caps the size of an RTT probe message. Probes carry only a tiny
// client-generated token, so a small limit is plenty and keeps the echo loop
// from buffering anything large.
const pingReadLimit = 1024

// HandleDashboardPingWS serves a lightweight echo websocket the dashboard uses to
// measure live round-trip time to the gateway. It keeps the connection open and
// echoes each client message straight back so the browser can time the round
// trip. Browsers do not expose WebSocket protocol-level ping/pong to JavaScript,
// so the probe is an application-level echo. No VM ownership is involved; it only
// requires an authenticated session like the other dashboard sockets.
func HandleDashboardPingWS(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessionManager.UserFromContext(r.Context())
		if !ok {
			log.Printf("reject ping websocket from %s: no authenticated session", r.RemoteAddr)
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}

		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin: sameOriginWebsocketRequest,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(upgradeResponseWriter("ping", "rtt", w), r, nil)
		if err != nil {
			log.Printf("upgrade dashboard ping websocket failed: %v", err)
			return
		}
		unregisterConnection := sessionManager.RegisterUserConnection(user.GetName(), func() {
			_ = ws.Close()
		})
		defer unregisterConnection()

		bridgePingSocket(ws)
	}
}

// bridgePingSocket echoes every client probe back until the connection closes.
func bridgePingSocket(ws *websocket.Conn) {
	defer func() { _ = ws.Close() }()

	configureWebsocketKeepalive(ws, pingReadLimit)

	done := make(chan struct{})
	defer close(done)
	go pingWebsocketUntil(ws, done)

	for {
		messageType, payload, err := ws.ReadMessage()
		if err != nil {
			return
		}
		_ = ws.SetReadDeadline(time.Now().Add(wsPongWait))
		if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
			continue
		}
		// No per-write deadline here: the echo is a tiny control payload, and a
		// stalled write is already bounded by pingWebsocketUntil, whose periodic
		// WriteControl sets a write deadline on the shared connection.
		if err := ws.WriteMessage(messageType, payload); err != nil {
			return
		}
	}
}

func openDashboardVNCSocket(name string) (net.Conn, error) {
	// The VNC socket is libvirt-managed (inside libvirt's per-domain runtime dir).
	// OpenVNCConn dials it directly when reachable and otherwise has libvirt open
	// it and hand back a connected fd.
	return virt.OpenVNCConn(name)
}

func writeDashboardVNCSocketError(w http.ResponseWriter, name string, err error) {
	switch {
	case errors.Is(err, virt.ErrVNCNotRunning):
		log.Printf("reject VNC for vm %q: VM is not running", name)
		http.Error(w, "VM must be running for VNC access.", http.StatusConflict)
	case errors.Is(err, virt.ErrVNCNotConfigured):
		log.Printf("reject VNC for vm %q: no VNC graphics device configured", name)
		http.Error(w, "VNC is not available for this VM.", http.StatusConflict)
	case errors.Is(err, virt.ErrVNCNotReady):
		log.Printf("reject VNC for vm %q: VNC socket not ready yet", name)
		http.Error(w, "VNC is not ready yet.", http.StatusConflict)
	default:
		log.Printf("open VNC for vm %q failed: %v", name, err)
		http.Error(w, "Failed to open VNC session.", http.StatusInternalServerError)
	}
}

func writeDashboardConsoleOwnershipError(w http.ResponseWriter, name, username string, err error) {
	if err != nil {
		log.Printf("verify terminal access for user %q vm %q failed: %v", username, name, err)
		http.Error(w, "Unable to verify VM ownership.", http.StatusInternalServerError)
		return
	}

	log.Printf("user %q attempted to access terminal for vm %q not owned by them", username, name)
	http.Error(w, "You do not have permission to access this VM terminal.", http.StatusForbidden)
}

func writeDashboardVNCOwnershipError(w http.ResponseWriter, name, username string, err error) {
	if err != nil {
		log.Printf("verify VNC access for user %q vm %q failed: %v", username, name, err)
		http.Error(w, "Unable to verify VM ownership.", http.StatusInternalServerError)
		return
	}

	log.Printf("user %q attempted to access VNC for vm %q not owned by them", username, name)
	http.Error(w, "You do not have permission to access this VM VNC session.", http.StatusForbidden)
}

// bridgeSerialConsole proxies a libvirt serial console stream to the websocket.
// The stream cannot be freed while a Recv/Send is in flight, so on shutdown it
// only Interrupts (to unblock both goroutines) and frees the session via Close
// after both have returned.
func bridgeSerialConsole(name string, ws *websocket.Conn, console *virt.SerialConsole) {
	log.Printf("dashboard serial websocket for vm %q established; bridging to console", name)
	defer log.Printf("dashboard serial websocket for vm %q closed", name)

	configureWebsocketKeepalive(ws, serialReadLimit)

	var wg sync.WaitGroup
	var stopOnce sync.Once
	done := make(chan struct{})
	stop := func() {
		stopOnce.Do(func() {
			close(done)
			_ = console.Interrupt()
			_ = ws.Close()
		})
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		pingWebsocketUntil(ws, done)
	}()
	go func() {
		defer wg.Done()
		defer stop()
		pumpConsoleToWebsocket(name, ws, console)
	}()
	go func() {
		defer wg.Done()
		defer stop()
		pumpWebsocketToConsole(name, ws, console)
	}()

	wg.Wait()
	_ = console.Close()
}

func pumpConsoleToWebsocket(name string, ws *websocket.Conn, console *virt.SerialConsole) {
	buf := make([]byte, bridgeBufferSize)
	var total int64
	defer func() { debugf("serial: console->ws for vm %q ended after %d bytes", name, total) }()
	for {
		n, err := console.Recv(buf)
		if n > 0 {
			if total == 0 {
				debugf("serial: first %d bytes console->ws for vm %q: %q", n, name, previewBytes(buf[:n]))
			}
			total += int64(n)
			_ = ws.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				debugf("serial: console->ws write failed for vm %q after %d bytes: %v", name, total, werr)
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !isExpectedConsoleClose(err) {
				log.Printf("dashboard terminal recv for vm %q ended: %v", name, err)
			}
			return
		}
	}
}

func pumpWebsocketToConsole(name string, ws *websocket.Conn, console *virt.SerialConsole) {
	var total int64
	defer func() { debugf("serial: ws->console for vm %q ended after %d bytes", name, total) }()
	for {
		messageType, payload, err := ws.ReadMessage()
		if err != nil {
			return
		}
		_ = ws.SetReadDeadline(time.Now().Add(wsPongWait))
		if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
			continue
		}
		total += int64(len(payload))
		if err := sendAllToConsole(console, payload); err != nil {
			return
		}
	}
}

func sendAllToConsole(console *virt.SerialConsole, payload []byte) error {
	for len(payload) > 0 {
		n, err := console.Send(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func bridgeDashboardSocket(channel, name string, ws *websocket.Conn, backendConn net.Conn) {
	log.Printf("dashboard %s websocket for vm %q established; bridging to backend", channel, name)
	defer func() {
		log.Printf("dashboard %s websocket for vm %q closed", channel, name)
		_ = ws.Close()
		_ = backendConn.Close()
	}()

	configureWebsocketKeepalive(ws, vncReadLimit)

	// done stops the ping loop. It is closed last (LIFO: this defer runs before
	// the conn-closing defer above), so the ping goroutine exits promptly once
	// the bridge is torn down.
	done := make(chan struct{})
	defer close(done)
	go pingWebsocketUntil(ws, done)

	errCh := make(chan error, 2)
	var closeOnce sync.Once
	closeAll := func() {
		_ = backendConn.Close()
		_ = ws.Close()
	}

	go func() {
		errCh <- copySocketToWebsocket(channel, name, ws, backendConn)
		closeOnce.Do(closeAll)
	}()

	go func() {
		errCh <- copyWebsocketToSocket(channel, name, ws, backendConn)
		closeOnce.Do(closeAll)
	}()

	if err := <-errCh; err != nil && !isExpectedConsoleClose(err) {
		log.Printf("dashboard %s bridge for vm %q ended with error: %v", channel, name, err)
	}
}

func copySocketToWebsocket(channel, name string, ws *websocket.Conn, backendConn net.Conn) error {
	buf := make([]byte, bridgeBufferSize)
	var total int64
	defer func() { debugf("%s: backend->ws for vm %q ended after %d bytes", channel, name, total) }()
	for {
		n, err := backendConn.Read(buf)
		if n > 0 {
			if total == 0 {
				debugf("%s: first %d bytes backend->ws for vm %q: %q", channel, name, n, previewBytes(buf[:n]))
			}
			total += int64(n)
			_ = ws.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if writeErr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
				debugf("%s: backend->ws write failed for vm %q after %d bytes: %v", channel, name, total, writeErr)
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func copyWebsocketToSocket(channel, name string, ws *websocket.Conn, backendConn net.Conn) error {
	var total int64
	defer func() { debugf("%s: ws->backend for vm %q ended after %d bytes", channel, name, total) }()
	for {
		messageType, payload, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		_ = ws.SetReadDeadline(time.Now().Add(wsPongWait))
		if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
			continue
		}
		total += int64(len(payload))
		if err := writeAll(backendConn, payload); err != nil {
			return err
		}
	}
}

// previewBytes returns a short, printable preview of a stream's first bytes for
// debug logging (e.g. the "RFB 003.008" VNC greeting), capped so the log stays
// readable and with non-printable bytes shown as '.'.
func previewBytes(b []byte) string {
	const maxPreview = 32
	if len(b) > maxPreview {
		b = b[:maxPreview]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			out[i] = '.'
			continue
		}
		out[i] = c
	}
	return string(out)
}

func isExpectedConsoleClose(err error) bool {
	return websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived)
}

// hijackableResponseWriter unwraps middleware response-writer wrappers until it
// reaches one that implements http.Hijacker. The session manager's LoadAndSave
// wraps the writer (to buffer the body and commit the session cookie) in a type
// that is not itself an http.Hijacker; it only exposes the underlying writer via
// Unwrap(). gorilla/websocket's Upgrade type-asserts the writer to
// http.Hijacker directly and does not follow Go's Unwrap() convention, so
// without this every console/VNC upgrade fails with "response does not implement
// http.Hijacker" (HTTP 500) and the browser sees the socket close with code
// 1006. Upgrading on the unwrapped writer is safe here because the handlers only
// read the session, so no session cookie needs to be written on the 101 response.
func hijackableResponseWriter(w http.ResponseWriter) http.ResponseWriter {
	for {
		if _, ok := w.(http.Hijacker); ok {
			return w
		}
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		w = unwrapper.Unwrap()
	}
}

// upgradeResponseWriter returns the writer handed to gorilla's Upgrade. It
// unwraps to the underlying http.Hijacker and, when debug logging is on, wraps
// it to trace exactly where a WebSocket upgrade blocks: the Hijack call and the
// first network write (the 101 handshake). This is the diagnostic for upgrades
// that never return over the SSH tunnel.
func upgradeResponseWriter(channel, name string, w http.ResponseWriter) http.ResponseWriter {
	hijackable := hijackableResponseWriter(w)
	if !debugLogging.Load() {
		return hijackable
	}
	return &debugUpgradeWriter{ResponseWriter: hijackable, channel: channel, name: name}
}

// debugUpgradeWriter logs around Hijack and wraps the hijacked conn so the first
// post-upgrade write (the 101 response) is traced start-to-finish.
type debugUpgradeWriter struct {
	http.ResponseWriter

	channel string
	name    string
}

func (w *debugUpgradeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *debugUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("debugUpgradeWriter: underlying response writer is not an http.Hijacker")
	}
	debugf("%s: hijacking connection for vm %q", w.channel, w.name)
	conn, brw, err := hj.Hijack()
	debugf("%s: hijack returned for vm %q (err=%v)", w.channel, w.name, err)
	if err != nil {
		return conn, brw, err
	}
	return &debugConn{Conn: conn, channel: w.channel, name: w.name}, brw, nil
}

// debugConn logs the start and completion of the first write on a hijacked
// connection. If the "starting" line appears without the "returned" line, the
// write to the SSH-channel-backed conn is blocking.
type debugConn struct {
	net.Conn

	channel string
	name    string
	logged  atomic.Bool
}

func (c *debugConn) Write(p []byte) (int, error) {
	first := c.logged.CompareAndSwap(false, true)
	if first {
		debugf("%s: first post-upgrade write of %d bytes for vm %q starting (101 handshake)", c.channel, len(p), c.name)
	}
	n, err := c.Conn.Write(p)
	if first {
		debugf("%s: first post-upgrade write returned for vm %q (n=%d err=%v)", c.channel, c.name, n, err)
	}
	return n, err
}

func sameOriginWebsocketRequest(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}

	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}

	return strings.EqualFold(originURL.Host, r.Host)
}

func parseDashboardVMPathParam(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("vm name is required")
	}
	if len(name) > 128 {
		return "", fmt.Errorf("vm name is too long")
	}
	return name, nil
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}
