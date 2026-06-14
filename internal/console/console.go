// Package console handles dashboard terminal and VNC websocket endpoints.
package console

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
	"strings"
	"sync"
	"sync/atomic"

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

		ws, err := dashboardSocketUpgrader.Upgrade(hijackableResponseWriter(w), r, nil)
		if err != nil {
			_ = console.Close()
			log.Printf("upgrade dashboard websocket for vm %q failed: %v", name, err)
			return
		}
		debugf("serial: websocket upgraded for vm %q (remote %s)", name, r.RemoteAddr)

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

		ws, err := dashboardSocketUpgrader.Upgrade(hijackableResponseWriter(w), r, nil)
		if err != nil {
			_ = vncConn.Close()
			log.Printf("upgrade dashboard websocket for vm %q failed: %v", name, err)
			return
		}
		debugf("vnc: websocket upgraded for vm %q (remote %s)", name, r.RemoteAddr)

		bridgeDashboardSocket("vnc", name, ws, vncConn)
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

	var wg sync.WaitGroup
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			_ = console.Interrupt()
			_ = ws.Close()
		})
	}

	wg.Add(2)
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
	buf := make([]byte, 4096)
	var total int64
	defer func() { debugf("serial: console->ws for vm %q ended after %d bytes", name, total) }()
	for {
		n, err := console.Recv(buf)
		if n > 0 {
			if total == 0 {
				debugf("serial: first %d bytes console->ws for vm %q: %q", n, name, previewBytes(buf[:n]))
			}
			total += int64(n)
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
	buf := make([]byte, 4096)
	var total int64
	defer func() { debugf("%s: backend->ws for vm %q ended after %d bytes", channel, name, total) }()
	for {
		n, err := backendConn.Read(buf)
		if n > 0 {
			if total == 0 {
				debugf("%s: first %d bytes backend->ws for vm %q: %q", channel, name, n, previewBytes(buf[:n]))
			}
			total += int64(n)
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
