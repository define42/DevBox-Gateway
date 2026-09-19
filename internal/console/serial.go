package console

import (
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

// serialReadLimit caps a single inbound serial-console frame. Terminal input
// is keystrokes, so a modest ceiling is ample while preventing an
// authenticated client from forcing the gateway to buffer an arbitrarily large
// frame in memory (a single-user OOM DoS). gorilla defaults to no limit.
const serialReadLimit = 1 << 20 // 1 MiB

// HandleDashboardConsoleWS serves the serial console websocket endpoint.
func HandleDashboardConsoleWS(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, authorization, ok := authorizeDashboardConnection(r.Context(), sessionManager)
		if !ok {
			log.Printf("reject serial console websocket from %s: no authenticated session", strconv.Quote(r.RemoteAddr))
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}

		name, err := parseDashboardVMPathParam(chi.URLParam(r, "name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		debugf("serial: request from %s user=%q vm=%q", r.RemoteAddr, user.Name, name)

		owned, err := virt.UserOwnsVM(name, user.Name)
		if err != nil {
			writeDashboardConsoleOwnershipError(w, name, user.Name, err)
			return
		}
		if !owned {
			writeDashboardConsoleOwnershipError(w, name, user.Name, nil)
			return
		}
		// Complete handshake and origin validation before OpenSerialConsole,
		// whose forced open would otherwise evict an existing terminal even for
		// an ordinary GET or rejected WebSocket request.
		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin:      sameOriginWebsocketRequest,
			HandshakeTimeout: wsWriteWait,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(upgradeResponseWriter("serial", name, w), r, nil)
		if err != nil {
			log.Printf("upgrade dashboard websocket for vm %s failed: %v", strconv.Quote(name), err)
			return
		}
		defer func() { _ = ws.Close() }()
		debugf("serial: websocket upgraded for vm %q (remote %s)", name, r.RemoteAddr)

		// The serial socket is libvirt-managed; the gateway cannot connect to its
		// path directly, so OpenSerialConsole has libvirt stream the console.
		console, err := virt.OpenSerialConsole(name)
		if err != nil {
			closeDashboardSerialSocketError(ws, name, err)
			return
		}
		// Opening the serial terminal counts as use for auto-shutdown.
		virt.MarkVMUsed(name)
		debugf("serial: libvirt console opened for vm %q", name)
		unregisterConnection, ok := sessionManager.RegisterUserConnection(authorization, func() {
			_ = ws.Close()
			_ = console.Interrupt()
		})
		if !ok {
			rejectDashboardConnection("serial", user.Name, ws)
			_ = console.Close()
			return
		}
		defer unregisterConnection()

		defer auditConsoleConnection(r.Context(), user, r.RemoteAddr, name, audit.ProtocolSerial)()

		bridgeSerialConsole(name, ws, console)
	}
}

func closeDashboardSerialSocketError(ws *websocket.Conn, name string, err error) {
	code := websocket.CloseTryAgainLater
	var message string
	switch {
	case errors.Is(err, virt.ErrSerialConsoleNotRunning):
		log.Printf("reject serial console for vm %s: VM is not running", strconv.Quote(name))
		message = "VM must be running for terminal access."
	case errors.Is(err, virt.ErrSerialConsoleNotConfigured):
		log.Printf("reject serial console for vm %s: no serial console device configured", strconv.Quote(name))
		message = "Serial terminal is not available for this VM."
	case errors.Is(err, virt.ErrSerialConsoleNotReady):
		log.Printf("reject serial console for vm %s: console not ready yet", strconv.Quote(name))
		message = "Serial terminal is not ready yet."
	default:
		log.Printf("open serial console for vm %s failed: %v", strconv.Quote(name), err)
		message = "Failed to open serial terminal."
		code = websocket.CloseInternalServerErr
	}
	_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, message), time.Now().Add(wsWriteWait))
}

func writeDashboardConsoleOwnershipError(w http.ResponseWriter, name, username string, err error) {
	if err != nil {
		log.Printf("verify terminal access for user %s vm %s failed: %v", strconv.Quote(username), strconv.Quote(name), err)
		http.Error(w, "Unable to verify VM ownership.", http.StatusInternalServerError)
		return
	}

	log.Printf("user %s attempted to access terminal for vm %s not owned by them", strconv.Quote(username), strconv.Quote(name))
	http.Error(w, "You do not have permission to access this VM terminal.", http.StatusForbidden)
}

// bridgeSerialConsole proxies a libvirt serial console stream to the websocket.
// The stream cannot be freed while a Recv/Send is in flight, so on shutdown it
// only Interrupts (to unblock both goroutines) and frees the session via Close
// after both have returned.
func bridgeSerialConsole(name string, ws *websocket.Conn, console *virt.SerialConsole) {
	log.Printf("dashboard serial websocket for vm %s established; bridging to console", strconv.Quote(name))
	defer log.Printf("dashboard serial websocket for vm %s closed", strconv.Quote(name))

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
				log.Printf("dashboard terminal recv for vm %s ended: %v", strconv.Quote(name), err)
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
