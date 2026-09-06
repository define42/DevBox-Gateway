// Package console handles the dashboard's websocket endpoints: the serial
// terminal (serial.go), VNC (vnc.go), and the shared control socket
// (dashboard_socket.go). This file holds the websocket plumbing they share.
package console

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/vmname"

	"github.com/gorilla/websocket"
)

// bridgeBufferSize is the read-chunk size when streaming console/VNC data to the
// websocket. A 32 KiB chunk copies a framebuffer update in far fewer
// reads/websocket frames than the previous 4 KiB, reducing per-frame overhead.
const bridgeBufferSize = 32 * 1024

const (
	// wsWriteWait bounds a single websocket write — a data frame or a keepalive
	// ping. A write that stalls longer than this (a dead or wedged peer, or a
	// full send buffer) fails the pump and tears the bridge down instead of
	// blocking a goroutine and its libvirt stream indefinitely.
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

func auditConsoleConnection(ctx context.Context, user *identity.User, remoteAddr, name, protocol string) func() {
	clientIP, _ := session.CanonicalClientIP(remoteAddr)
	connectedAt := time.Now()
	audit.Log(ctx, audit.Event{
		Action:        audit.ActionConnectionConnect,
		User:          user.Name,
		SourceIP:      clientIP,
		VM:            name,
		Protocol:      protocol,
		Administrator: user.IsAdmin,
	})
	return func() {
		audit.Log(ctx, audit.Event{
			Action:        audit.ActionConnectionDisconnect,
			User:          user.Name,
			SourceIP:      clientIP,
			VM:            name,
			Protocol:      protocol,
			Administrator: user.IsAdmin,
			Duration:      time.Since(connectedAt),
		})
	}
}

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

// rejectOverUserConnectionLimit closes a just-upgraded websocket whose user
// already holds the maximum number of registered live connections
// (MAX_CONNECTIONS_PER_USER), telling the browser why via a policy-violation
// close frame. Refusing here bounds how much of the gateway-wide
// front-connection budget one authenticated user can occupy.
func rejectOverUserConnectionLimit(kind, username string, ws *websocket.Conn) {
	log.Printf("reject %s websocket for user %q: per-user connection limit reached", kind, username)
	deadline := time.Now().Add(wsWriteWait)
	_ = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "Too many open connections for this user."), deadline)
	_ = ws.Close()
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
// first network write (the 101 handshake).
func upgradeResponseWriter(channel, name string, w http.ResponseWriter) http.ResponseWriter {
	hijackable := hijackableResponseWriter(w)
	if !debugLogging.Load() {
		return hijackable
	}
	return &debugUpgradeWriter{ResponseWriter: hijackable, channel: channel, name: name}
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
	if len(name) > vmname.MaxVMNameLength {
		return "", fmt.Errorf("vm name is too long")
	}
	return name, nil
}
