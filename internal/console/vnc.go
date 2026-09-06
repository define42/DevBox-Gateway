package console

import (
	"errors"
	"io"
	"log"
	"net"
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

// vncReadLimit caps a single inbound VNC client frame. noVNC input events
// (pointer/keyboard, clipboard cut-text) are small; the ceiling only bounds
// worst-case memory. gorilla defaults to no limit.
const vncReadLimit = 1 << 20 // 1 MiB

// HandleDashboardVNCWS serves the VNC websocket endpoint.
func HandleDashboardVNCWS(sessionManager *session.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, authorization, ok := authorizeDashboardConnection(r.Context(), sessionManager)
		if !ok {
			log.Printf("reject VNC websocket from %s: no authenticated session", strconv.Quote(r.RemoteAddr))
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}

		name, err := parseDashboardVMPathParam(chi.URLParam(r, "name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		debugf("vnc: request from %s user=%q vm=%q", r.RemoteAddr, user.Name, name)

		owned, err := virt.UserOwnsVM(name, user.Name)
		if err != nil {
			writeDashboardVNCOwnershipError(w, name, user.Name, err)
			return
		}
		if !owned {
			writeDashboardVNCOwnershipError(w, name, user.Name, nil)
			return
		}
		debugf("vnc: ownership confirmed for vm %q; opening VNC backend", name)

		vncConn, err := openDashboardVNCSocket(name)
		if err != nil {
			writeDashboardVNCSocketError(w, name, err)
			return
		}
		// Opening noVNC counts as use for auto-shutdown.
		virt.MarkVMUsed(name)
		debugf("vnc: backend connected for vm %q (%s); upgrading websocket", name, vncConn.RemoteAddr())

		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin: sameOriginWebsocketRequest,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(upgradeResponseWriter("vnc", name, w), r, nil)
		if err != nil {
			_ = vncConn.Close()
			log.Printf("upgrade dashboard websocket for vm %s failed: %v", strconv.Quote(name), err)
			return
		}
		debugf("vnc: websocket upgraded for vm %q (remote %s)", name, r.RemoteAddr)
		unregisterConnection, ok := sessionManager.RegisterUserConnection(authorization, func() {
			_ = ws.Close()
			_ = vncConn.Close()
		})
		if !ok {
			rejectDashboardConnection("vnc", user.Name, ws)
			_ = vncConn.Close()
			return
		}
		defer unregisterConnection()

		defer auditConsoleConnection(r.Context(), user, r.RemoteAddr, name, audit.ProtocolNoVNC)()

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
		log.Printf("reject VNC for vm %s: VM is not running", strconv.Quote(name))
		http.Error(w, "VM must be running for VNC access.", http.StatusConflict)
	case errors.Is(err, virt.ErrVNCNotConfigured):
		log.Printf("reject VNC for vm %s: no VNC graphics device configured", strconv.Quote(name))
		http.Error(w, "VNC is not available for this VM.", http.StatusConflict)
	case errors.Is(err, virt.ErrVNCNotReady):
		log.Printf("reject VNC for vm %s: VNC socket not ready yet", strconv.Quote(name))
		http.Error(w, "VNC is not ready yet.", http.StatusConflict)
	default:
		log.Printf("open VNC for vm %s failed: %v", strconv.Quote(name), err)
		http.Error(w, "Failed to open VNC session.", http.StatusInternalServerError)
	}
}

func writeDashboardVNCOwnershipError(w http.ResponseWriter, name, username string, err error) {
	if err != nil {
		log.Printf("verify VNC access for user %s vm %s failed: %v", strconv.Quote(username), strconv.Quote(name), err)
		http.Error(w, "Unable to verify VM ownership.", http.StatusInternalServerError)
		return
	}

	log.Printf("user %s attempted to access VNC for vm %s not owned by them", strconv.Quote(username), strconv.Quote(name))
	http.Error(w, "You do not have permission to access this VM VNC session.", http.StatusForbidden)
}

func bridgeDashboardSocket(channel, name string, ws *websocket.Conn, backendConn net.Conn) {
	log.Printf("dashboard %s websocket for vm %s established; bridging to backend", channel, strconv.Quote(name))
	defer func() {
		log.Printf("dashboard %s websocket for vm %s closed", channel, strconv.Quote(name))
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
		log.Printf("dashboard %s bridge for vm %s ended with error: %v", channel, strconv.Quote(name), err)
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
