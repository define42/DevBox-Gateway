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
	"os"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

// HandleDashboardConsoleWS serves the serial console websocket endpoint.
func HandleDashboardConsoleWS(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessionManager.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}

		name, err := parseDashboardVMPathParam(chi.URLParam(r, "name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		owned, err := virt.UserOwnsVM(name, user.GetName())
		if err != nil {
			writeDashboardConsoleOwnershipError(w, name, user.GetName(), err)
			return
		}
		if !owned {
			writeDashboardConsoleOwnershipError(w, name, user.GetName(), nil)
			return
		}

		serialConn, err := openDashboardSerialSocket(name, settings.GetDuration(config.TIMEOUT))
		if err != nil {
			writeDashboardSerialSocketError(w, name, err)
			return
		}

		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin: sameOriginWebsocketRequest,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(w, r, nil)
		if err != nil {
			_ = serialConn.Close()
			log.Printf("upgrade dashboard websocket for vm %q failed: %v", name, err)
			return
		}

		bridgeDashboardSocket("terminal", name, ws, serialConn)
	}
}

func openDashboardSerialSocket(name string, timeout time.Duration) (net.Conn, error) {
	socketPath, err := virt.SerialSocketPathForDomain(name)
	if err != nil {
		return nil, err
	}
	return dialDashboardSerialSocket(socketPath, timeout)
}

func dialDashboardSerialSocket(socketPath string, timeout time.Duration) (net.Conn, error) {
	serialConn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, virt.ErrSerialConsoleNotReady
		}
		return nil, fmt.Errorf("dial serial socket %s: %w", socketPath, err)
	}
	return serialConn, nil
}

func writeDashboardSerialSocketError(w http.ResponseWriter, name string, err error) {
	switch {
	case errors.Is(err, virt.ErrSerialConsoleNotRunning):
		http.Error(w, "VM must be running for terminal access.", http.StatusConflict)
	case errors.Is(err, virt.ErrSerialConsoleNotConfigured):
		http.Error(w, "Serial terminal is not available for this VM.", http.StatusConflict)
	case errors.Is(err, virt.ErrSerialConsoleNotReady):
		http.Error(w, "Serial terminal is not ready yet.", http.StatusConflict)
	default:
		log.Printf("open serial console for vm %q failed: %v", name, err)
		http.Error(w, "Failed to open serial terminal.", http.StatusInternalServerError)
	}
}

// HandleDashboardVNCWS serves the VNC websocket endpoint.
func HandleDashboardVNCWS(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessionManager.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}

		name, err := parseDashboardVMPathParam(chi.URLParam(r, "name"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		owned, err := virt.UserOwnsVM(name, user.GetName())
		if err != nil {
			writeDashboardVNCOwnershipError(w, name, user.GetName(), err)
			return
		}
		if !owned {
			writeDashboardVNCOwnershipError(w, name, user.GetName(), nil)
			return
		}

		vncConn, err := openDashboardVNCSocket(name, settings.GetDuration(config.TIMEOUT))
		if err != nil {
			writeDashboardVNCSocketError(w, name, err)
			return
		}

		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin: sameOriginWebsocketRequest,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(w, r, nil)
		if err != nil {
			_ = vncConn.Close()
			log.Printf("upgrade dashboard websocket for vm %q failed: %v", name, err)
			return
		}

		bridgeDashboardSocket("vnc", name, ws, vncConn)
	}
}

func openDashboardVNCSocket(name string, timeout time.Duration) (net.Conn, error) {
	socketPath, err := virt.VNCSocketPathForDomain(name)
	if err != nil {
		return nil, err
	}
	return dialDashboardVNCSocket(socketPath, timeout)
}

func dialDashboardVNCSocket(socketPath string, timeout time.Duration) (net.Conn, error) {
	vncConn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, virt.ErrVNCNotReady
		}
		return nil, fmt.Errorf("dial vnc socket %s: %w", socketPath, err)
	}
	return vncConn, nil
}

func writeDashboardVNCSocketError(w http.ResponseWriter, name string, err error) {
	switch {
	case errors.Is(err, virt.ErrVNCNotRunning):
		http.Error(w, "VM must be running for VNC access.", http.StatusConflict)
	case errors.Is(err, virt.ErrVNCNotConfigured):
		http.Error(w, "VNC is not available for this VM.", http.StatusConflict)
	case errors.Is(err, virt.ErrVNCNotReady):
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

func bridgeDashboardSocket(channel, name string, ws *websocket.Conn, backendConn net.Conn) {
	defer func() {
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
		errCh <- copySocketToWebsocket(ws, backendConn)
		closeOnce.Do(closeAll)
	}()

	go func() {
		errCh <- copyWebsocketToSocket(ws, backendConn)
		closeOnce.Do(closeAll)
	}()

	if err := <-errCh; err != nil && !isExpectedConsoleClose(err) {
		log.Printf("dashboard %s bridge for vm %q ended with error: %v", channel, name, err)
	}
}

func copySocketToWebsocket(ws *websocket.Conn, backendConn net.Conn) error {
	buf := make([]byte, 4096)
	for {
		n, err := backendConn.Read(buf)
		if n > 0 {
			if writeErr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
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

func copyWebsocketToSocket(ws *websocket.Conn, backendConn net.Conn) error {
	for {
		messageType, payload, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
			continue
		}
		if err := writeAll(backendConn, payload); err != nil {
			return err
		}
	}
}

func isExpectedConsoleClose(err error) bool {
	return websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived)
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
