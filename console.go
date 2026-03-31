package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

var (
	dialDashboardSerialSocket = virt.DialSerialSocket
	dialDashboardVNCSocket    = virt.DialVNCSocket
	dashboardSocketUpgrader   = websocket.Upgrader{
		CheckOrigin: sameOriginWebsocketRequest,
	}
)

func handleDashboardConsoleWS(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
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

		owned, err := dashboardVMOwnershipCheck(name, user.GetName())
		if err != nil {
			log.Printf("verify terminal access for user %q vm %q failed: %v", user.GetName(), name, err)
			http.Error(w, "Unable to verify VM ownership.", http.StatusInternalServerError)
			return
		}
		if !owned {
			log.Printf("user %q attempted to access terminal for vm %q not owned by them", user.GetName(), name)
			http.Error(w, "You do not have permission to access this VM terminal.", http.StatusForbidden)
			return
		}

		serialConn, err := dialDashboardSerialSocket(name, settings.GetDuration(config.TIMEOUT))
		if err != nil {
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
			return
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

func handleDashboardVNCWS(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
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

		owned, err := dashboardVMOwnershipCheck(name, user.GetName())
		if err != nil {
			log.Printf("verify VNC access for user %q vm %q failed: %v", user.GetName(), name, err)
			http.Error(w, "Unable to verify VM ownership.", http.StatusInternalServerError)
			return
		}
		if !owned {
			log.Printf("user %q attempted to access VNC for vm %q not owned by them", user.GetName(), name)
			http.Error(w, "You do not have permission to access this VM VNC session.", http.StatusForbidden)
			return
		}

		vncConn, err := dialDashboardVNCSocket(name, settings.GetDuration(config.TIMEOUT))
		if err != nil {
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
			return
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
