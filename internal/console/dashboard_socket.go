package console

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/dashboard"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"

	"github.com/gorilla/websocket"
)

const (
	// dashboardControlReadLimit caps inbound dashboard control messages. The
	// browser only sends a tiny typed RTT probe, so 1 KiB is ample.
	dashboardControlReadLimit = 1024
	dashboardOutboundQueue    = 16
	dashboardRDPReadinessPoll = 2 * time.Second
)

type dashboardClientMessage struct {
	Type string   `json:"type"`
	ID   *float64 `json:"id,omitempty"`
}

type dashboardServerMessage struct {
	Type         string                  `json:"type"`
	ID           *float64                `json:"id,omitempty"`
	Data         *dashboard.DataResponse `json:"data,omitempty"`
	ServerMemory *dashboard.ServerMemory `json:"serverMemory,omitempty"`
	ServerDisk   *dashboard.ServerDisk   `json:"serverDisk,omitempty"`
	Error        string                  `json:"error,omitempty"`
}

type dashboardView struct {
	username         string
	isAdmin          bool
	allVMs           bool
	readServerMemory func() (dashboard.ServerMemory, error)
	readServerDisk   func() (dashboard.ServerDisk, error)
}

// HandleDashboardWS serves the dashboard's shared control websocket. Typed
// messages multiplex application-level RTT probes with user-filtered VM status
// pushes, avoiding a second long-lived SSE connection. Browsers do not expose
// protocol-level ping/pong to JavaScript, so RTT still uses explicit ping/pong
// messages while WebSocket control frames keep the transport alive.
func HandleDashboardWS(sessionManager *session.Manager, settings *config.Settings) http.HandlerFunc {
	return handleDashboardWS(sessionManager, settings, false)
}

// HandleAdminDashboardWS serves the administrator inventory WebSocket. It
// shares the dashboard transport and RTT protocol, but publishes every VM and
// performs its own server-side role check before upgrading the connection.
func HandleAdminDashboardWS(sessionManager *session.Manager, settings *config.Settings) http.HandlerFunc {
	return handleDashboardWS(sessionManager, settings, true)
}

func handleDashboardWS(sessionManager *session.Manager, settings *config.Settings, adminView bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessionManager.UserFromContext(r.Context())
		if !ok {
			log.Printf("reject dashboard websocket from %s: no authenticated session", strconv.Quote(r.RemoteAddr))
			http.Error(w, "Login required.", http.StatusUnauthorized)
			return
		}
		if adminView && !user.IsAdmin {
			log.Printf("reject admin dashboard websocket from %s for non-admin user %q", strconv.Quote(r.RemoteAddr), user.Name)
			http.Error(w, "Administrator access required.", http.StatusForbidden)
			return
		}
		sessionDeadline := sessionManager.Deadline(r.Context())

		dashboardSocketUpgrader := websocket.Upgrader{
			CheckOrigin: sameOriginWebsocketRequest,
		}

		ws, err := dashboardSocketUpgrader.Upgrade(upgradeResponseWriter("dashboard", "control", w), r, nil)
		if err != nil {
			log.Printf("upgrade dashboard websocket failed: %v", err)
			return
		}
		unregisterConnection, ok := sessionManager.RegisterUserConnection(user.Name, func() {
			_ = ws.Close()
		})
		if !ok {
			rejectOverUserConnectionLimit("dashboard", user.Name, ws)
			return
		}
		defer unregisterConnection()

		view := dashboardView{
			username: user.Name,
			isAdmin:  user.IsAdmin,
			allVMs:   adminView,
		}
		if adminView {
			view.readServerMemory = dashboard.ReadServerMemory
			view.readServerDisk = func() (dashboard.ServerDisk, error) {
				return dashboard.ReadServerDisk(config.VirtStoragePoolPath(settings))
			}
		}
		bridgeDashboardControlSocketForView(ws, view, settings, sessionDeadline)
	}
}

func bridgeDashboardControlSocket(
	ws *websocket.Conn,
	username string,
	settings *config.Settings,
	sessionDeadline time.Time,
) {
	bridgeDashboardControlSocketForView(ws, dashboardView{username: username}, settings, sessionDeadline)
}

func bridgeDashboardControlSocketForView(
	ws *websocket.Conn,
	view dashboardView,
	settings *config.Settings,
	sessionDeadline time.Time,
) {
	configureWebsocketKeepalive(ws, dashboardControlReadLimit)
	ctx, cancel := context.WithDeadline(context.Background(), sessionDeadline)
	outbound := make(chan dashboardServerMessage, dashboardOutboundQueue)
	writerDone := make(chan struct{})
	publisherDone := make(chan struct{})
	keepaliveDone := make(chan struct{})
	socketCloserDone := make(chan struct{})

	go writeDashboardMessages(ctx, cancel, ws, outbound, writerDone)
	go publishDashboardVMUpdates(ctx, view, settings, outbound, publisherDone)
	go pingWebsocketUntil(ws, keepaliveDone)
	go closeDashboardSocketWhenDone(ctx, ws, socketCloserDone)

	defer func() {
		cancel()
		_ = ws.Close()
		close(keepaliveDone)
		<-writerDone
		<-publisherDone
		<-socketCloserDone
	}()

	for {
		var message dashboardClientMessage
		if err := ws.ReadJSON(&message); err != nil {
			return
		}
		_ = ws.SetReadDeadline(time.Now().Add(wsPongWait))
		if message.Type != "ping" || message.ID == nil {
			continue
		}
		response := dashboardPong(view, message.ID)
		select {
		case outbound <- response:
		case <-ctx.Done():
			return
		}
	}
}

func dashboardPong(view dashboardView, id *float64) dashboardServerMessage {
	response := dashboardServerMessage{Type: "pong", ID: id}
	if !view.allVMs {
		return response
	}

	// Pongs run every two seconds while an admin tab is visible. Leave an
	// optional sample out rather than flooding logs if host statistics are
	// temporarily unavailable; each metric remains independent and the browser
	// renders only the failed sample as an unknown value.
	if view.readServerMemory != nil {
		if memory, err := view.readServerMemory(); err == nil {
			response.ServerMemory = &memory
		}
	}
	if view.readServerDisk != nil {
		if disk, err := view.readServerDisk(); err == nil {
			response.ServerDisk = &disk
		}
	}
	return response
}

func closeDashboardSocketWhenDone(ctx context.Context, ws *websocket.Conn, done chan<- struct{}) {
	defer close(done)
	<-ctx.Done()
	// Closing the socket is required in addition to cancelling the publishers:
	// ReadJSON may otherwise remain blocked after the authenticated session has
	// reached its absolute deadline.
	_ = ws.Close()
}

func writeDashboardMessages(
	ctx context.Context,
	cancel context.CancelFunc,
	ws *websocket.Conn,
	outbound <-chan dashboardServerMessage,
	done chan<- struct{},
) {
	defer close(done)
	defer cancel()

	for {
		select {
		case message := <-outbound:
			_ = ws.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := ws.WriteJSON(message); err != nil {
				_ = ws.Close()
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func publishDashboardVMUpdates(
	ctx context.Context,
	view dashboardView,
	settings *config.Settings,
	outbound chan<- dashboardServerMessage,
	done chan<- struct{},
) {
	defer close(done)
	worker := virt.NewInventory()

	// RDP readiness belongs to an interactive owner dashboard connection. Probe
	// before its initial snapshot, then repeat until cancellation. The
	// administrator inventory has lifecycle controls but no RDP connection
	// controls, so it deliberately does not probe every user's RDP port from each
	// open admin tab.
	if !view.allVMs {
		worker.RefreshRDPReadiness(ctx, view.username)
	}

	updates, unsubscribe := worker.SubscribeVMChanges()
	defer unsubscribe()

	if !queueDashboardDataUpdate(ctx, view, settings, outbound) {
		return
	}

	var readiness <-chan time.Time
	if !view.allVMs {
		readinessTicker := time.NewTicker(dashboardRDPReadinessPoll)
		defer readinessTicker.Stop()
		readiness = readinessTicker.C
	}

	for {
		select {
		case _, ok := <-updates:
			if !ok || !queueDashboardDataUpdate(ctx, view, settings, outbound) {
				return
			}
		case <-readiness:
			worker.RefreshRDPReadiness(ctx, view.username)
		case <-ctx.Done():
			return
		}
	}
}

func queueDashboardDataUpdate(
	ctx context.Context,
	view dashboardView,
	settings *config.Settings,
	outbound chan<- dashboardServerMessage,
) bool {
	var data dashboard.DataResponse
	var err error
	if view.allVMs {
		data, err = dashboard.DataForAdmin(settings)
	} else {
		data, err = dashboard.DataForUser(settings, view.username)
		data.IsAdmin = view.isAdmin
	}
	message := dashboardServerMessage{Type: "dashboard", Data: &data}
	if err != nil {
		log.Printf("list vms for dashboard websocket: %v", err)
		message = dashboardServerMessage{Type: "dashboard", Error: "Unable to load virtual machines right now."}
	}

	select {
	case outbound <- message:
		return true
	case <-ctx.Done():
		return false
	}
}
