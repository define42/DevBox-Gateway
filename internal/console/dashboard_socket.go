package console

import (
	"context"
	"devboxgateway/internal/config"
	"devboxgateway/internal/dashboard"
	"devboxgateway/internal/session"
	"devboxgateway/internal/virt"
	"log"
	"net/http"
	"strconv"
	"time"

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
	Type  string                  `json:"type"`
	ID    *float64                `json:"id,omitempty"`
	Data  *dashboard.DataResponse `json:"data,omitempty"`
	Error string                  `json:"error,omitempty"`
}

// HandleDashboardWS serves the dashboard's shared control websocket. Typed
// messages multiplex application-level RTT probes with user-filtered VM status
// pushes, avoiding a second long-lived SSE connection. Browsers do not expose
// protocol-level ping/pong to JavaScript, so RTT still uses explicit ping/pong
// messages while WebSocket control frames keep the transport alive.
func HandleDashboardWS(sessionManager *session.Manager, settings *config.SettingsType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessionManager.UserFromContext(r.Context())
		if !ok {
			log.Printf("reject dashboard websocket from %s: no authenticated session", strconv.Quote(r.RemoteAddr))
			http.Error(w, "Login required.", http.StatusUnauthorized)
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
		unregisterConnection, ok := sessionManager.RegisterUserConnection(user.GetName(), func() {
			_ = ws.Close()
		})
		if !ok {
			rejectOverUserConnectionLimit("dashboard", user.GetName(), ws)
			return
		}
		defer unregisterConnection()

		bridgeDashboardControlSocket(ws, user.GetName(), settings, sessionDeadline)
	}
}

func bridgeDashboardControlSocket(
	ws *websocket.Conn,
	username string,
	settings *config.SettingsType,
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
	go publishDashboardVMUpdates(ctx, username, settings, outbound, publisherDone)
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
		response := dashboardServerMessage{Type: "pong", ID: message.ID}
		select {
		case outbound <- response:
		case <-ctx.Done():
			return
		}
	}
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
	username string,
	settings *config.SettingsType,
	outbound chan<- dashboardServerMessage,
	done chan<- struct{},
) {
	defer close(done)
	worker := virt.GetInstance()

	// Readiness belongs to this authenticated dashboard connection. Probe before
	// the initial WebSocket snapshot, then repeat until its context is cancelled.
	// Separate tabs intentionally run separate probe rounds.
	worker.RefreshRDPReadiness(ctx, username)

	updates, unsubscribe := worker.SubscribeVMChanges()
	defer unsubscribe()

	if !queueDashboardDataUpdate(ctx, username, settings, outbound) {
		return
	}

	readinessTicker := time.NewTicker(dashboardRDPReadinessPoll)
	defer readinessTicker.Stop()

	for {
		select {
		case _, ok := <-updates:
			if !ok || !queueDashboardDataUpdate(ctx, username, settings, outbound) {
				return
			}
		case <-readinessTicker.C:
			worker.RefreshRDPReadiness(ctx, username)
		case <-ctx.Done():
			return
		}
	}
}

func queueDashboardDataUpdate(
	ctx context.Context,
	username string,
	settings *config.SettingsType,
	outbound chan<- dashboardServerMessage,
) bool {
	data, err := dashboard.DataForUser(settings, username)
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
