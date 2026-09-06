package console

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

func covxConnectionAuthorization(t *testing.T, manager *session.Manager, username string) session.ConnectionAuthorization {
	t.Helper()
	cookie := covxSessionCookie(t, manager, username)
	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	req.AddCookie(cookie)
	var authorization session.ConnectionAuthorization
	manager.LoadAndSave(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var ok bool
		authorization, ok = manager.AuthorizeConnection(r.Context())
		if !ok {
			t.Error("committed session did not authorize a connection")
		}
	})).ServeHTTP(httptest.NewRecorder(), req)
	return authorization
}

type pausedWebsocketUpgrade struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

type pausedUpgradeWriter struct {
	http.ResponseWriter

	gate *pausedWebsocketUpgrade
}

func (w pausedUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.gate.once.Do(func() {
		close(w.gate.entered)
		<-w.gate.release
	})
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

func newPausedUpgradeServer(
	t *testing.T,
	manager *session.Manager,
	route string,
	handler http.HandlerFunc,
) (*httptest.Server, *pausedWebsocketUpgrade, func()) {
	t.Helper()
	gate := &pausedWebsocketUpgrade{entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(gate.release) })
	router := chi.NewRouter()
	router.Use(manager.LoadAndSave)
	router.Get(route, func(w http.ResponseWriter, r *http.Request) {
		handler(pausedUpgradeWriter{ResponseWriter: w, gate: gate}, r)
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	t.Cleanup(release)
	return server, gate, release
}

func dialPausedWebsocket(
	t *testing.T,
	server *httptest.Server,
	path string,
	cookie *http.Cookie,
	release func(),
) <-chan *websocket.Conn {
	t.Helper()
	result := make(chan *websocket.Conn, 1)
	go func() {
		defer close(result)
		header := http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
		dialer := websocket.Dialer{HandshakeTimeout: websocketTestTimeout}
		conn, response, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+path, header)
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if err != nil {
			t.Errorf("dial paused websocket: %v", err)
		}
		result <- conn
	}()
	t.Cleanup(func() {
		release()
		select {
		case conn := <-result:
			if conn != nil {
				_ = conn.Close()
			}
		case <-time.After(websocketTestTimeout):
			t.Error("paused websocket dial did not finish")
		}
	})
	return result
}

func TestWebsocketHandlersRejectLoadedSessionAfterLogout(t *testing.T) {
	for _, name := range []string{"personal", "admin", "serial", "vnc"} {
		t.Run(name, func(t *testing.T) {
			manager := session.New()
			settings := config.NewSettings(false)
			handlers := map[string]http.HandlerFunc{
				"personal": HandleDashboardWS(manager, settings),
				"admin":    HandleAdminDashboardWS(manager, settings),
				"serial":   HandleDashboardConsoleWS(manager),
				"vnc":      HandleDashboardVNCWS(manager),
			}
			user := &identity.User{Name: covxTestUsername, IsAdmin: true}
			cookie := covxSessionCookieForUser(t, manager, user, time.Time{})
			req := httptest.NewRequest(http.MethodGet, "/ws", nil)
			req.AddCookie(cookie)
			recorder := httptest.NewRecorder()
			manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := manager.DestroyAllSessionsForUser(user.Name); err != nil {
					t.Errorf("destroy sessions after loading request: %v", err)
				}
				manager.CloseUserConnections(user.Name)
				handlers[name](w, r)
			})).ServeHTTP(recorder, req)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("stale loaded session got HTTP %d, want 401", recorder.Code)
			}
		})
	}
}

func TestDashboardWebsocketRejectsLogoutDuringUpgrade(t *testing.T) {
	for _, admin := range []bool{false, true} {
		name := "personal"
		if admin {
			name = "admin"
		}
		t.Run(name, func(t *testing.T) {
			manager := session.New()
			handler := handleDashboardWS(manager, config.NewSettings(false), admin)
			assertLogoutDuringUpgrade(t, manager, "/ws", "/ws", handler)
		})
	}
}

func TestConsoleWebsocketRejectsLogoutDuringUpgrade(t *testing.T) {
	for _, channel := range []string{"console", "vnc"} {
		t.Run(channel, func(t *testing.T) {
			domain := covxDefineDomain(t, "late-"+channel)
			domain.setOwnerMetadata(covxOwnerMetadata)
			domain.startPaused()
			manager := session.New()
			handler := HandleDashboardConsoleWS(manager)
			if channel == "vnc" {
				handler = HandleDashboardVNCWS(manager)
			}
			assertLogoutDuringUpgrade(t, manager, "/{name}/ws", "/"+domain.name+"/ws", handler)
		})
	}
}

func assertLogoutDuringUpgrade(
	t *testing.T,
	manager *session.Manager,
	route string,
	path string,
	handler http.HandlerFunc,
) {
	t.Helper()
	server, gate, release := newPausedUpgradeServer(t, manager, route, handler)
	user := &identity.User{Name: covxTestUsername, IsAdmin: true}
	cookie := covxSessionCookieForUser(t, manager, user, time.Time{})
	pending := dialPausedWebsocket(t, server, path, cookie, release)
	select {
	case <-gate.entered:
	case <-time.After(websocketTestTimeout):
		t.Fatal("websocket did not reach the upgrade after authentication and backend setup")
	}
	if err := manager.DestroyAllSessionsForUser(user.Name); err != nil {
		t.Fatalf("destroy user sessions: %v", err)
	}
	if count := manager.CloseUserConnections(user.Name); count != 0 {
		t.Fatalf("connection registered before its paused upgrade: %d", count)
	}
	// A new login must neither revive the pending old authorization nor be
	// rejected itself after the old request finishes setting up.
	freshCookie := covxSessionCookieForUser(t, manager, user, time.Time{})
	release()
	assertRejectedUpgrade(t, pending)
	fresh := covxDialWebsocket(t, server, path, freshCookie)
	covxRevokeUserConnections(t, manager, user.Name, fresh)
}

func assertRejectedUpgrade(t *testing.T, pending <-chan *websocket.Conn) {
	t.Helper()
	var conn *websocket.Conn
	select {
	case conn = <-pending:
	case <-time.After(websocketTestTimeout):
		t.Fatal("websocket upgrade did not finish after release")
	}
	if conn == nil {
		t.Fatal("websocket upgrade failed before its registration check")
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set rejected websocket deadline: %v", err)
	}
	if _, _, err := conn.ReadMessage(); !websocket.IsCloseError(err, websocket.ClosePolicyViolation) {
		t.Fatalf("late websocket was not rejected with a policy close: %v", err)
	}
}
