package console

import (
	"bufio"
	"devboxgateway/internal/session"
	"devboxgateway/internal/types"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

const (
	covxSessionCookieName = "cv_session"
	covxTestUsername      = "covx-user"
)

// covxSessionCookie logs username in through the session manager and returns
// the resulting session cookie for authenticated follow-up requests.
func covxSessionCookie(t *testing.T, manager *session.Manager, username string) *http.Cookie {
	t.Helper()

	user, err := types.NewUser(username)
	if err != nil {
		t.Fatalf("new user %q: %v", username, err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "192.0.2.55:12345"

	handler := manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.CreateSession(r.Context(), user, r.RemoteAddr); err != nil {
			t.Errorf("create session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	for _, cookie := range res.Cookies() {
		if cookie.Name == covxSessionCookieName {
			return cookie
		}
	}

	t.Fatal("session cookie not set")
	return nil
}

// covxDashboardServer serves the dashboard websocket routes behind the session
// middleware, mirroring the production router wiring.
func covxDashboardServer(t *testing.T, manager *session.Manager) *httptest.Server {
	t.Helper()

	router := chi.NewRouter()
	router.Use(manager.LoadAndSave)
	router.Get("/api/dashboard/console/{name}/ws", HandleDashboardConsoleWS(manager))
	router.Get("/api/dashboard/vnc/{name}/ws", HandleDashboardVNCWS(manager))
	router.Get("/api/dashboard/ping/ws", HandleDashboardPingWS(manager))

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

func covxGetStatus(t *testing.T, server *httptest.Server, path string, cookie *http.Cookie) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
	if err != nil {
		t.Fatalf("new request for %s: %v", path, err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body for %s: %v", path, err)
	}
	return resp.StatusCode, string(body)
}

func covxDialWebsocket(t *testing.T, server *httptest.Server, path string, cookie *http.Cookie) *websocket.Conn {
	t.Helper()

	header := http.Header{}
	header.Add("Cookie", cookie.Name+"="+cookie.Value)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + path

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			t.Fatalf("dial websocket %s: %v (body %s)", path, err, data)
		}
		t.Fatalf("dial websocket %s: %v", path, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// covxRevokeUserConnections closes the user's registered websocket connections,
// polling until the handler under test has registered one.
func covxRevokeUserConnections(t *testing.T, manager *session.Manager, username string) {
	t.Helper()

	deadline := time.Now().Add(websocketTestTimeout)
	for manager.CloseUserConnections(username) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("websocket connection was never registered for revocation")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// covxAwaitWebsocketClosed drains conn until it reports an error, bounded by a
// read deadline.
func covxAwaitWebsocketClosed(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func TestCovxPingWSRejectsUnauthenticated(t *testing.T) {
	manager := session.NewManager()
	server := covxDashboardServer(t, manager)

	status, body := covxGetStatus(t, server, "/api/dashboard/ping/ws", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d with body %s", http.StatusUnauthorized, status, body)
	}
	if !strings.Contains(body, "Login required.") {
		t.Fatalf("expected login required message, got %q", body)
	}
}

func TestCovxPingWSUpgradeFailure(t *testing.T) {
	manager := session.NewManager()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	// A plain GET with a valid session is not a websocket handshake, so the
	// upgrade fails after authentication succeeded.
	status, body := covxGetStatus(t, server, "/api/dashboard/ping/ws", cookie)
	if status != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d with body %s", http.StatusBadRequest, status, body)
	}
}

func TestCovxPingWSEchoWithDebugLogging(t *testing.T) {
	// Debug logging routes the upgrade through debugUpgradeWriter/debugConn and
	// exercises the debugf logging branch.
	SetDebugLogging(true)
	t.Cleanup(func() { SetDebugLogging(false) })

	manager := session.NewManager()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	conn := covxDialWebsocket(t, server, "/api/dashboard/ping/ws", cookie)

	const probe = "123.456"
	if err := conn.WriteMessage(websocket.TextMessage, []byte(probe)); err != nil {
		t.Fatalf("write ping probe: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	messageType, got, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read echoed probe: %v", err)
	}
	if messageType != websocket.TextMessage {
		t.Fatalf("expected text echo, got message type %d", messageType)
	}
	if string(got) != probe {
		t.Fatalf("expected echoed probe %q, got %q", probe, string(got))
	}

	closeWebsocketClient(t, conn)
}

func TestCovxPingWSClosedOnUserRevocation(t *testing.T) {
	manager := session.NewManager()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	conn := covxDialWebsocket(t, server, "/api/dashboard/ping/ws", cookie)

	// Closing the user's tracked connections runs the handler's registered
	// close callback, which shuts the websocket down server-side.
	covxRevokeUserConnections(t, manager, covxTestUsername)
	covxAwaitWebsocketClosed(t, conn)
}

func TestCovxBridgeDashboardSocketLogsUnexpectedError(t *testing.T) {
	_, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	backendConn, backendPeer := net.Pipe()
	defer func() { _ = backendPeer.Close() }()
	// A backend that is already closed makes the bridge end with a non-close
	// error, taking the error-logging branch.
	_ = backendConn.Close()

	bridgeDashboardSocket("vnc", "covx-vm", serverWS, backendConn)
}

func TestCovxBridgePingSocketWriteFailure(t *testing.T) {
	clientWS, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	// An already-expired write deadline makes the echo write fail while the
	// preceding read still succeeds.
	if err := serverWS.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("set expired write deadline: %v", err)
	}

	done := make(chan struct{})
	go func() {
		bridgePingSocket(serverWS)
		close(done)
	}()

	if err := clientWS.WriteMessage(websocket.TextMessage, []byte("1.0")); err != nil {
		t.Fatalf("write probe: %v", err)
	}

	select {
	case <-done:
	case <-time.After(websocketTestTimeout):
		t.Fatal("bridgePingSocket did not return after echo write failure")
	}
}

// covxHijacker satisfies http.Hijacker with configurable results so the
// debugUpgradeWriter branches can be driven directly.
type covxHijacker struct {
	http.ResponseWriter

	conn net.Conn
	err  error
}

func (h covxHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) { return h.conn, nil, h.err }

func TestCovxDebugUpgradeWriterUnwrap(t *testing.T) {
	base := httptest.NewRecorder()
	writer := &debugUpgradeWriter{ResponseWriter: base, channel: "serial", name: "covx-vm"}

	if got := writer.Unwrap(); got != http.ResponseWriter(base) {
		t.Fatalf("expected Unwrap to return the wrapped writer, got %T", got)
	}
}

func TestCovxDebugUpgradeWriterHijackNotHijacker(t *testing.T) {
	writer := &debugUpgradeWriter{ResponseWriter: httptest.NewRecorder(), channel: "serial", name: "covx-vm"}

	if _, _, err := writer.Hijack(); err == nil {
		t.Fatal("expected error when underlying writer is not an http.Hijacker")
	}
}

func TestCovxDebugUpgradeWriterHijackError(t *testing.T) {
	wantErr := errors.New("hijack boom")
	writer := &debugUpgradeWriter{
		ResponseWriter: covxHijacker{err: wantErr},
		channel:        "vnc",
		name:           "covx-vm",
	}

	if _, _, err := writer.Hijack(); !errors.Is(err, wantErr) {
		t.Fatalf("expected hijack error %v, got %v", wantErr, err)
	}
}

func TestCovxDebugUpgradeWriterHijackWrapsConnWrites(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close() }()
	defer func() { _ = peer.Close() }()
	go func() { _, _ = io.Copy(io.Discard, peer) }()

	writer := &debugUpgradeWriter{ResponseWriter: covxHijacker{conn: conn}, channel: "serial", name: "covx-vm"}
	hijacked, _, err := writer.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	if _, ok := hijacked.(*debugConn); !ok {
		t.Fatalf("expected hijacked conn to be a *debugConn, got %T", hijacked)
	}

	// The first write takes the handshake-logging branch; the second takes the
	// quiet branch.
	for i, payload := range []string{"HTTP/1.1 101", "frame"} {
		n, err := hijacked.Write([]byte(payload))
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if n != len(payload) {
			t.Fatalf("write %d: expected %d bytes written, got %d", i, len(payload), n)
		}
	}
}

func TestCovxUpgradeResponseWriterDebugToggle(t *testing.T) {
	base := hijackableRecorder{}

	SetDebugLogging(false)
	if got := upgradeResponseWriter("serial", "covx-vm", base); got != http.ResponseWriter(base) {
		t.Fatalf("expected the hijacker unchanged with debug off, got %T", got)
	}

	SetDebugLogging(true)
	t.Cleanup(func() { SetDebugLogging(false) })
	wrapped, ok := upgradeResponseWriter("serial", "covx-vm", base).(*debugUpgradeWriter)
	if !ok {
		t.Fatal("expected a *debugUpgradeWriter with debug on")
	}
	if wrapped.ResponseWriter != http.ResponseWriter(base) {
		t.Fatalf("expected the debug writer to wrap the hijacker, got %T", wrapped.ResponseWriter)
	}
}

func TestCovxPreviewBytes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "printable unchanged", input: "RFB 003.008", want: "RFB 003.008"},
		{name: "non-printable replaced", input: "\x1b[1mA\x7f\n", want: ".[1mA.."},
		{name: "long input truncated", input: strings.Repeat("a", 40), want: strings.Repeat("a", 32)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := previewBytes([]byte(tc.input)); got != tc.want {
				t.Fatalf("previewBytes(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCovxWriteAllErrorOnClosedConn(t *testing.T) {
	conn, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	_ = conn.Close()

	if err := writeAll(conn, []byte("payload")); err == nil {
		t.Fatal("expected error writing to a closed connection")
	}
}

func TestCovxCopySocketToWebsocketReadError(t *testing.T) {
	_, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	backendConn, backendPeer := net.Pipe()
	defer func() { _ = backendPeer.Close() }()
	_ = backendConn.Close()

	err := copySocketToWebsocket("vnc", "covx-vm", serverWS, backendConn)
	if err == nil {
		t.Fatal("expected error reading from a closed backend")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("expected a non-EOF error, got %v", err)
	}
}

func TestCovxCopySocketToWebsocketWriteError(t *testing.T) {
	_, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	backendConn, backendPeer := net.Pipe()
	defer func() { _ = backendConn.Close() }()
	defer func() { _ = backendPeer.Close() }()

	// Closing the server websocket makes the forwarding write fail
	// deterministically; copySocketToWebsocket now sets a fresh write deadline
	// before each write, so an expired deadline would be overwritten.
	if err := serverWS.Close(); err != nil {
		t.Fatalf("close server websocket: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- copySocketToWebsocket("vnc", "covx-vm", serverWS, backendConn)
	}()

	if _, err := backendPeer.Write([]byte("backend payload")); err != nil {
		t.Fatalf("write backend payload: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected websocket write error")
		}
	case <-time.After(websocketTestTimeout):
		t.Fatal("copySocketToWebsocket did not return after write failure")
	}
}

func TestCovxCopyWebsocketToSocketWriteError(t *testing.T) {
	clientWS, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	backendConn, backendPeer := net.Pipe()
	defer func() { _ = backendPeer.Close() }()
	_ = backendConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- copyWebsocketToSocket("vnc", "covx-vm", serverWS, backendConn)
	}()

	if err := clientWS.WriteMessage(websocket.TextMessage, []byte("browser payload")); err != nil {
		t.Fatalf("write websocket payload: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error writing to a closed backend")
		}
	case <-time.After(websocketTestTimeout):
		t.Fatal("copyWebsocketToSocket did not return after backend write failure")
	}
}

func TestCovxDashboardHandlersRejectInvalidVMName(t *testing.T) {
	manager := session.NewManager()
	server := covxDashboardServer(t, manager)
	cookie := covxSessionCookie(t, manager, covxTestUsername)

	for _, channel := range []string{"console", "vnc"} {
		status, body := covxGetStatus(t, server, "/api/dashboard/"+channel+"/%20%20%20/ws", cookie)
		if status != http.StatusBadRequest {
			t.Fatalf("%s: expected %d for blank vm name, got %d with body %s", channel, http.StatusBadRequest, status, body)
		}
	}
}
