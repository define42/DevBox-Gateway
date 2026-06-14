package console

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const websocketTestTimeout = 5 * time.Second

func newWebsocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	t.Helper()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	serverConnCh := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		serverConnCh <- conn
	}))

	clientConn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial websocket server: %v", err)
	}

	var serverConn *websocket.Conn
	select {
	case serverConn = <-serverConnCh:
	case <-time.After(websocketTestTimeout):
		_ = clientConn.Close()
		server.Close()
		t.Fatal("timed out waiting for websocket server connection")
	}

	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		server.Close()
	}
	return clientConn, serverConn, cleanup
}

func closeWebsocketClient(t *testing.T, conn *websocket.Conn) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	if err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), deadline); err != nil {
		t.Fatalf("write websocket close frame: %v", err)
	}
	_ = conn.Close()
}

func TestCopySocketToWebsocket(t *testing.T) {
	clientWS, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	backendConn, backendPeer := net.Pipe()
	defer func() { _ = backendConn.Close() }()
	defer func() { _ = backendPeer.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- copySocketToWebsocket("vnc", "test-vm", serverWS, backendConn)
	}()

	want := []byte("hello from serial")
	if _, err := backendPeer.Write(want); err != nil {
		t.Fatalf("write backend payload: %v", err)
	}

	if err := clientWS.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set websocket read deadline: %v", err)
	}
	messageType, got, err := clientWS.ReadMessage()
	if err != nil {
		t.Fatalf("read websocket message: %v", err)
	}
	if messageType != websocket.BinaryMessage {
		t.Fatalf("expected binary websocket message, got %d", messageType)
	}
	if string(got) != string(want) {
		t.Fatalf("expected websocket payload %q, got %q", string(want), string(got))
	}

	if err := backendPeer.Close(); err != nil {
		t.Fatalf("close backend peer: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("copySocketToWebsocket returned error: %v", err)
		}
	case <-time.After(websocketTestTimeout):
		t.Fatal("copySocketToWebsocket did not return in time")
	}
}

func TestCopyWebsocketToSocket(t *testing.T) {
	clientWS, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	backendConn, backendPeer := net.Pipe()
	defer func() { _ = backendConn.Close() }()
	defer func() { _ = backendPeer.Close() }()

	errCh := make(chan error, 1)
	go func() {
		errCh <- copyWebsocketToSocket("vnc", "test-vm", serverWS, backendConn)
	}()

	want := []byte("hello from browser")
	if err := clientWS.WriteMessage(websocket.TextMessage, want); err != nil {
		t.Fatalf("write websocket message: %v", err)
	}

	if err := backendPeer.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set backend read deadline: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(backendPeer, got); err != nil {
		t.Fatalf("read backend payload: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("expected backend payload %q, got %q", string(want), string(got))
	}

	closeWebsocketClient(t, clientWS)

	select {
	case err := <-errCh:
		if !isExpectedConsoleClose(err) {
			t.Fatalf("expected normal websocket close, got %v", err)
		}
	case <-time.After(websocketTestTimeout):
		t.Fatal("copyWebsocketToSocket did not return in time")
	}
}

func TestBridgeDashboardSocket(t *testing.T) {
	clientWS, serverWS, cleanup := newWebsocketPair(t)
	defer cleanup()

	backendConn, backendPeer := net.Pipe()
	defer func() { _ = backendPeer.Close() }()

	done := make(chan struct{})
	go func() {
		bridgeDashboardSocket("terminal", "alice-devbox", serverWS, backendConn)
		close(done)
	}()

	wantFromBackend := []byte("backend-to-browser")
	if _, err := backendPeer.Write(wantFromBackend); err != nil {
		t.Fatalf("write backend-to-browser payload: %v", err)
	}

	if err := clientWS.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set websocket read deadline: %v", err)
	}
	messageType, gotFromBackend, err := clientWS.ReadMessage()
	if err != nil {
		t.Fatalf("read backend-to-browser websocket payload: %v", err)
	}
	if messageType != websocket.BinaryMessage {
		t.Fatalf("expected binary websocket message, got %d", messageType)
	}
	if string(gotFromBackend) != string(wantFromBackend) {
		t.Fatalf("expected backend-to-browser payload %q, got %q", string(wantFromBackend), string(gotFromBackend))
	}

	wantFromBrowser := []byte("browser-to-backend")
	if err := clientWS.WriteMessage(websocket.BinaryMessage, wantFromBrowser); err != nil {
		t.Fatalf("write browser-to-backend websocket payload: %v", err)
	}

	if err := backendPeer.SetReadDeadline(time.Now().Add(websocketTestTimeout)); err != nil {
		t.Fatalf("set backend read deadline: %v", err)
	}
	gotFromBrowser := make([]byte, len(wantFromBrowser))
	if _, err := io.ReadFull(backendPeer, gotFromBrowser); err != nil {
		t.Fatalf("read browser-to-backend payload: %v", err)
	}
	if string(gotFromBrowser) != string(wantFromBrowser) {
		t.Fatalf("expected browser-to-backend payload %q, got %q", string(wantFromBrowser), string(gotFromBrowser))
	}

	closeWebsocketClient(t, clientWS)

	select {
	case <-done:
	case <-time.After(websocketTestTimeout):
		t.Fatal("bridgeDashboardSocket did not return in time")
	}
}
