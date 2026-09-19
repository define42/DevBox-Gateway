package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/session"
	"github.com/gorilla/websocket"
)

type httpDrainResponse struct {
	status int
	body   string
	err    error
}

func startHTTPDrainRuntime(t *testing.T, handler http.Handler, sink io.Closer) (*gatewayRuntime, *http.Client, string) {
	t.Helper()
	frontTLS, settings := newTestTLSManager(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	runtime := &gatewayRuntime{
		listener:       listener,
		frontTLS:       frontTLS,
		httpServers:    newHTTPServerRegistry(),
		sessionManager: session.New(),
		auditSink:      sink,
		done:           done,
	}
	go func() {
		runtime.serveErr = serveListenerWithHTTPServers(listener, handler, frontTLS, runtime.sessionManager, settings, runtime.httpServers)
		close(done)
	}()
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   3 * gatewayShutdownTimeout,
	}
	t.Cleanup(func() {
		client.CloseIdleConnections()
		_ = runtime.Close()
	})
	return runtime, client, "https://" + listener.Addr().String()
}

func startHTTPDrainRequest(t *testing.T, client *http.Client, address string) <-chan httpDrainResponse {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, address, strings.NewReader("unread request body"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	result := make(chan httpDrainResponse, 1)
	go func() {
		response, err := client.Do(request)
		if err != nil {
			result <- httpDrainResponse{err: err}
			return
		}
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		result <- httpDrainResponse{status: response.StatusCode, body: string(body), err: err}
	}()
	return result
}

func awaitHTTPDrainRequest(t *testing.T, entered <-chan context.Context) context.Context {
	t.Helper()
	select {
	case ctx := <-entered:
		return ctx
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP handler did not start")
		return nil
	}
}

func completedBeforeAuditClose(t *testing.T, completed <-chan struct{}) io.Closer {
	t.Helper()
	return &auditTestCloser{closeFn: func() {
		select {
		case <-completed:
		default:
			t.Error("audit sink closed before the HTTP handler completed")
		}
	}}
}

func TestHTTPShutdownWaitsForActiveRequest(t *testing.T) {
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	completed := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(completed)
		entered <- r.Context()
		select {
		case <-release:
			_, _ = io.WriteString(w, "creation completed")
		case <-r.Context().Done():
			t.Error("HTTP request was cancelled before its graceful drain completed")
		}
	})
	runtime, client, address := startHTTPDrainRuntime(t, handler, completedBeforeAuditClose(t, completed))
	response := startHTTPDrainRequest(t, client, address)
	requestContext := awaitHTTPDrainRequest(t, entered)
	closed := make(chan error, 1)
	go func() { closed <- runtime.Close() }()

	select {
	case err := <-closed:
		t.Fatalf("shutdown returned before the active request finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := requestContext.Err(); err != nil {
		t.Fatalf("request cancelled during grace: %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	result := <-response
	if result.err != nil || result.status != http.StatusOK || result.body != "creation completed" {
		t.Fatalf("active response interrupted by shutdown: %+v", result)
	}
	if err := <-closed; err != nil {
		t.Fatalf("runtime shutdown: %v", err)
	}
}

func TestHTTPShutdownCancelsRequestAfterDeadline(t *testing.T) {
	entered := make(chan context.Context, 1)
	completed := make(chan struct{})
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		defer close(completed)
		entered <- r.Context()
		// Leave the body unread: cancellation must not depend on net/http's
		// background socket reader noticing the transport has closed.
		<-r.Context().Done()
	})
	runtime, client, address := startHTTPDrainRuntime(t, handler, completedBeforeAuditClose(t, completed))
	response := startHTTPDrainRequest(t, client, address)
	requestContext := awaitHTTPDrainRequest(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := runtime.httpServers.shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("HTTP drain = %v, want deadline exceeded", err)
	}
	if !errors.Is(requestContext.Err(), context.Canceled) {
		t.Fatalf("request context after force close = %v, want cancellation", requestContext.Err())
	}
	select {
	case <-completed:
	default:
		t.Fatal("HTTP drain returned before cancellation cleanup finished")
	}
	if result := <-response; result.err == nil {
		t.Fatalf("expected the forced HTTP response to be interrupted, got %+v", result)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close runtime after HTTP drain: %v", err)
	}
}

func TestHTTPShutdownPreservesWebsocketDrain(t *testing.T) {
	completed := make(chan struct{})
	registered := make(chan struct{})
	var runtime *gatewayRuntime
	upgrader := websocket.Upgrader{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer func() { _ = ws.Close() }()
		authorization := testConnectionAuthorization(t, runtime.sessionManager, "alice")
		unregister, ok := runtime.sessionManager.RegisterUserConnection(authorization, func() { _ = ws.Close() })
		if !ok {
			t.Error("register upgraded connection")
			return
		}
		defer unregister()
		defer close(completed)
		close(registered)
		_, _, _ = ws.ReadMessage()
	})
	var address string
	runtime, _, address = startHTTPDrainRuntime(t, handler, completedBeforeAuditClose(t, completed))
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	ws, response, err := dialer.DialContext(t.Context(), "wss"+strings.TrimPrefix(address, "https"), nil)
	if response != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = ws.Close() }()
	select {
	case <-registered:
	case <-time.After(2 * time.Second):
		t.Fatal("upgraded connection did not register")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime shutdown with websocket: %v", err)
	}
}

type pausedHTTPAdmissionConn struct {
	net.Conn

	paused chan struct{}
	resume <-chan struct{}
	once   sync.Once
}

func (c *pausedHTTPAdmissionConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.once.Do(func() {
			close(c.paused)
			<-c.resume
		})
	}
	return c.Conn.SetDeadline(deadline)
}

func TestHTTPShutdownRejectsLateTLSSetup(t *testing.T) {
	frontTLS, settings := newTestTLSManager(t)
	registry := newHTTPServerRegistry()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	resume := make(chan struct{})
	var resumeOnce sync.Once
	defer resumeOnce.Do(func() { close(resume) })
	paused := &pausedHTTPAdmissionConn{Conn: server, paused: make(chan struct{}), resume: resume}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handleHTTPSWithHTTPServers(paused, frontTLS, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("HTTP handler started after shutdown closed admission")
		}), settings, registry)
	}()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	tlsClient := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	<-paused.paused
	if err := registry.shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown during TLS setup: %v", err)
	}
	resumeOnce.Do(func() { close(resume) })
	_, _ = io.WriteString(tlsClient, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if response, err := http.ReadResponse(bufio.NewReader(tlsClient), &http.Request{Method: http.MethodGet}); err == nil {
		_ = response.Body.Close()
		t.Fatal("late TLS setup served an HTTP response after shutdown")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("rejected HTTP setup did not close")
	}
}

func TestHTTPShutdownBeforeServeStarts(t *testing.T) {
	registry := newHTTPServerRegistry()
	client, conn := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = conn.Close() }()
	server := &http.Server{}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	registration, ok := registry.register(server, cancel, func() { _ = conn.Close() })
	if !ok {
		t.Fatal("register HTTP server before shutdown")
	}
	shutdownStarted := make(chan struct{})
	server.RegisterOnShutdown(func() { close(shutdownStarted) })
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- registry.shutdown(ctx) }()
	<-shutdownStarted
	serveDone := make(chan struct{})
	go func() {
		serveHTTPConnection(server, conn, registration)
		close(serveDone)
	}()
	select {
	case <-serveDone:
	case <-ctx.Done():
		t.Fatal("server admitted before shutdown remained blocked before Serve")
	}
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown before Serve started: %v", err)
	}
}

func TestSingleConnListenerConcurrentAcceptClose(t *testing.T) {
	for range 100 {
		client, server := net.Pipe()
		listener := newSingleConnListener(server)
		closed := make(chan struct{})
		go func() {
			_ = listener.Close()
			close(closed)
		}()
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		} else if !errors.Is(err, net.ErrClosed) {
			t.Errorf("concurrent accept/close: %v", err)
		}
		<-closed
		<-listener.connectionDone
		_ = client.Close()
	}
}
