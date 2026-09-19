package gateway

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/dashboard"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
)

func startWriteDeadlineTestHTTPS(
	t *testing.T,
	timeout time.Duration,
	handler func(*config.Settings) http.Handler,
) (*tls.Conn, *failFastLimitListener, <-chan struct{}) {
	t.Helper()
	frontTLS, settings := newTestTLSManager(t)
	if err := settings.OverwriteForTestDuration(config.TIMEOUT, timeout); err != nil {
		t.Fatalf("set timeout: %v", err)
	}
	router := handler(settings)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	limited := newFailFastLimitListener(ln, 1)
	t.Cleanup(func() { _ = limited.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := limited.Accept()
		if acceptErr != nil {
			t.Errorf("accept: %v", acceptErr)
			return
		}
		defer func() { _ = conn.Close() }()
		tcp := conn.(*slotTrackedConn).Conn.(*net.TCPConn)
		if bufferErr := tcp.SetWriteBuffer(4096); bufferErr != nil {
			t.Errorf("set server write buffer: %v", bufferErr)
			return
		}
		handleSharedConn(conn, frontTLS, router, nil, settings)
	}()
	raw, err := net.Dial("tcp", limited.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
		waitWriteDeadlineTestDone(t, done)
	})
	if err := raw.(*net.TCPConn).SetReadBuffer(4096); err != nil {
		t.Fatalf("set client read buffer: %v", err)
	}
	client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	return client, limited, done
}

func TestHandleHTTPSBlockedAssetWritesReleaseConnectionSlot(t *testing.T) {
	client, limited, done := startWriteDeadlineTestHTTPS(t, 200*time.Millisecond,
		func(settings *config.Settings) http.Handler { return NewHandler(session.New(), settings) })
	requests := strings.Repeat("GET /static/dashboard.js HTTP/1.1\r\nHost: localhost\r\n\r\n", 256)
	if _, err := io.WriteString(client, requests); err != nil {
		t.Fatalf("pipeline public asset requests: %v", err)
	}

	// Keep the client connected without reading responses. Kernel socket buffers
	// must fill before this tests the HTTP write deadline rather than idle reads.
	waitWriteDeadlineTestDone(t, done)
	if got := len(limited.slots); got != 0 {
		t.Fatalf("blocked writer retained %d connection slots", got)
	}
}

func waitWriteDeadlineTestDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		// crypto/tls additionally bounds its close_notify write to five seconds
		// when closing an already blocked connection after the HTTP timeout.
		t.Fatal("client that stopped reading retained its HTTPS connection slot")
	}
}

func TestHandleHTTPSCreationStreamRenewsWritesAfterLongGaps(t *testing.T) {
	const timeout = 100 * time.Millisecond
	client, _, _ := startWriteDeadlineTestHTTPS(t, timeout, func(settings *config.Settings) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			stream := dashboard.NewCreationStream(withRenewableWriteDeadline(w, httpWriteTimeout(settings)))
			// Preparation, disk copying, and final provisioning can each exceed
			// the ordinary HTTP write timeout without writing any response bytes.
			time.Sleep(2 * timeout)
			stream.ReportDiskCopy(0, 100)
			time.Sleep(2 * timeout)
			stream.ReportDiskCopy(100, 100)
			time.Sleep(2 * timeout)
			stream.WriteResult(dashboard.ActionResponse{OK: true, Message: "VM created."})
		})
	})
	if _, err := io.WriteString(client, "POST /api/dashboard HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatalf("write stream request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read stream response: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	decoder := json.NewDecoder(response.Body)
	for _, want := range []string{"progress", "progress", "result"} {
		var event struct {
			Type string `json:"type"`
		}
		if err := decoder.Decode(&event); err != nil {
			t.Fatalf("read %s event after deadline elapsed: %v", want, err)
		}
		if event.Type != want {
			t.Fatalf("event type = %q, want %q", event.Type, want)
		}
	}
}

func TestHandleHTTPSBlockedStreamWritesReleaseConnectionSlot(t *testing.T) {
	for _, flush := range []bool{false, true} {
		t.Run(fmt.Sprintf("flush=%t", flush), func(t *testing.T) {
			writeError := make(chan error, 1)
			client, limited, done := startWriteDeadlineTestHTTPS(t, 200*time.Millisecond,
				func(settings *config.Settings) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w = withRenewableWriteDeadline(w, httpWriteTimeout(settings))
						writeError <- fillStreamingResponse(w, flush)
					})
				})
			if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
				t.Fatalf("write request: %v", err)
			}
			select {
			case err := <-writeError:
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("blocked stream must time out, got %v", err)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("stream blocked indefinitely after client stopped reading")
			}
			waitWriteDeadlineTestDone(t, done)
			if got := len(limited.slots); got != 0 {
				t.Fatalf("blocked stream retained %d connection slots", got)
			}
		})
	}
}

func fillStreamingResponse(w http.ResponseWriter, flush bool) error {
	chunk := make([]byte, 1024)
	for range 1 << 16 {
		if _, err := w.Write(chunk); err != nil {
			return err
		}
		if flush {
			if err := http.NewResponseController(w).Flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestHandleHTTPSUploadResponseAfterWriteTimeout(t *testing.T) {
	const timeout = 100 * time.Millisecond
	upload := baseImageUploadRequest(t, "base_image", "slow.qcow2", baseImageQCOW2TestData("image contents"))
	body, err := io.ReadAll(upload.Body)
	if err != nil {
		t.Fatalf("read upload fixture: %v", err)
	}
	var cookie *http.Cookie
	client, _, _ := startWriteDeadlineTestHTTPS(t, timeout, func(settings *config.Settings) http.Handler {
		if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, t.TempDir()); err != nil {
			t.Fatalf("set data root: %v", err)
		}
		manager := session.New()
		cookie = issueSessionCookieForUser(t, manager, &identity.User{Name: "admin", IsAdmin: true}, "127.0.0.1:12345", testGuestPasswordHash)
		return NewHandler(manager, settings)
	})
	_, err = fmt.Fprintf(client, "POST /api/admin/base-images HTTP/1.1\r\nHost: localhost\r\nOrigin: https://localhost\r\nCookie: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		cookie.String(), upload.Header.Get("Content-Type"), len(body))
	if err != nil {
		t.Fatalf("write upload headers: %v", err)
	}
	if _, err := client.Write(body[:len(body)/2]); err != nil {
		t.Fatalf("write first upload chunk: %v", err)
	}
	time.Sleep(3 * timeout)
	if _, err := client.Write(body[len(body)/2:]); err != nil {
		t.Fatalf("write delayed upload chunk: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read response after slow upload: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	var action dashboard.ActionResponse
	if err := json.NewDecoder(response.Body).Decode(&action); err != nil {
		t.Fatalf("read upload result: %v", err)
	}
	if response.StatusCode != http.StatusCreated || !action.OK {
		t.Fatalf("upload response = %s, %+v", response.Status, action)
	}
}

func TestHTTPWriteTimeoutRemainsBounded(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, 42 * time.Second} {
		settings := config.NewSettings(false)
		if err := settings.OverwriteForTestDuration(config.TIMEOUT, timeout); err != nil {
			t.Fatalf("set timeout: %v", err)
		}
		want := timeout
		if want <= 0 {
			want = defaultHTTPWriteTimeout
		}
		if got := httpWriteTimeout(settings); got != want {
			t.Fatalf("HTTP write timeout for TIMEOUT=%v is %v, want %v", timeout, got, want)
		}
	}
}
