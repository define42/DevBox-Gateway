package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"

	"libvirt.org/go/libvirt"
)

// mcovCleanupStoragePool registers a cleanup that destroys and undefines the
// uniquely named storage pool a boot test asked bootGateway to create. Every
// step tolerates errors so cleanup of a pool that was never created is a no-op.
func mcovCleanupStoragePool(t *testing.T, name string) {
	t.Helper()
	t.Cleanup(func() {
		conn, err := libvirt.NewConnect(virt.LibvirtURI())
		if err != nil {
			return
		}
		defer func() { _, _ = conn.Close() }()

		pool, err := conn.LookupStoragePoolByName(name)
		if err != nil {
			return
		}
		defer func() { _ = pool.Free() }()

		if active, err := pool.IsActive(); err == nil && active {
			_ = pool.Destroy()
		}
		_ = pool.Undefine()
	})
}

// mcovBootEnv points bootGateway at a fully self-contained environment: a
// missing config file, an ephemeral loopback listen address, a temp data root,
// a placeholder base image, and a unique storage pool removed again on cleanup.
// It returns the data root so tests can plant failures inside it.
func mcovBootEnv(t *testing.T) string {
	t.Helper()

	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv(config.LISTEN_ADDR, "127.0.0.1:0")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.ACME_ENABLE, "false")
	t.Setenv(config.FRONT_DOMAIN, "mcov.gateway.test")
	t.Setenv(config.SNI_HASH_SECRET, "")

	root := newLibvirtAccessibleTempDir(t, "mcov-root-")
	t.Setenv(config.DATA_ROOT_DIR, root)

	baseImageDir := filepath.Join(t.TempDir(), "baseimages")
	if err := os.MkdirAll(baseImageDir, 0o755); err != nil {
		t.Fatalf("create base image dir %s: %v", baseImageDir, err)
	}
	imagePath := filepath.Join(baseImageDir, "mcov-base.img")
	if err := os.WriteFile(imagePath, []byte("placeholder"), 0o644); err != nil {
		t.Fatalf("seed base image %s: %v", imagePath, err)
	}
	t.Setenv(config.BASE_IMAGE_DIR, baseImageDir)

	poolName := fmt.Sprintf("mcov-pool-%d", time.Now().UnixNano())
	t.Setenv(config.VIRT_STORAGE_POOL_NAME, poolName)
	mcovCleanupStoragePool(t, poolName)
	return root
}

// mcovWriteBadConfigFile writes a config file whose first line is not KEY=VALUE
// so LoadConfigFile fails before mutating the process environment.
func mcovWriteBadConfigFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bad.conf")
	if err := os.WriteFile(path, []byte("this line has no equals sign\n"), 0o600); err != nil {
		t.Fatalf("write bad config file: %v", err)
	}
	return path
}

func TestMcovBootGatewaySuccessAndClose(t *testing.T) {
	mcovBootEnv(t)

	gateway, err := bootGateway()
	if err != nil {
		t.Fatalf("bootGateway: %v", err)
	}
	defer func() { _ = gateway.Close() }()

	addr, ok := gateway.listener.Addr().(*net.TCPAddr)
	if !ok || addr.Port == 0 {
		t.Fatalf("expected bound TCP listener, got %v", gateway.listener.Addr())
	}
	mcovAssertGatewayAcceptsTLS(t, addr.String())

	if err := gateway.Close(); err != nil {
		t.Fatalf("close gateway runtime: %v", err)
	}
}

// mcovAssertGatewayAcceptsTLS proves the booted gateway's accept loop dispatches
// connections: a completed TLS handshake requires the per-connection handler to
// be running on the server side.
func mcovAssertGatewayAcceptsTLS(t *testing.T, addr string) {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway listener: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "mcov.gateway.test",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake with gateway: %v", err)
	}
	_ = tlsConn.Close()
}

func TestMcovBootGatewayConfigFileError(t *testing.T) {
	t.Setenv(config.ConfigFileEnv, mcovWriteBadConfigFile(t))

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "failed to load config file") {
		t.Fatalf("expected config file load error, got %v", err)
	}
}

func TestMcovBootGatewayFrontDomainError(t *testing.T) {
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv(config.FRONT_DOMAIN, "")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), config.FRONT_DOMAIN) {
		t.Fatalf("expected FRONT_DOMAIN validation error, got %v", err)
	}
}

func TestMcovBootGatewayRejectsRemovedSSHTunnelMode(t *testing.T) {
	// A configuration preserved from before the SSH reverse-tunnel mode was
	// removed may still enable it; boot must fail fast instead of silently
	// binding LISTEN_ADDR on a host that never exposed a local listener.
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv("SSH_TUNNEL_ENABLE", "true")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "SSH reverse-tunnel mode has been removed") {
		t.Fatalf("expected removed SSH-tunnel mode error, got %v", err)
	}
}

func TestMcovBootGatewaySNIHashSecretError(t *testing.T) {
	root := mcovBootEnv(t)

	// A directory at the persisted secret path makes reading it fail with a
	// non-NotExist error after virt initialization has already succeeded.
	if err := os.Mkdir(filepath.Join(root, "sni_hash.secret"), 0o755); err != nil {
		t.Fatalf("create secret blocker dir: %v", err)
	}

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "failed to resolve SNI hash secret") {
		t.Fatalf("expected SNI hash secret error, got %v", err)
	}
}

func TestMcovBootGatewayListenError(t *testing.T) {
	mcovBootEnv(t)
	t.Setenv(config.LISTEN_ADDR, "bad::addr")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("expected listen error, got %v", err)
	}
}

func TestMcovRunReturnsOneOnBootFailure(t *testing.T) {
	t.Setenv(config.ConfigFileEnv, mcovWriteBadConfigFile(t))

	if code := Run(context.Background()); code != 1 {
		t.Fatalf("expected run to return 1 on boot failure, got %d", code)
	}
}

func TestMcovRunReturnsZeroOnCanceledContext(t *testing.T) {
	mcovBootEnv(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := Run(ctx); code != 0 {
		t.Fatalf("expected run to return 0 after cancellation, got %d", code)
	}
}

// mcovListener is a stub net.Listener whose Accept and Close fail with
// configurable errors, driving gatewayRuntime.Close and serveListener error
// branches deterministically.
type mcovListener struct {
	closeErr  error
	acceptErr error
}

func (l *mcovListener) Accept() (net.Conn, error) { return nil, l.acceptErr }
func (l *mcovListener) Close() error              { return l.closeErr }
func (l *mcovListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func TestMcovGatewayRuntimeCloseListenerError(t *testing.T) {
	closeErr := errors.New("mcov listener close failure")
	g := &gatewayRuntime{listener: &mcovListener{closeErr: closeErr}}
	if err := g.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("expected listener close error, got %v", err)
	}

	g = &gatewayRuntime{listener: &mcovListener{closeErr: net.ErrClosed}}
	if err := g.Close(); err != nil {
		t.Fatalf("expected net.ErrClosed to be ignored, got %v", err)
	}
}

func TestMcovGatewayRuntimeCloseDoneTimeout(t *testing.T) {
	// The accept loop never signals done, so Close must give up after its
	// internal five-second grace period and report the stall.
	g := &gatewayRuntime{done: make(chan struct{})}

	err := g.Close()
	if err == nil || !strings.Contains(err.Error(), "did not stop in time") {
		t.Fatalf("expected stop timeout error, got %v", err)
	}
}

func TestMcovSingleConnListenerCloseWithConnAccepted(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	listener := newSingleConnListener(server)
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Close while the accepted conn is still open: the listener itself must
	// release the done channel so a pending Accept unblocks.
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after close, got %v", err)
	}
	_ = conn.Close()
}

func TestMcovServeListenerStopsOnPermanentAcceptError(t *testing.T) {
	settings := config.NewSettingType(false)
	acceptErr := errors.New("mcov accept failure")
	ln := &mcovListener{acceptErr: acceptErr}

	errCh := make(chan error, 1)
	go func() {
		errCh <- serveListener(ln, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil, session.New(), settings)
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, acceptErr) {
			t.Fatalf("expected the permanent accept error to be returned, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveListener did not stop on a permanent accept error")
	}
}

// mcovDeadlineFailConn fails SetDeadline so setSetupDeadline's error branch can
// be driven without a broken socket.
type mcovDeadlineFailConn struct{ net.Conn }

func (c *mcovDeadlineFailConn) SetDeadline(time.Time) error {
	return errors.New("mcov deadline failure")
}

func TestMcovSetSetupDeadlineZeroTimeout(t *testing.T) {
	t.Setenv(config.TIMEOUT, "0s")
	settings := config.NewSettingType(false)

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	if !setSetupDeadline(server, settings) {
		t.Fatal("expected setSetupDeadline to succeed when the timeout is disabled")
	}
}

func TestMcovSetSetupDeadlineError(t *testing.T) {
	t.Setenv(config.TIMEOUT, "10s")
	settings := config.NewSettingType(false)

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	if setSetupDeadline(&mcovDeadlineFailConn{Conn: server}, settings) {
		t.Fatal("expected setSetupDeadline to fail when SetDeadline errors")
	}
}

func TestMcovHandleSharedConnDebugLogging(t *testing.T) {
	t.Setenv(config.DEBUG_CONNECTIONS, "true")
	frontTLS, settings := newTestTLSManager(t)

	cases := []struct {
		name    string
		payload []byte
	}{
		{"https", []byte{tlsHandshakeRecordType}},
		{"rdp", []byte{0x03, 0x00, 0x00, 0x02}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()

			done := make(chan struct{})
			go func() {
				handleSharedConn(server, frontTLS, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), session.New(), settings)
				close(done)
			}()

			if _, err := client.Write(tc.payload); err != nil {
				t.Fatalf("write first bytes: %v", err)
			}
			_ = client.Close()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("handleSharedConn did not return")
			}
		})
	}
}

func TestMcovHandleSharedConnEarlyExits(t *testing.T) {
	t.Setenv(config.TIMEOUT, "50ms")
	settings := config.NewSettingType(false)

	t.Run("peek timeout", func(t *testing.T) {
		// The client stays idle, so the 50ms setup deadline expires inside the
		// protocol-byte peek. Keeping the client open until handleSharedConn
		// returns avoids racing the deadline setup with a closed pipe.
		client, server := net.Pipe()
		defer func() { _ = client.Close() }()

		done := make(chan struct{})
		go func() {
			handleSharedConn(server, nil, nil, nil, settings)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleSharedConn did not return after the peek timed out")
		}
	})

	t.Run("deadline error", func(t *testing.T) {
		client, server := net.Pipe()
		defer func() { _ = client.Close() }()

		done := make(chan struct{})
		go func() {
			handleSharedConn(&mcovDeadlineFailConn{Conn: server}, nil, nil, nil, settings)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleSharedConn did not return after a deadline error")
		}
	})
}
