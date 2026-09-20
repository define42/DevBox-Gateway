package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
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
// a tiny QCOW2-header base image, and a unique storage pool removed again on cleanup.
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
	t.Setenv(config.AUDIT_LOG_FILE, filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv(config.SAURON_EVENT_LOG_FILE, filepath.Join(t.TempDir(), "sauron.jsonl"))
	t.Setenv(config.SAURON_SPLUNK_HEC_ENDPOINT, "")
	t.Setenv(config.SAURON_SPLUNK_HEC_TOKEN, "")
	t.Setenv(config.SAURON_SPLUNK_HEC_INDEX, "")

	root := newLibvirtAccessibleTempDir(t, "mcov-root-")
	t.Setenv(config.DATA_ROOT_DIR, root)

	baseImageDir := filepath.Join(t.TempDir(), "baseimages")
	if err := os.MkdirAll(baseImageDir, 0o755); err != nil {
		t.Fatalf("create base image dir %s: %v", baseImageDir, err)
	}
	imagePath := filepath.Join(baseImageDir, "mcov-base.img")
	if err := os.WriteFile(imagePath, []byte("QFI\xfbplaceholder"), 0o644); err != nil {
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
	requireSauronVSock(t)
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

func TestMcovBootGatewayForwardsAuditEventsToSplunkHEC(t *testing.T) {
	requireSauronVSock(t)
	mcovBootEnv(t)
	collector := newMcovHECCollector(t)
	t.Setenv(config.SPLUNK_HEC_ENDPOINT, collector.server.URL)
	t.Setenv(config.SPLUNK_HEC_TOKEN, "mcov-hec-token")
	t.Setenv(config.SPLUNK_HEC_INDEX, "mcov_audit")
	t.Setenv(config.SPLUNK_HEC_SKIP_TLS_VERIFY, "true")
	// A closed local port makes the LDAP bind, and so the login, fail fast.
	t.Setenv(config.LDAP_URL, "ldap://127.0.0.1:1")

	gateway, err := bootGateway()
	if err != nil {
		t.Fatalf("bootGateway: %v", err)
	}
	defer func() { _ = gateway.Close() }()

	mcovPostFailedLogin(t, gateway.listener.Addr().String())
	// Closing the gateway flushes queued HEC events before it returns.
	if err := gateway.Close(); err != nil {
		t.Fatalf("close gateway runtime: %v", err)
	}

	bodies, auths := collector.snapshot()
	for _, want := range []string{`"action":"user.login"`, `"result":"failure"`, `"index":"mcov_audit"`, `"sourcetype":"devbox-gateway:audit"`} {
		if !strings.Contains(bodies, want) {
			t.Errorf("collector bodies missing %s: %s", want, bodies)
		}
	}
	for _, auth := range auths {
		if auth != "Splunk mcov-hec-token" {
			t.Errorf("Authorization = %q, want the configured HEC token", auth)
		}
	}
}

// mcovHECCollector is a fake Splunk HEC that records every request.
type mcovHECCollector struct {
	mu     sync.Mutex
	bodies []string
	auths  []string
	server *httptest.Server
}

func newMcovHECCollector(t *testing.T) *mcovHECCollector {
	t.Helper()
	collector := &mcovHECCollector{}
	collector.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		collector.mu.Lock()
		collector.bodies = append(collector.bodies, string(body))
		collector.auths = append(collector.auths, r.Header.Get("Authorization"))
		collector.mu.Unlock()
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	t.Cleanup(collector.server.Close)
	return collector
}

func (c *mcovHECCollector) snapshot() (string, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.bodies, "\n"), append([]string(nil), c.auths...)
}

// mcovPostFailedLogin submits a same-origin login with bad credentials, which
// the real request path audits as a failed user.login.
func mcovPostFailedLogin(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "mcov.gateway.test"}, // #nosec G402 -- test client for the gateway's self-signed certificate
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	form := url.Values{"username": {"hec-probe"}, "password": {"wrong"}}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://mcov.gateway.test/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://mcov.gateway.test")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	_ = response.Body.Close()
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

func TestMcovBootGatewayLDAPUserDomainError(t *testing.T) {
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv(config.LDAP_USER_DOMAIN, "")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), config.LDAP_USER_DOMAIN) {
		t.Fatalf("expected LDAP_USER_DOMAIN validation error, got %v", err)
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

func TestMcovBootGatewayRDPPortError(t *testing.T) {
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv(config.RDP_PORT, "65536")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), config.RDP_PORT) {
		t.Fatalf("expected RDP_PORT validation error, got %v", err)
	}
}

func TestMcovBootGatewayRejectsRemovedSSHTunnelMode(t *testing.T) {
	// A configuration preserved from before the SSH reverse-tunnel mode was
	// removed may still enable it; boot must fail fast instead of silently
	// binding LISTEN_ADDR on a host that never exposed a local listener.
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv("SSH_TUNNEL_ENABLE", "true")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "ssh reverse-tunnel mode has been removed") {
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
	if err == nil || !strings.Contains(err.Error(), "failed to resolve sni hash secret") {
		t.Fatalf("expected SNI hash secret error, got %v", err)
	}
}

func TestMcovBootGatewayListenError(t *testing.T) {
	requireSauronVSock(t)
	mcovBootEnv(t)
	t.Setenv(config.LISTEN_ADDR, "bad::addr")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("expected listen error, got %v", err)
	}
}

func TestMcovBootGatewayAuditLogError(t *testing.T) {
	mcovBootEnv(t)
	// An audit file path that is itself a directory must fail before the
	// gateway starts accepting connections.
	t.Setenv(config.AUDIT_LOG_FILE, t.TempDir())

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "configure audit log") {
		t.Fatalf("expected audit log setup error, got %v", err)
	}
}

func TestMcovBootGatewayRejectsPartialSplunkHEC(t *testing.T) {
	// A HEC token without an endpoint means forwarding was intended but would
	// never happen; boot must fail instead of silently not forwarding.
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv(config.SPLUNK_HEC_ENDPOINT, "")
	t.Setenv(config.SPLUNK_HEC_TOKEN, "hec-token")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), config.SPLUNK_HEC_ENDPOINT) {
		t.Fatalf("expected SPLUNK_HEC_ENDPOINT validation error, got %v", err)
	}
}

func TestMcovBootGatewaySplunkHECEndpointError(t *testing.T) {
	t.Setenv(config.ConfigFileEnv, filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv(config.AUDIT_LOG_FILE, filepath.Join(t.TempDir(), "audit.jsonl"))
	t.Setenv(config.SPLUNK_HEC_ENDPOINT, "splunk.example.test:8088")
	t.Setenv(config.SPLUNK_HEC_TOKEN, "hec-token")

	_, err := bootGateway()
	if err == nil || !strings.Contains(err.Error(), "configure audit log") {
		t.Fatalf("expected audit log setup error for an endpoint without a scheme, got %v", err)
	}
}

func TestMcovAuditOptionsMapsSettings(t *testing.T) {
	t.Setenv(config.AUDIT_LOG_FILE, "/srv/audit/devbox.jsonl")
	t.Setenv(config.DATA_ROOT_DIR, "/srv/devbox")
	t.Setenv(config.DEVBOX_GATEWAY_SPOOL_MAX_MIB, "512")
	t.Setenv(config.SPLUNK_HEC_ENDPOINT, "https://splunk.example.test:8088")
	t.Setenv(config.SPLUNK_HEC_TOKEN, "hec-token")
	t.Setenv(config.SPLUNK_HEC_INDEX, "devbox_audit")
	t.Setenv(config.SPLUNK_HEC_ACK_ENABLED, "true")
	t.Setenv(config.SPLUNK_HEC_SKIP_TLS_VERIFY, "true")

	want := audit.Options{
		FilePath:      "/srv/audit/devbox.jsonl",
		SpoolDir:      "/srv/devbox/audit-spool",
		SpoolMaxBytes: 512 << 20,
		HEC: audit.HECConfig{
			Endpoint:           "https://splunk.example.test:8088",
			Token:              "hec-token",
			Index:              "devbox_audit",
			ACKEnabled:         true,
			InsecureSkipVerify: true,
		},
	}
	if got := auditOptions(config.NewSettings(false)); got != want {
		t.Fatalf("auditOptions() = %+v, want %+v", got, want)
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

type mcovShutdownAuditSink struct {
	order *[]string
}

func (s *mcovShutdownAuditSink) BeginShutdown() {
	*s.order = append(*s.order, "begin-audit-shutdown")
}

func (s *mcovShutdownAuditSink) Close() error {
	*s.order = append(*s.order, "close-audit")
	return nil
}

func TestMcovGatewayRuntimeBeginsAuditShutdownBeforeStoppingWorkers(t *testing.T) {
	var order []string
	gateway := &gatewayRuntime{
		auditSink: &mcovShutdownAuditSink{order: &order},
		stopAutoShutdown: func() {
			order = append(order, "stop-auto-shutdown")
		},
	}

	if err := gateway.Close(); err != nil {
		t.Fatalf("close gateway runtime: %v", err)
	}
	want := []string{"begin-audit-shutdown", "stop-auto-shutdown", "close-audit"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("shutdown order = %v, want %v", order, want)
	}
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
	settings := config.NewSettings(false)
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
	settings := config.NewSettings(false)

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	if !setSetupDeadline(server, settings) {
		t.Fatal("expected setSetupDeadline to succeed when the timeout is disabled")
	}
}

func TestMcovSetSetupDeadlineError(t *testing.T) {
	t.Setenv(config.TIMEOUT, "10s")
	settings := config.NewSettings(false)

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
	settings := config.NewSettings(false)

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
