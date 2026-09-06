package rdp

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
)

func testConnectionAuthorization(t *testing.T, manager *session.Manager, username string) session.ConnectionAuthorization {
	t.Helper()
	ctx, err := manager.Load(t.Context(), "")
	if err != nil {
		t.Fatalf("load new connection session: %v", err)
	}
	user, err := identity.New(username)
	if err != nil {
		t.Fatalf("create connection user: %v", err)
	}
	if err := manager.CreateSession(ctx, user, "192.0.2.186:5000", ""); err != nil {
		t.Fatalf("create connection session: %v", err)
	}
	if _, _, err := manager.Commit(ctx); err != nil {
		t.Fatalf("commit connection session: %v", err)
	}
	authorization, allowed := manager.AuthorizeConnection(ctx)
	if !allowed {
		t.Fatal("stored session did not authorize a connection")
	}
	return authorization
}

func TestHandleRejectsConnectionAfterLogoutDuringBackendSetup(t *testing.T) {
	InitLogging()
	name := covxUniqueName("latelogout")
	backendHost := "127.0.0.75"
	stubVMIPs(t, map[string]string{name: backendHost})
	covxDefineOwnedDomain(t, name)
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	manager := session.New()
	issueUserSession(t, manager, "alice", "192.0.2.186:5000", name)
	requested, negotiated, resume := startPausedRDPBackend(t, backendHost)
	defer resume()

	client, done := startHandleTestConnection(t, frontTLS, manager, settings, "192.0.2.186")
	t.Cleanup(func() {
		_ = client.Close()
		waitDone(t, done)
	})
	tlsClient := performFrontHandshake(t, client, name+".example.test")
	clientClosed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
		close(clientClosed)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		waitDone(t, clientClosed)
	})

	// The backend CRQ is sent only after the old session's grant is consumed.
	waitDone(t, requested)
	if err := manager.DestroyAllSessionsForUser("alice"); err != nil {
		t.Fatalf("destroy sessions during backend setup: %v", err)
	}
	if closed := manager.CloseUserConnections("alice"); closed != 0 {
		t.Fatalf("closed %d proxies before backend setup finished, want 0", closed)
	}
	// A new login must not revive authorization captured before logout.
	issueUserSession(t, manager, "alice", "192.0.2.186:5000")
	resume()
	waitDone(t, negotiated)
	waitDone(t, done)
}

func startPausedRDPBackend(t *testing.T, host string) (<-chan struct{}, <-chan struct{}, func()) {
	t.Helper()
	requested := make(chan struct{})
	negotiated := make(chan struct{})
	released := make(chan struct{})
	resume := sync.OnceFunc(func() { close(released) })
	certificate := backendTLSCert(t)
	stop := startBackendServer(t, host, func(raw net.Conn) {
		if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("set backend deadline: %v", err)
			return
		}
		if !expectTLSOnlyBackendCRQ(t, raw) {
			return
		}
		close(requested)
		<-released
		if err := writeTPKT(raw, buildServerCCFSelectTLS()); err != nil {
			t.Errorf("backend write CCF: %v", err)
			return
		}
		backend := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
		if err := backend.Handshake(); err != nil {
			t.Errorf("backend TLS handshake: %v", err)
			return
		}
		close(negotiated)
		_, _ = io.Copy(io.Discard, backend)
	})
	t.Cleanup(stop)
	t.Cleanup(resume)
	return requested, negotiated, resume
}
