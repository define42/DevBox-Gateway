package ldap

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldapclient "github.com/go-ldap/ldap/v3"
)

type ldapStallPhase struct {
	name     string
	scheme   string
	startTLS bool
	prepare  func(context.Context, net.Conn) error
}

func ldapStallPhases() []ldapStallPhase {
	return []ldapStallPhase{
		{name: "bind", scheme: "ldap", prepare: stallLDAPBind},
		{name: "search", scheme: "ldap", prepare: stallLDAPSearch},
		{name: "LDAPS handshake", scheme: "ldaps", prepare: readLDAPClientHello},
		{name: "StartTLS reply", scheme: "ldap", startTLS: true, prepare: stallLDAPStartTLSReply},
		{name: "StartTLS handshake", scheme: "ldap", startTLS: true, prepare: stallLDAPStartTLSHandshake},
	}
}

func TestAuthenticateAccessDeadlineAtEveryLDAPPhase(t *testing.T) {
	for _, phase := range ldapStallPhases() {
		t.Run(phase.name, func(t *testing.T) {
			t.Parallel()
			server := newLDAPStallServer(t, phase.prepare)
			settings := ldapStallSettings(t, server, phase, 500*time.Millisecond)
			result, _ := startLDAPTimeoutAttempt(t, server, settings)
			server.waitReady(t)
			assertLDAPTimeout(t, awaitLDAPTimeoutResult(t, result, 2*time.Second))
			server.waitClosed(t)
		})
	}
}

func TestAuthenticateAccessCancellationAtEveryLDAPPhase(t *testing.T) {
	for _, phase := range ldapStallPhases() {
		t.Run(phase.name, func(t *testing.T) {
			t.Parallel()
			server := newLDAPStallServer(t, phase.prepare)
			settings := ldapStallSettings(t, server, phase, time.Minute)
			result, cancel := startLDAPTimeoutAttempt(t, server, settings)
			server.waitReady(t)
			cancel()
			outcome := awaitLDAPTimeoutResult(t, result, 2*time.Second)
			if outcome.user != nil || !errors.Is(outcome.err, context.Canceled) {
				t.Fatalf("canceled authentication returned user=%v, err=%v", outcome.user, outcome.err)
			}
			server.waitClosed(t)
		})
	}
}

func TestAuthenticateAccessNonPositiveTimeoutUsesDefault(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{name: "zero"},
		{name: "negative", timeout: -time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := newLDAPStallServer(t, stallLDAPBind)
			settings := ldapStallSettings(t, server, ldapStallPhase{scheme: "ldap"}, tt.timeout)
			result, cancel := startLDAPTimeoutAttempt(t, server, settings)
			// Non-positive settings must leave enough time to connect and bind,
			// while the original request context must still cancel that attempt.
			server.waitReady(t)
			cancel()
			outcome := awaitLDAPTimeoutResult(t, result, 2*time.Second)
			if outcome.user != nil || !errors.Is(outcome.err, context.Canceled) {
				t.Fatalf("fallback timeout returned user=%v, err=%v", outcome.user, outcome.err)
			}
			server.waitClosed(t)
		})
	}
}

func TestAuthenticateAccessSharesDeadlineAcrossBindAndSearch(t *testing.T) {
	const timeout = 2 * time.Second
	const bindDelay = 1500 * time.Millisecond
	// A fresh timeout for search would take at least 3.5 seconds. Allow 750ms
	// scheduling headroom around the shared 2-second deadline.
	const maximumElapsed = timeout + 750*time.Millisecond
	prepare := func(ctx context.Context, conn net.Conn) error {
		return delayLDAPBindThenSearch(ctx, conn, bindDelay)
	}
	server := newLDAPStallServer(t, prepare)
	phase := ldapStallPhase{scheme: "ldap"}
	settings := ldapStallSettings(t, server, phase, timeout)
	started := time.Now()
	result, _ := startLDAPTimeoutAttempt(t, server, settings)
	server.waitReady(t)
	remaining := maximumElapsed - time.Since(started)
	if remaining <= 0 {
		t.Fatal("authentication exhausted the shared deadline before search")
	}
	assertLDAPTimeout(t, awaitLDAPTimeoutResult(t, result, remaining))
	server.waitClosed(t)
}

type ldapTimeoutResult struct {
	user *identity.User
	err  error
}

func startLDAPTimeoutAttempt(
	t *testing.T,
	server *ldapStallServer,
	settings *config.Settings,
) (<-chan ldapTimeoutResult, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan ldapTimeoutResult, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		// Closing the peer also releases an implementation that ignores the
		// request context, so a failed assertion cannot strand either goroutine.
		server.stop()
		<-done
	})
	go func() {
		defer close(done)
		user, err := AuthenticateAccess(ctx, "johndoe", "dogood", settings)
		result <- ldapTimeoutResult{user: user, err: err}
	}()
	return result, cancel
}

func awaitLDAPTimeoutResult(t *testing.T, result <-chan ldapTimeoutResult, timeout time.Duration) ldapTimeoutResult {
	t.Helper()
	select {
	case outcome := <-result:
		return outcome
	case <-time.After(timeout):
		t.Fatal("LDAP authentication did not return within its time budget")
		return ldapTimeoutResult{}
	}
}

func assertLDAPTimeout(t *testing.T, outcome ldapTimeoutResult) {
	t.Helper()
	if outcome.user != nil || outcome.err == nil {
		t.Fatalf("stalled authentication returned user=%v, err=%v", outcome.user, outcome.err)
	}
	var networkError net.Error
	if !errors.Is(outcome.err, context.DeadlineExceeded) &&
		!(errors.As(outcome.err, &networkError) && networkError.Timeout()) {
		t.Fatalf("expected a deadline error, got %v", outcome.err)
	}
}

type ldapStallServer struct {
	address string
	ready   chan struct{}
	done    chan struct{}
	failed  chan error
	stop    func()
}

func newLDAPStallServer(t *testing.T, prepare func(context.Context, net.Conn) error) *ldapStallServer {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen for LDAP client: %v", err)
	}
	server := &ldapStallServer{
		address: listener.Addr().String(),
		ready:   make(chan struct{}),
		done:    make(chan struct{}),
		failed:  make(chan error, 1),
	}
	server.stop = sync.OnceFunc(func() {
		cancel()
		_ = listener.Close()
		<-server.done
	})
	t.Cleanup(server.stop)
	go server.serve(ctx, listener, prepare)
	return server
}

func (server *ldapStallServer) serve(ctx context.Context, listener net.Listener, prepare func(context.Context, net.Conn) error) {
	defer close(server.done)
	conn, err := listener.Accept()
	if err != nil {
		server.failed <- err
		return
	}
	defer func() { _ = conn.Close() }()
	stopClosing := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClosing()
	if err := prepare(ctx, conn); err != nil {
		server.failed <- err
		return
	}
	close(server.ready)
	// Consume client traffic without replying, until authentication closes its
	// transport. Tests check this before cleanup closes the peer for them.
	_, _ = io.Copy(io.Discard, conn)
}

func (server *ldapStallServer) waitReady(t *testing.T) {
	t.Helper()
	select {
	case <-server.ready:
	case err := <-server.failed:
		t.Fatalf("fake LDAP server did not reach the requested phase: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("LDAP client did not reach the requested phase")
	}
}

func (server *ldapStallServer) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-server.done:
	case <-time.After(2 * time.Second):
		t.Fatal("LDAP client returned without closing its transport")
	}
}

func ldapStallSettings(t *testing.T, server *ldapStallServer, phase ldapStallPhase, timeout time.Duration) *config.Settings {
	t.Helper()
	settings := config.NewSettings(false)
	updates := []error{
		settings.OverwriteForTestString(config.LDAP_URL, phase.scheme+"://"+server.address),
		settings.OverwriteForTestString(config.LDAP_USER_DOMAIN, "@example.com"),
		settings.OverwriteForTestString(config.LDAP_USER_FILTER, "(mail=%s)"),
		settings.OverwriteForTestString(config.LDAP_BASE_DN, "dc=example,dc=com"),
		settings.OverwriteForTestBool(config.LDAP_STARTTLS, phase.startTLS),
		settings.OverwriteForTestBool(config.LDAP_SKIP_TLS_VERIFY, true),
		settings.OverwriteForTestDuration(config.LDAP_AUTH_TIMEOUT, timeout),
	}
	for _, err := range updates {
		if err != nil {
			t.Fatalf("configure stalled LDAP test: %v", err)
		}
	}
	return settings
}

func stallLDAPBind(_ context.Context, conn net.Conn) error {
	_, err := readLDAPRequest(conn, ldapclient.ApplicationBindRequest)
	return err
}

func stallLDAPSearch(ctx context.Context, conn net.Conn) error {
	return delayLDAPBindThenSearch(ctx, conn, 0)
}

func delayLDAPBindThenSearch(ctx context.Context, conn net.Conn, delay time.Duration) error {
	request, err := readLDAPRequest(conn, ldapclient.ApplicationBindRequest)
	if err != nil {
		return err
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := writeLDAPSuccess(conn, request, ldapclient.ApplicationBindResponse); err != nil {
		return err
	}
	_, err = readLDAPRequest(conn, ldapclient.ApplicationSearchRequest)
	return err
}

func stallLDAPStartTLSReply(_ context.Context, conn net.Conn) error {
	_, err := readLDAPRequest(conn, ldapclient.ApplicationExtendedRequest)
	return err
}

func stallLDAPStartTLSHandshake(ctx context.Context, conn net.Conn) error {
	request, err := readLDAPRequest(conn, ldapclient.ApplicationExtendedRequest)
	if err != nil {
		return err
	}
	if err := writeLDAPSuccess(conn, request, ldapclient.ApplicationExtendedResponse); err != nil {
		return err
	}
	return readLDAPClientHello(ctx, conn)
}

func readLDAPRequest(conn net.Conn, tag ber.Tag) (*ber.Packet, error) {
	packet, err := ber.ReadPacket(conn)
	if err != nil {
		return nil, err
	}
	if len(packet.Children) < 2 || packet.Children[1].Tag != tag {
		return nil, fmt.Errorf("expected LDAP request tag %d", tag)
	}
	return packet, nil
}

func writeLDAPSuccess(conn net.Conn, request *ber.Packet, tag ber.Tag) error {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP message")
	response.AppendChild(request.Children[0])
	operation := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "LDAP result")
	operation.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "success"))
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matched DN"))
	operation.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnostic"))
	response.AppendChild(operation)
	_, err := conn.Write(response.Bytes())
	return err
}

func readLDAPClientHello(_ context.Context, conn net.Conn) error {
	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 22 {
		return fmt.Errorf("expected TLS handshake record, got %d", header[0])
	}
	_, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(header[3:])))
	return err
}
