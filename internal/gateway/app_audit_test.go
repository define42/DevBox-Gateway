package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/session"
)

type auditTestCloser struct {
	calls   int
	closeFn func()
	err     error
}

func (c *auditTestCloser) Close() error {
	c.calls++
	if c.closeFn != nil {
		c.closeFn()
	}
	return c.err
}

func TestGatewayRuntimeCloseWaitsForDisconnectAudit(t *testing.T) {
	output := captureStructuredLogs(t)
	sessionManager := session.New()
	transportClosed := make(chan struct{})
	handlerDone := make(chan struct{})

	unregister, ok := sessionManager.RegisterUserConnection("alice", func() {
		close(transportClosed)
	})
	if !ok {
		t.Fatal("expected connection registration to succeed")
	}
	go func() {
		<-transportClosed
		// RDP, serial, and noVNC handlers defer their disconnect audit after
		// deferring unregister, so this record is emitted before the drain signal.
		audit.Log(context.Background(), audit.Event{
			Action:   audit.ActionConnectionDisconnect,
			User:     "alice",
			VM:       "alice-desktop",
			Protocol: audit.ProtocolRDP,
		})
		unregister()
		close(handlerDone)
	}()

	auditPresentWhenSinkClosed := false
	auditSink := &auditTestCloser{closeFn: func() {
		auditPresentWhenSinkClosed = len(output.Bytes()) > 0
	}}
	gateway := &gatewayRuntime{
		sessionManager: sessionManager,
		auditSink:      auditSink,
	}
	if err := gateway.Close(); err != nil {
		t.Fatalf("close gateway runtime: %v", err)
	}
	if !auditPresentWhenSinkClosed {
		t.Fatal("audit sink closed before the disconnect record was emitted")
	}
	if err := gateway.Close(); err != nil {
		t.Fatalf("close gateway runtime a second time: %v", err)
	}
	if auditSink.calls != 1 {
		t.Fatalf("expected audit sink to close once, got %d calls", auditSink.calls)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not finish during runtime shutdown")
	}

	record := requireSingleAuditRecord(t, output)
	if record["action"] != audit.ActionConnectionDisconnect ||
		record["user"] != "alice" ||
		record["vm"] != "alice-desktop" ||
		record["protocol"] != audit.ProtocolRDP {
		t.Fatalf("unexpected shutdown disconnect audit record: %#v", record)
	}
}

func TestGatewayRuntimeCloseReturnsAuditSinkErrorIdempotently(t *testing.T) {
	wantErr := errors.New("audit sink close failure")
	auditSink := &auditTestCloser{err: wantErr}
	gateway := &gatewayRuntime{auditSink: auditSink}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := gateway.Close(); !errors.Is(err, wantErr) {
			t.Fatalf("close attempt %d: expected %v, got %v", attempt, wantErr, err)
		}
	}
	if auditSink.calls != 1 {
		t.Fatalf("expected one audit sink close, got %d", auditSink.calls)
	}
}
