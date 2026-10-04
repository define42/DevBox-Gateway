package sauron

import (
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCollectorFailureObservableBeforeBlockedInventoryDrains(t *testing.T) {
	listener := &healthTestListener{fail: make(chan error, 1), closed: make(chan struct{})}
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var releaseOnce sync.Once
	c := startTestCollector(t, Options{
		Port: 9000, EventLogFile: filepath.Join(t.TempDir(), "events.jsonl"), listener: listener,
		ExpectedVMs: func() ([]VM, error) {
			close(lookupStarted)
			<-releaseLookup
			return nil, nil
		},
	})
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseLookup) }) })
	select {
	case <-lookupStarted:
	case <-time.After(testTimeout):
		t.Fatal("inventory lookup never started")
	}
	failure := errors.New("permanent listener failure")
	listener.fail <- failure
	select {
	case <-c.Done():
	case <-time.After(testTimeout):
		t.Fatal("collector hid its failure behind the blocked inventory callback")
	}
	if !errors.Is(c.Err(), failure) || !errors.Is(c.Readiness(), failure) {
		t.Fatalf("collector failure was not observable: Err=%v Readiness=%v", c.Err(), c.Readiness())
	}
	releaseOnce.Do(func() { close(releaseLookup) })
	if err := c.Close(); !errors.Is(err, failure) {
		t.Fatalf("Close = %v, want original failure", err)
	}
}

func TestCollectorReadinessTracksOrderlyClose(t *testing.T) {
	c := startTestCollector(t, Options{
		Port: 9000, EventLogFile: filepath.Join(t.TempDir(), "events.jsonl"), listener: tcpListener(t),
	})
	if err := c.Readiness(); err != nil || c.Err() != nil {
		t.Fatalf("new collector not ready: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
	default:
		t.Fatal("orderly close did not signal Done")
	}
	if c.Readiness() == nil || c.Err() != nil {
		t.Fatalf("closed collector status: readiness=%v err=%v", c.Readiness(), c.Err())
	}
}

func TestExpectedVMsPreserveTrustedIdentityAndErrors(t *testing.T) {
	if expectedVMs(nil) != nil {
		t.Fatal("nil callback must preserve standalone monitor behavior")
	}
	failure := errors.New("inventory unavailable")
	listErr := error(nil)
	list := expectedVMs(func() ([]VM, error) {
		return []VM{{CID: 102, Name: "desktop", UUID: "vm-id", Owner: "alice"}}, listErr
	})
	vms, err := list()
	if err != nil || len(vms) != 1 || vms[0].CID != 102 || vms[0].UUID != "vm-id" ||
		vms[0].Name != "desktop" || vms[0].Labels["owner"] != "alice" || !vms[0].Expected {
		t.Fatalf("expected mapping = %+v, error = %v", vms, err)
	}
	listErr = failure
	if _, err := list(); !errors.Is(err, failure) {
		t.Fatalf("expected lookup error = %v, want %v", err, failure)
	}
}

type healthTestListener struct {
	fail   chan error
	closed chan struct{}
	once   sync.Once
}

func (l *healthTestListener) Accept() (net.Conn, error) {
	select {
	case err := <-l.fail:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *healthTestListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (*healthTestListener) Addr() net.Addr { return &net.TCPAddr{} }
