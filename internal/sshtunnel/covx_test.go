package sshtunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestCovxChanConnDeadlinesAreNoOps(t *testing.T) {
	conn := chanConn{}
	when := time.Now().Add(time.Minute)

	if err := conn.SetDeadline(when); err != nil {
		t.Fatalf("SetDeadline should be a no-op, got %v", err)
	}
	if err := conn.SetReadDeadline(when); err != nil {
		t.Fatalf("SetReadDeadline should be a no-op, got %v", err)
	}
	if err := conn.SetWriteDeadline(when); err != nil {
		t.Fatalf("SetWriteDeadline should be a no-op, got %v", err)
	}
}

// covxFailingListener always fails Accept so the chanListener error branch can
// be driven without a live SSH connection.
type covxFailingListener struct{ err error }

func (l covxFailingListener) Accept() (net.Conn, error) { return nil, l.err }
func (covxFailingListener) Close() error                { return nil }
func (covxFailingListener) Addr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestCovxChanListenerAcceptError(t *testing.T) {
	acceptErr := errors.New("accept failed")
	listener := chanListener{Listener: covxFailingListener{err: acceptErr}}

	if _, err := listener.Accept(); !errors.Is(err, acceptErr) {
		t.Fatalf("expected the accept error to pass through, got %v", err)
	}
}

func TestCovxHostKeyProbeAddrAndKey(t *testing.T) {
	addr := hostKeyAlgorithmProbeAddr("203.0.113.7:22")
	if got := addr.Network(); got != "tcp" {
		t.Fatalf("probe addr network = %q, want tcp", got)
	}
	if got := addr.String(); got != "203.0.113.7:22" {
		t.Fatalf("probe addr string = %q, want 203.0.113.7:22", got)
	}

	key := hostKeyAlgorithmProbeKey{}
	if got := key.Type(); got == "" {
		t.Fatal("expected a non-empty probe key type")
	}
	if len(key.Marshal()) == 0 {
		t.Fatal("expected a non-empty probe key marshaling")
	}
	if err := key.Verify(nil, nil); err == nil {
		t.Fatal("expected the probe key to refuse signature verification")
	}
}

func TestCovxValidateServerAddressEmptyHost(t *testing.T) {
	err := validateServerAddress(":22")
	if err == nil || !strings.Contains(err.Error(), "include an IP address") {
		t.Fatalf("expected an empty-host error, got %v", err)
	}
}

func TestCovxHostKeyAlgorithmsForRSACert(t *testing.T) {
	got := hostKeyAlgorithmsForKeyType(ssh.CertAlgoRSAv01)
	want := []string{ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01}
	if len(got) != len(want) {
		t.Fatalf("expected %d algorithms for an RSA cert, got %v", len(want), got)
	}
	for i, algorithm := range want {
		if got[i] != algorithm {
			t.Fatalf("algorithm[%d] = %q, want %q (full list %v)", i, got[i], algorithm, got)
		}
	}
}

func TestCovxHostKeyAlgorithmsForKnownKeysDeduplicates(t *testing.T) {
	signer := mustLoadSigner(t, writeTestKey(t, nil))
	known := knownhosts.KnownKey{Key: signer.PublicKey()}

	got := hostKeyAlgorithmsForKnownKeys([]knownhosts.KnownKey{known, known})
	if len(got) != 1 || got[0] != signer.PublicKey().Type() {
		t.Fatalf("expected duplicate key types to collapse to one algorithm, got %v", got)
	}
}

func TestCovxHostKeyAlgorithmsForKnownHostErrors(t *testing.T) {
	const server = "203.0.113.7:22"

	t.Run("unexpected probe match", func(t *testing.T) {
		callback := func(string, net.Addr, ssh.PublicKey) error { return nil }
		_, err := hostKeyAlgorithmsForKnownHost(callback, server)
		if err == nil || !strings.Contains(err.Error(), "unexpectedly matched") {
			t.Fatalf("expected an unexpected-match error, got %v", err)
		}
	})

	t.Run("non key error passes through", func(t *testing.T) {
		callbackErr := errors.New("callback exploded")
		callback := func(string, net.Addr, ssh.PublicKey) error { return callbackErr }
		_, err := hostKeyAlgorithmsForKnownHost(callback, server)
		if !errors.Is(err, callbackErr) {
			t.Fatalf("expected the callback error to pass through, got %v", err)
		}
	})
}

func TestCovxLoadKnownHostsMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent_known_hosts")
	if _, _, err := loadKnownHosts(missing, "203.0.113.7:22"); err == nil {
		t.Fatal("expected an error for a missing known_hosts file")
	}
}

func TestCovxConnectSSHErrors(t *testing.T) {
	keyPath := writeTestKey(t, nil)
	missing := filepath.Join(t.TempDir(), "absent")

	t.Run("bad private key path", func(t *testing.T) {
		_, err := connectSSH(Config{
			User:           "tester",
			Server:         "203.0.113.7:22",
			PrivateKeyPath: missing,
			KnownHostsPath: keyPath,
		})
		if err == nil || !strings.Contains(err.Error(), "load private key") {
			t.Fatalf("expected a private key load error, got %v", err)
		}
	})

	t.Run("bad known hosts path", func(t *testing.T) {
		_, err := connectSSH(Config{
			User:           "tester",
			Server:         "203.0.113.7:22",
			PrivateKeyPath: keyPath,
			KnownHostsPath: missing,
		})
		if err == nil || !strings.Contains(err.Error(), "load known_hosts") {
			t.Fatalf("expected a known_hosts load error, got %v", err)
		}
	})
}

func TestCovxOpenValidateAndConnectErrors(t *testing.T) {
	if _, err := Open(Config{}); err == nil {
		t.Fatal("expected a validation error for an empty config")
	}

	_, err := Open(Config{
		User:             "tester",
		Server:           "203.0.113.7:22",
		PrivateKeyPath:   filepath.Join(t.TempDir(), "absent"),
		KnownHostsPath:   filepath.Join(t.TempDir(), "absent"),
		RemoteListenAddr: ":443",
	})
	if err == nil || !strings.Contains(err.Error(), "SSH connection failed") {
		t.Fatalf("expected an SSH connection failure, got %v", err)
	}
}

func TestCovxOpenRemoteListenDenied(t *testing.T) {
	addr, clientKeyPath, knownHostsPath := startCovxForwardDenyingServer(t)

	tunnel, err := Open(Config{
		User:              "tester",
		Server:            addr,
		PrivateKeyPath:    clientKeyPath,
		KnownHostsPath:    knownHostsPath,
		RemoteListenAddr:  "127.0.0.1:9",
		DialTimeout:       5 * time.Second,
		KeepAliveInterval: time.Second,
		KeepAliveTimeout:  time.Second,
	})
	if err == nil {
		_ = tunnel.Close()
		t.Fatal("expected Open to fail when the relay denies the forward")
	}
	if !strings.Contains(err.Error(), "remote listen") {
		t.Fatalf("expected a remote listen failure, got %v", err)
	}
}

// startCovxForwardDenyingServer starts an in-process SSH server that
// authenticates the generated client key but replies failure to every global
// request, so the client's tcpip-forward (Client.Listen) is denied.
func startCovxForwardDenyingServer(t *testing.T) (addr, clientKeyPath, knownHostsPath string) {
	t.Helper()

	hostSigner := mustLoadSigner(t, writeTestKey(t, nil))
	clientKeyPath = writeTestKey(t, nil)
	clientSigner := mustLoadSigner(t, clientKeyPath)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unknown public key")
		},
	}
	cfg.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go covxAcceptAndDenyForwards(listener, cfg)

	return listener.Addr().String(), clientKeyPath,
		writeKnownHosts(t, listener.Addr().String(), hostSigner.PublicKey())
}

func covxAcceptAndDenyForwards(listener net.Listener, cfg *ssh.ServerConfig) {
	for {
		nConn, err := listener.Accept()
		if err != nil {
			return
		}
		_, channels, requests, err := ssh.NewServerConn(nConn, cfg)
		if err != nil {
			_ = nConn.Close()
			continue
		}
		go rejectChannels(channels)
		go covxDenyGlobalRequests(requests)
	}
}

func covxDenyGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

func TestCovxReadOnceTerminalBranches(t *testing.T) {
	newIdleConn := func() *deadlineConn {
		return &deadlineConn{
			data:    make(chan []byte),
			done:    make(chan struct{}),
			closed:  make(chan struct{}),
			dlReset: make(chan struct{}),
		}
	}

	t.Run("closed connection", func(t *testing.T) {
		dc := newIdleConn()
		close(dc.closed)
		_, retry, err := dc.readOnce(make([]byte, 4))
		if retry || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed without retry, got retry=%v err=%v", retry, err)
		}
	})

	t.Run("pump error", func(t *testing.T) {
		dc := newIdleConn()
		pumpErr := errors.New("pump failed")
		dc.pumpErr = pumpErr
		close(dc.done)
		_, retry, err := dc.readOnce(make([]byte, 4))
		if retry || !errors.Is(err, pumpErr) {
			t.Fatalf("expected the pump error without retry, got retry=%v err=%v", retry, err)
		}
	})

	t.Run("clean end of stream", func(t *testing.T) {
		dc := newIdleConn()
		close(dc.done)
		_, retry, err := dc.readOnce(make([]byte, 4))
		if retry || !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF without retry, got retry=%v err=%v", retry, err)
		}
	})
}

func TestCovxPumpExitsOnCloseWithPendingChunk(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	conn := NewReadDeadlineConn(noDeadlineConn{Conn: server})
	dc, ok := conn.(*deadlineConn)
	if !ok {
		t.Fatalf("NewReadDeadlineConn returned %T, want *deadlineConn", conn)
	}

	// net.Pipe's Write returns once the pump goroutine has read the chunk; with
	// no Read pending, the pump then blocks handing the chunk over.
	if _, err := client.Write([]byte("pending")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := dc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case <-dc.done:
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not exit after Close while holding a pending chunk")
	}
	if dc.pumpErr != nil {
		t.Fatalf("expected the pump to exit via close, got pump error %v", dc.pumpErr)
	}
}

func TestCovxDeadlineConnWriteAndFullDeadline(t *testing.T) {
	client, server := net.Pipe()
	dc := NewReadDeadlineConn(noDeadlineConn{Conn: server})
	t.Cleanup(func() {
		_ = dc.Close()
		_ = client.Close()
	})

	if err := dc.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline should be a no-op, got %v", err)
	}
	if err := dc.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := dc.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected the full deadline to apply to reads, got %v", err)
	}
}
