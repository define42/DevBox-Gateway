package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/identity"
)

// These tests drive run() in process. Spawning the built binary is the
// end-to-end test's job; what matters here is the surface the packaging
// depends on -- the two flags, the built-in configuration the shipped unit
// runs on, and the two signals doing two different things.
//
// Nothing here sleeps to synchronise: the shutdown test polls for a state with
// a deadline, and the signal tests drive an injected channel.

const (
	// waitTimeout is generous; it only bounds a test that is already failing.
	waitTimeout  = 20 * time.Second
	pollInterval = 2 * time.Millisecond
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// syncWriter is an io.Writer that a test and the goroutine it started can both
// touch without arguing about happens-before.
type syncWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// deadTCPAddress returns a loopback address nothing is listening on, so that
// every dial fails immediately.
func deadTCPAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("closing the reserved port: %v", err)
	}
	return addr
}

// ---------------------------------------------------------------------------
// flags
// ---------------------------------------------------------------------------

func TestVersionFlagPrintsTheBuiltVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit status = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	// The Makefile stamps identity.Version with git describe, and the HELLO
	// message reports the same value: -version has to agree with it or an
	// operator cannot tell which build a guest is running.
	want := "sauronagent " + identity.Version
	if !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
}

func TestHelpFlagIsNotAFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-h"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit status = %d, want %d", code, exitOK)
	}
	for _, want := range []string{"-check-config", "-version"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("usage does not mention %s:\n%s", want, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "\n  -config ") {
		t.Errorf("usage still advertises the removed -config flag:\n%s", stderr.String())
	}
}

func TestUnknownFlagIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-not-a-flag"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit status = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "not-a-flag") {
		t.Errorf("stderr does not name the flag:\n%s", stderr.String())
	}
}

func TestConfigFlagIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", "ignored"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit status = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "-config") {
		t.Errorf("stderr does not name the removed flag:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing", stdout.String())
	}
}

// A stray argument is refused rather than ignored: it is far more likely to be
// a mistyped flag that was meant to change what is collected.
func TestUnexpectedArgumentIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-version", "extra"}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit status = %d, want %d", code, exitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("the version was printed anyway: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), `"extra"`) {
		t.Errorf("stderr does not name the argument:\n%s", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// -check-config
// ---------------------------------------------------------------------------

func TestCheckConfigReportsTheBuiltInConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-check-config"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit status = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "built-in configuration") {
		t.Errorf("stdout does not identify the built-in configuration:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "manage_rules=true") {
		t.Errorf("defaults do not enable automatic rule setup:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
}

// ---------------------------------------------------------------------------
// running and stopping
// ---------------------------------------------------------------------------

// A cancelled context is an orderly shutdown, not a failure: systemd stops the
// unit that way, and a non-zero status would make every clean stop look like a
// crash in the journal.
func TestRunStopsCleanlyWhenTheContextIsCancelled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "agent.log")
	// No netlink socket is opened, and the collector
	// address is a port nothing listens on, so the sender spends the test
	// failing to connect -- which is the state a real guest is in whenever the
	// hypervisor's collector is down, and it must still stop cleanly.
	cfg := config.DefaultAgent()
	cfg.Audit.Enabled = false
	cfg.Transport.Kind = config.TransportTCP
	cfg.Transport.TCPAddress = deadTCPAddress(t)
	cfg.Queue.Capacity = 64
	cfg.Spool.Path = filepath.Join(dir, "spool")
	cfg.Spool.MaxSize = config.Size(1 << 20)
	cfg.Spool.SegmentSize = config.Size(64 << 10)
	cfg.Reconnect.InitialDelay = config.Duration(20 * time.Millisecond)
	cfg.Reconnect.MaxDelay = config.Duration(20 * time.Millisecond)
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "text"
	cfg.Logging.Output = logPath
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test configuration is invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr syncWriter
	done := make(chan int, 1)
	go func() { done <- runAgent(ctx, cfg, &stdout, &stderr) }()

	// Wait for the agent to be up before stopping it, so the test covers a
	// running pipeline being torn down rather than a context that was already
	// cancelled when Run was called.
	waitFor(t, "the agent to log that it started", func() bool {
		data, err := os.ReadFile(logPath)
		return err == nil && strings.Contains(string(data), "sauronagent starting")
	})
	cancel()

	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("exit status = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
		}
	case <-time.After(waitTimeout):
		t.Fatal("run did not return after the context was cancelled")
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading the log: %v", err)
	}
	log := string(data)
	// The startup line is what ties a journal to a guest, the boot id is what
	// scopes the sequence numbers the collector deduplicates on, and the config
	// records that the executable's built-in policy is in force.
	for _, want := range []string{"boot_id=", "target=", "config=built-in", "sauronagent stopped"} {
		if !strings.Contains(log, want) {
			t.Errorf("log does not contain %q:\n%s", want, log)
		}
	}
	// The spool is the agent's promise that an outage costs nothing: it must
	// exist on disk after a run that never reached the host.
	if _, err := os.Stat(filepath.Join(dir, "spool")); err != nil {
		t.Errorf("the spool directory was not created: %v", err)
	}
}

// ---------------------------------------------------------------------------
// signals
// ---------------------------------------------------------------------------

func TestWatchSignalsCancelsThenExits(t *testing.T) {
	sigs := make(chan os.Signal, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exited := make(chan int, 1)
	done := make(chan struct{})
	defer close(done)

	var out syncWriter
	go watchSignals(done, sigs, cancel, &out, func(code int) { exited <- code })

	sigs <- syscall.SIGTERM
	select {
	case <-ctx.Done():
	case code := <-exited:
		t.Fatalf("the first signal exited with %d instead of starting an orderly shutdown", code)
	case <-time.After(waitTimeout):
		t.Fatal("the first signal did not cancel the context")
	}

	sigs <- syscall.SIGINT
	select {
	case code := <-exited:
		// 128+signal is the shell convention, so a supervisor can tell a
		// process that was told to stop from one that failed.
		if want := 128 + int(syscall.SIGINT); code != want {
			t.Errorf("exit status = %d, want %d", code, want)
		}
	case <-time.After(waitTimeout):
		t.Fatal("the second signal did not exit immediately")
	}

	// An operator who signalled twice is owed an explanation of what they
	// interrupted and where the events went.
	msg := out.String()
	if !strings.Contains(msg, "signal again") {
		t.Errorf("the first notice does not say a second signal exits:\n%s", msg)
	}
	if !strings.Contains(msg, "spool") {
		t.Errorf("the second notice does not say where undelivered events are:\n%s", msg)
	}
}

// A clean return from run() must not leave a goroutine parked on the signal
// channel.
func TestWatchSignalsReturnsWhenStopped(t *testing.T) {
	sigs := make(chan os.Signal, 2)
	done := make(chan struct{})
	returned := make(chan struct{})

	go func() {
		defer close(returned)
		watchSignals(done, sigs, func() { t.Error("the context was cancelled without a signal") }, &syncWriter{},
			func(int) { t.Error("the process exited without a signal") })
	}()

	close(done)
	select {
	case <-returned:
	case <-time.After(waitTimeout):
		t.Fatal("watchSignals did not return when it was stopped")
	}
}

// The handler has to be installed for real, not only tested through the
// injected channel: a SIGTERM that is not caught kills the process outright
// and the spool never gets its final sync.
func TestInstalledHandlerCatchesSIGTERM(t *testing.T) {
	var out syncWriter
	ctx, stop := installSignalHandler(context.Background(), &out)
	defer stop()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("signalling this process: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(waitTimeout):
		t.Fatal("SIGTERM did not cancel the root context")
	}

	// stop() must also release the context of a run that ended on its own.
	ctx2, stop2 := installSignalHandler(context.Background(), &out)
	stop2()
	select {
	case <-ctx2.Done():
	case <-time.After(waitTimeout):
		t.Fatal("stopping the handler did not cancel its context")
	}
}

func TestSignalExitCode(t *testing.T) {
	if got, want := signalExitCode(syscall.SIGTERM), 128+int(syscall.SIGTERM); got != want {
		t.Errorf("signalExitCode(SIGTERM) = %d, want %d", got, want)
	}
	if got := signalExitCode(fakeSignal("nonsense")); got != exitFailure {
		t.Errorf("signalExitCode(non-unix signal) = %d, want %d", got, exitFailure)
	}
}

// fakeSignal is an os.Signal that is not a syscall.Signal.
type fakeSignal string

func (f fakeSignal) String() string { return string(f) }
func (f fakeSignal) Signal()        {}

// ---------------------------------------------------------------------------
// startup hints
// ---------------------------------------------------------------------------

// The single most common deployment failure. The message has to name the
// capability and the unit, or an operator is left with "operation not
// permitted" and no way to know what to grant.
func TestStartupHintNamesTheCapabilityAndTheUnit(t *testing.T) {
	// The shape the audit package produces for an EPERM on the netlink socket.
	err := fmt.Errorf("audit: opening NETLINK_AUDIT socket: %w (the process needs CAP_AUDIT_READ "+
		"(for example AmbientCapabilities=CAP_AUDIT_READ in the systemd unit))", syscall.EPERM)

	hint := startupHint(defaultTestConfig(t), err)
	for _, want := range []string{"CAP_AUDIT_READ", "sauronagent.service", "AmbientCapabilities", "CapabilityBoundingSet"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint does not mention %q:\n%s", want, hint)
		}
	}
}

func TestStartupHintForAuditControl(t *testing.T) {
	err := fmt.Errorf("audit: configure rules requires CAP_AUDIT_CONTROL: %w", syscall.EPERM)
	hint := startupHint(defaultTestConfig(t), err)
	for _, want := range []string{"CAP_AUDIT_CONTROL", "sauronagent.service"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint does not mention %q: %s", want, hint)
		}
	}
	if strings.Contains(hint, "audit.manage_rules") {
		t.Errorf("hint recommends a removed configuration setting: %s", hint)
	}
}

func TestStartupHintForPrivateHomeDiscovery(t *testing.T) {
	err := fmt.Errorf("audit: private home directory requires CAP_DAC_READ_SEARCH: %w", syscall.EACCES)
	hint := startupHint(defaultTestConfig(t), err)
	for _, want := range []string{"CAP_DAC_READ_SEARCH", "ProtectHome=read-only", "sauronagent.service"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint does not mention %q: %s", want, hint)
		}
	}
	if strings.Contains(hint, "spool") {
		t.Errorf("home discovery failure was blamed on the spool: %s", hint)
	}
}

// A permission error that is not the netlink socket must not be answered with
// advice about a capability that has nothing to do with it.
func TestStartupHintForAnUnwritableSpoolPointsAtTheStateDirectory(t *testing.T) {
	cfg := defaultTestConfig(t)
	err := fmt.Errorf("spool: creating %s: %w", cfg.Spool.Path, syscall.EACCES)

	hint := startupHint(cfg, err)
	if strings.Contains(hint, "CAP_AUDIT_READ") {
		t.Errorf("a spool failure was blamed on the audit capability:\n%s", hint)
	}
	for _, want := range []string{cfg.Spool.Path, "StateDirectory"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint does not mention %q:\n%s", want, hint)
		}
	}
}

func TestStartupHintIsSilentForOtherFailures(t *testing.T) {
	if hint := startupHint(defaultTestConfig(t), fmt.Errorf("spool: corrupt segment")); hint != "" {
		t.Errorf("hint = %q, want none", hint)
	}
}

// defaultTestConfig is the built-in configuration, which -check-config has
// already been shown to accept.
func defaultTestConfig(t *testing.T) config.Agent {
	t.Helper()
	cfg := config.DefaultAgent()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validating the built-in configuration: %v", err)
	}
	return cfg
}
