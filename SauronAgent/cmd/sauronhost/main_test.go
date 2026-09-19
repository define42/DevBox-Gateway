package main

import (
	"bytes"
	"context"
	"fmt"
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
// depends on -- the three flags in ExecStart= and in the Makefile -- and the
// two rules a collector cannot get wrong: it does not start on a configuration
// it did not understand, and it does not exit without closing its sinks.
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

// writeConfig writes a configuration file into the test's temporary directory.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sauronhost.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
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

// ---------------------------------------------------------------------------
// flags
// ---------------------------------------------------------------------------

func TestVersionFlagPrintsTheBuiltVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit status = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	// Both binaries are stamped from the same -ldflags variable, so a
	// hypervisor and its guests can be compared build for build.
	want := "sauronhost " + identity.Version
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
	for _, want := range []string{"-config", "-check-config", "-version"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("usage does not mention %s:\n%s", want, stderr.String())
		}
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

func TestCheckConfigAcceptsAGoodFile(t *testing.T) {
	// The output path is a temporary one so that the "nothing was created"
	// assertion below is about this test and not about whatever the machine
	// running it happens to have in /var/log.
	eventsPath := filepath.Join(t.TempDir(), "events.json")
	path := writeConfig(t, fmt.Sprintf(`
host:
  name: hypervisor-07
listen:
  kind: vsock
  port: 9000
vms:
  - cid: 100
    name: web-frontend-01
    expected: true
  - cid: 101
    name: scratch-vm
output:
  stdout:
    enabled: false
  file:
    enabled: true
    path: %s
`, eventsPath))

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-check-config", "-config", path}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit status = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	want := []string{
		path, "is valid",
		"hypervisor-07",
		// The wildcard CID has to be spelled out: "4294967295" tells an
		// operator nothing, and a collector bound to one specific CID is deaf
		// to every other guest.
		"vsock cid any port 9000",
		"2 mapped, 1 expected",
		"file " + eventsPath,
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("summary does not report %q:\n%s", w, out)
		}
	}
	// Validating must not have side effects: no file sink is opened, so
	// nothing is created and no syslog connection is made.
	if _, err := os.Stat(eventsPath); !os.IsNotExist(err) {
		t.Errorf("-check-config touched the output file (stat error: %v)", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", stderr.String())
	}
}

// Two VMs sharing a CID would make every event from either of them
// unattributable, so the collector refuses to start rather than mislabel an
// audit trail.
func TestCheckConfigRejectsADuplicateCID(t *testing.T) {
	path := writeConfig(t, `
vms:
  - cid: 100
    name: a
  - cid: 100
    name: b
`)

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-check-config", "-config", path}, &stdout, &stderr); code == exitOK {
		t.Fatalf("exit status = %d, want non-zero (stdout: %s)", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "already mapped") {
		t.Errorf("stderr does not explain the duplicate:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "is valid") {
		t.Errorf("a rejected configuration was reported as valid:\n%s", stdout.String())
	}
}

func TestCheckConfigRejectsAMisspelledKey(t *testing.T) {
	path := writeConfig(t, "limits:\n  allow_unknown_cid: true\n")

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-check-config", "-config", path}, &stdout, &stderr); code == exitOK {
		t.Fatalf("exit status = %d, want non-zero", code)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "allow_unknown_cid") || !strings.Contains(msg, path) {
		t.Errorf("stderr does not name the key and the file:\n%s", msg)
	}
}

func TestMissingConfigFileIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yaml")

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", path}, &stdout, &stderr); code == exitOK {
		t.Fatalf("exit status = %d, want non-zero", code)
	}
	if !strings.Contains(stderr.String(), path) {
		t.Errorf("stderr does not name the file:\n%s", stderr.String())
	}
}

// A collector with every sink disabled would accept connections, acknowledge
// every event and discard all of it, which looks exactly like a healthy
// deployment until the evidence is needed.
func TestACollectorWithNoOutputRefusesToStart(t *testing.T) {
	path := writeConfig(t, `
listen:
  kind: tcp
  tcp_address: "127.0.0.1:0"
output:
  stdout:
    enabled: false
  file:
    enabled: false
  syslog:
    enabled: false
`)

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", path}, &stdout, &stderr); code == exitOK {
		t.Fatalf("exit status = %d, want non-zero", code)
	}
	if !strings.Contains(stderr.String(), "no output is enabled") {
		t.Errorf("stderr does not explain the missing output:\n%s", stderr.String())
	}
	// -check-config says the same thing before anything is started.
	var checkOut, checkErr bytes.Buffer
	if code := run(context.Background(), []string{"-check-config", "-config", path}, &checkOut, &checkErr); code != exitOK {
		t.Fatalf("-check-config exit status = %d, want %d", code, exitOK)
	}
	if !strings.Contains(checkOut.String(), "refuse to start") {
		t.Errorf("the summary does not warn that no sink is enabled:\n%s", checkOut.String())
	}
}

// ---------------------------------------------------------------------------
// running and stopping
// ---------------------------------------------------------------------------

// A cancelled context is an orderly shutdown, not a failure -- and the sinks
// must be closed on the way out. Losing the tail of the log on a restart would
// be exactly the silent evidence loss this collector exists to prevent.
func TestRunStopsCleanlyAndClosesTheOutput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "collector.log")
	eventsPath := filepath.Join(dir, "events.json")
	// The TCP listener keeps the test off AF_VSOCK, which needs a hypervisor;
	// everything from the accept loop onwards is the production path.
	path := writeConfig(t, fmt.Sprintf(`
host:
  name: test-hypervisor
listen:
  kind: tcp
  tcp_address: "127.0.0.1:0"
vms:
  - cid: 100
    name: web-frontend-01
    expected: true
output:
  stdout:
    enabled: false
  file:
    enabled: true
    path: %s
monitor:
  enabled: true
  timeout: 1s
  check_interval: 100ms
logging:
  level: info
  format: text
  output: %s
`, eventsPath, logPath))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var stdout, stderr syncWriter
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, &stdout, &stderr) }()

	// Wait until the listener is actually up, so the test tears down a running
	// collector rather than one whose context was cancelled before it started.
	waitFor(t, "the collector to report that it is listening", func() bool {
		data, err := os.ReadFile(logPath)
		return err == nil && strings.Contains(string(data), "collector listening")
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
	for _, want := range []string{"sauronhost starting", "mapped_vms=1", "sauronhost stopped"} {
		if !strings.Contains(log, want) {
			t.Errorf("log does not contain %q:\n%s", want, log)
		}
	}
	// The file sink was opened, which is what an enabled output has to do
	// before the first guest connects, and closing it is what makes what it
	// holds durable.
	if _, err := os.Stat(eventsPath); err != nil {
		t.Errorf("the output file was not created: %v", err)
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
		if want := 128 + int(syscall.SIGINT); code != want {
			t.Errorf("exit status = %d, want %d", code, want)
		}
	case <-time.After(waitTimeout):
		t.Fatal("the second signal did not exit immediately")
	}

	msg := out.String()
	if !strings.Contains(msg, "signal again") {
		t.Errorf("the first notice does not say a second signal exits:\n%s", msg)
	}
	if !strings.Contains(msg, "unflushed") {
		t.Errorf("the second notice does not say what is lost:\n%s", msg)
	}
}

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
// and the sinks are never flushed.
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

// EAFNOSUPPORT from the listener reads like a missing kernel module even when
// the real cause is a unit that does not allow AF_VSOCK, so the hint has to
// name both.
func TestStartupHintForAMissingVSOCKTransport(t *testing.T) {
	cfg := defaultTestConfig(t)
	err := fmt.Errorf("host: listen: vsock listen vm(4294967295):9000: no AF_VSOCK transport on this system: %w",
		syscall.EAFNOSUPPORT)

	hint := startupHint(cfg, err)
	for _, want := range []string{"vhost_vsock", "RestrictAddressFamilies", "sauronhost.service"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint does not mention %q:\n%s", want, hint)
		}
	}
}

func TestStartupHintForAPortAlreadyHeld(t *testing.T) {
	cfg := defaultTestConfig(t)
	err := fmt.Errorf("host: listen: %w", syscall.EADDRINUSE)

	hint := startupHint(cfg, err)
	if !strings.Contains(hint, "port 9000") {
		t.Errorf("hint does not name the listener:\n%s", hint)
	}
}

func TestStartupHintIsSilentForOtherFailures(t *testing.T) {
	if hint := startupHint(defaultTestConfig(t), fmt.Errorf("host: invalid configuration")); hint != "" {
		t.Errorf("hint = %q, want none", hint)
	}
}

// defaultTestConfig is the built-in configuration, which -check-config has
// already been shown to accept.
func defaultTestConfig(t *testing.T) config.Host {
	t.Helper()
	cfg, err := config.LoadHost("")
	if err != nil {
		t.Fatalf("loading the default configuration: %v", err)
	}
	return cfg
}
