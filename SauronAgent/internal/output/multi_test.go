package output

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/define42/SauronAgent/internal/config"
)

// recordingSink is a destination whose behaviour a test dictates, standing in
// for a file that has filled up or a syslog daemon that is down.
type recordingSink struct {
	mu       sync.Mutex
	name     string
	writeErr error
	flushErr error
	closeErr error

	got     []*Envelope
	flushes int
	closes  int
}

func (r *recordingSink) Write(ctx context.Context, env *Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeErr != nil {
		return r.writeErr
	}
	r.got = append(r.got, env)
	return nil
}

func (r *recordingSink) Flush(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushes++
	return r.flushErr
}

func (r *recordingSink) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closes++
	return r.closeErr
}

func (r *recordingSink) Name() string { return r.name }

func (r *recordingSink) received() []*Envelope {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*Envelope(nil), r.got...)
}

func TestMultiWritesToEverySink(t *testing.T) {
	a := &recordingSink{name: "a"}
	b := &recordingSink{name: "b"}
	m := NewMulti(a, b)

	env := execEnvelope(12)
	if err := m.Write(context.Background(), env); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, s := range []*recordingSink{a, b} {
		got := s.received()
		if len(got) != 1 || got[0] != env {
			t.Errorf("sink %s received %d envelopes, want the one written", s.name, len(got))
		}
	}
	if m.Name() != "multi(a,b)" {
		t.Errorf("Name = %q, want %q", m.Name(), "multi(a,b)")
	}
}

// One broken destination must not hide events from the working ones, and the
// failure must still reach the caller so the guest is not acknowledged.
func TestMultiKeepsGoingAfterAFailure(t *testing.T) {
	diskFull := errors.New("no space left on device")
	a := &recordingSink{name: "stdout"}
	b := &recordingSink{name: "file", writeErr: diskFull}
	c := &recordingSink{name: "syslog"}
	m := NewMulti(a, b, c)

	env := execEnvelope(1)
	err := m.Write(context.Background(), env)
	if err == nil {
		t.Fatal("Write returned nil although a sink failed: the event would be acknowledged without being stored")
	}
	if !errors.Is(err, diskFull) {
		t.Errorf("error %v does not wrap the sink failure", err)
	}
	if !strings.Contains(err.Error(), "file:") {
		t.Errorf("error %q does not name the failing sink", err)
	}
	for _, s := range []*recordingSink{a, c} {
		if len(s.received()) != 1 {
			t.Errorf("sink %s was skipped because an earlier sink failed", s.name)
		}
	}
}

func TestMultiJoinsEveryFailure(t *testing.T) {
	first := errors.New("syslog daemon is down")
	second := errors.New("read-only file system")
	ok := &recordingSink{name: "stdout"}
	m := NewMulti(&recordingSink{name: "syslog", writeErr: first}, ok, &recordingSink{name: "file", writeErr: second})

	err := m.Write(context.Background(), execEnvelope(1))
	if err == nil {
		t.Fatal("Write returned nil although two sinks failed")
	}
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Errorf("error %v does not carry both failures", err)
	}
	joined, isJoin := err.(interface{ Unwrap() []error })
	if !isJoin {
		t.Fatalf("error %T is not an errors.Join result", err)
	}
	if got := len(joined.Unwrap()); got != 2 {
		t.Errorf("joined %d errors, want 2", got)
	}
	if len(ok.received()) != 1 {
		t.Error("the working sink did not receive the envelope")
	}
}

func TestMultiFlush(t *testing.T) {
	boom := errors.New("fsync failed")
	a := &recordingSink{name: "a", flushErr: boom}
	b := &recordingSink{name: "b"}
	m := NewMulti(a, b)

	err := m.Flush(context.Background())
	if !errors.Is(err, boom) {
		t.Errorf("Flush err = %v, want it to carry %v", err, boom)
	}
	if a.flushes != 1 || b.flushes != 1 {
		t.Errorf("flushes: a=%d b=%d, want every sink flushed once", a.flushes, b.flushes)
	}
}

// A failing Close must not leave the remaining sinks open: their file handles
// and daemon connections would outlive the collector's shutdown.
func TestMultiCloseClosesEverything(t *testing.T) {
	boom := errors.New("closing the log file failed")
	a := &recordingSink{name: "a"}
	b := &recordingSink{name: "b", closeErr: boom}
	c := &recordingSink{name: "c"}
	m := NewMulti(a, b, c)

	err := m.Close()
	if !errors.Is(err, boom) {
		t.Errorf("Close err = %v, want it to carry %v", err, boom)
	}
	for _, s := range []*recordingSink{a, b, c} {
		if s.closes != 1 {
			t.Errorf("sink %s closed %d times, want 1", s.name, s.closes)
		}
	}
}

func TestMultiIgnoresNilSinks(t *testing.T) {
	a := &recordingSink{name: "a"}
	m := NewMulti(nil, a, nil)
	if err := m.Write(context.Background(), execEnvelope(1)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(a.received()) != 1 {
		t.Error("the real sink did not receive the envelope")
	}
	if m.Name() != "multi(a)" {
		t.Errorf("Name = %q, want %q", m.Name(), "multi(a)")
	}
}

func TestBuildRequiresAnEnabledOutput(t *testing.T) {
	s, err := Build(config.OutputSection{})
	if err == nil {
		_ = s.Close()
		t.Fatal("Build succeeded with every output disabled: the collector would discard every event it acknowledges")
	}
	if !errors.Is(err, errNoOutputs) {
		t.Errorf("err = %v, want errNoOutputs", err)
	}
	if s != nil {
		t.Error("Build returned a sink alongside an error")
	}
}

func TestBuildEnabledSinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	s, err := Build(config.OutputSection{
		Stdout: config.StdoutOutput{Enabled: false},
		File:   config.FileOutput{Enabled: true, Path: path, MaxFiles: 2},
		Syslog: config.SyslogOutput{Enabled: false},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer func() { _ = s.Close() }()

	if s.Name() != "multi(file)" {
		t.Errorf("Name = %q, want %q", s.Name(), "multi(file)")
	}
	if err := s.Write(context.Background(), execEnvelope(3)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got, want := readSequences(t, path), []uint64{3}; !equalSeq(got, want) {
		t.Errorf("file holds %v, want %v", got, want)
	}
}

// A constructor failing part way through must not leave the sinks that were
// already opened holding file descriptors.
func TestBuildClosesOpenedSinksWhenALaterOneFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	cfg := config.OutputSection{
		Stdout: config.StdoutOutput{Enabled: true},
		File:   config.FileOutput{Enabled: true, Path: path},
		Syslog: config.SyslogOutput{Enabled: true, Facility: "not-a-facility"},
	}
	before := openFileDescriptors(t)
	s, err := Build(cfg)
	if err == nil {
		_ = s.Close()
		t.Fatal("Build accepted an unknown syslog facility")
	}
	if s != nil {
		t.Error("Build returned a sink alongside an error")
	}
	if after := openFileDescriptors(t); after > before {
		t.Errorf("open file descriptors grew from %d to %d: the file sink was left open", before, after)
	}
}

// openFileDescriptors counts this process's open descriptors, which is how a
// leaked log file shows up on Linux.
func openFileDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("/proc is unavailable: %v", err)
	}
	return len(entries)
}
