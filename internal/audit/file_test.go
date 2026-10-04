package audit

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAuditFileCommitsNewDirectoryAncestry(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "new-parent")
	leaf := filepath.Join(parent, "new-leaf")
	directories, err := auditDirectoriesToSync(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{leaf, parent, base}; !slices.Equal(directories, want) {
		t.Fatalf("directories needed to publish the new file = %v, want %v", directories, want)
	}
	f, err := newAuditFile(filepath.Join(leaf, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("record\n")); err != nil {
		t.Fatal(err)
	}
	// Reopening an existing file still commits its immediate parent because
	// an external rotator may have created it without syncing that directory.
	directories, err = auditDirectoriesToSync(leaf)
	if err != nil || !slices.Equal(directories, []string{leaf}) {
		t.Fatalf("directories needed on reopen = %v, error = %v", directories, err)
	}
}

func TestAuditDirectorySyncFailureIsReturned(t *testing.T) {
	// procfs accepts directory opens but cannot persist them. This exercises
	// a real fsync failure without changing any process or kernel settings:
	// opening comm does not change it, and this test never writes to it.
	if _, err := os.Stat("/proc/self"); err != nil {
		t.Skip("procfs is unavailable")
	}
	f, err := newAuditFile("/proc/self/comm")
	if f != nil {
		_ = f.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "sync audit log directory") {
		t.Fatalf("uncommitted directory was accepted: %v", err)
	}
}

func TestAuditFileFailureIsReportedAndLatched(t *testing.T) {
	previous := log.Writer()
	var diagnostics bytes.Buffer
	log.SetOutput(&diagnostics)
	t.Cleanup(func() { log.SetOutput(previous) })
	closer, err := Configure(Options{FilePath: "/dev/full"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	sink := closer.(*configuredSink)
	Log(t.Context(), Event{Action: ActionUserLogin, User: "private-record-content"})
	if sink.Readiness() == nil {
		t.Fatal("failed file audit remained ready")
	}
	if !strings.Contains(diagnostics.String(), "audit: record persistence failed") {
		t.Fatalf("failed write had no operational diagnostic: %s", diagnostics.String())
	}
	if strings.Contains(diagnostics.String(), "private-record-content") {
		t.Fatal("failure diagnostic leaked record contents")
	}
	if closer.Close() == nil {
		t.Fatal("Close concealed the rejected audit record")
	}
}

func TestAuditFileFollowsRenameRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	closer, err := Configure(Options{FilePath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	Log(t.Context(), Event{Action: ActionUserLogin, User: "before"})
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	Log(t.Context(), Event{Action: ActionUserLogin, User: "after"})
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ path, want, absent string }{
		{path: path + ".1", want: `"user":"before"`, absent: `"user":"after"`},
		{path: path, want: `"user":"after"`, absent: `"user":"before"`},
	} {
		t.Run(filepath.Base(tt.path), func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil || !bytes.Contains(data, []byte(tt.want)) || bytes.Contains(data, []byte(tt.absent)) {
				t.Fatalf("rotation destination %s: data=%s error=%v", tt.path, data, err)
			}
		})
	}
}

func TestAuditFileRecoveryDoesNotEraseLossSignal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	closer, err := Configure(Options{FilePath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	Log(t.Context(), Event{Action: ActionUserLogin, User: "rejected"})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	Log(t.Context(), Event{Action: ActionUserLogin, User: "recovered"})
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte(`"user":"recovered"`)) {
		t.Fatalf("recovered file does not accept writes: %s, %v", data, err)
	}
	if closer.(*configuredSink).Readiness() == nil {
		t.Fatal("successful later write erased the audit loss signal")
	}
}

func TestAuditFileRejectsFailedSync(t *testing.T) {
	// /dev/null accepts the write but cannot fsync it. A successful Write alone
	// must not count as durable acceptance.
	f, err := newAuditFile("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("record\n")); err == nil || !strings.Contains(err.Error(), "sync audit file") {
		t.Fatalf("write without successful fsync = %v", err)
	}
}

func TestAuditWriterRejectsShortWrites(t *testing.T) {
	health := &auditHealth{}
	w := observedAuditWriter{destination: shortAuditWriter{}, health: health}
	if _, err := w.Write([]byte("record")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v", err)
	}
	if !errors.Is(health.status(), io.ErrShortWrite) {
		t.Fatal("short write was not observable")
	}
}

type shortAuditWriter struct{}

func (shortAuditWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
