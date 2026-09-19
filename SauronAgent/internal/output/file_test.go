package output

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/define42/SauronAgent/internal/config"
)

// readSequences returns the event sequence numbers found in path, failing the
// test if any line is not a complete envelope: a half written line is the
// failure mode rotation and concurrency are most likely to produce.
func readSequences(t *testing.T, path string) []uint64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	trimmed := strings.TrimSuffix(string(data), "\n")
	if trimmed == "" {
		return nil
	}
	var seqs []uint64
	for i, line := range strings.Split(trimmed, "\n") {
		var env Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("%s line %d is not a complete JSON object (%v): %q", path, i+1, err, line)
		}
		if env.Event == nil {
			t.Fatalf("%s line %d carries no event: %q", path, i+1, line)
		}
		if env.Source.VM == "" {
			t.Fatalf("%s line %d lost the trusted source block: %q", path, i+1, line)
		}
		seqs = append(seqs, env.Event.Sequence)
	}
	return seqs
}

// lineSize is the exact encoded size of one envelope, which rotation
// thresholds in these tests are expressed in.
func lineSize(t *testing.T, env *Envelope) int64 {
	t.Helper()
	line, err := marshalLine(env, false)
	if err != nil {
		t.Fatalf("marshalLine: %v", err)
	}
	return int64(len(line))
}

func mustFileSink(t *testing.T, cfg config.FileOutput) Sink {
	t.Helper()
	s, err := NewFile(cfg)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestFileWritesNDJSONIntoCreatedDirectories(t *testing.T) {
	dir := t.TempDir()
	// A path several levels below the configured directory: the collector is
	// normally the first thing to run after packaging, so nothing has created
	// /var/log/sauronhost yet.
	path := filepath.Join(dir, "sauronhost", "events", "events.json")
	s := mustFileSink(t, config.FileOutput{Enabled: true, Path: path})

	ctx := context.Background()
	for seq := uint64(1); seq <= 3; seq++ {
		if err := s.Write(ctx, execEnvelope(seq)); err != nil {
			t.Fatalf("Write %d: %v", seq, err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got, want := readSequences(t, path), []uint64{1, 2, 3}; !equalSeq(got, want) {
		t.Errorf("sequences = %v, want %v", got, want)
	}
	if s.Name() != "file" {
		t.Errorf("Name = %q, want %q", s.Name(), "file")
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence", "events.json")
	s := mustFileSink(t, config.FileOutput{Enabled: true, Path: path})
	if err := s.Write(context.Background(), execEnvelope(1)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != fs.FileMode(0o640) {
		t.Errorf("file mode = %04o, want 0640: the event log must not be world-readable", got)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != fs.FileMode(0o750) {
		t.Errorf("directory mode = %04o, want 0750", got)
	}
}

// A file left behind by another tool, or by a previous version running under a
// looser umask, must not keep its permissions just because it already exists.
func TestFileTightensExistingPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o666); err != nil {
		t.Fatalf("pre-creating file: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	mustFileSink(t, config.FileOutput{Enabled: true, Path: path})

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != fs.FileMode(0o640) {
		t.Errorf("file mode = %04o, want 0640", got)
	}
}

func TestFileRotation(t *testing.T) {
	size := lineSize(t, execEnvelope(1))

	tests := []struct {
		name     string
		maxSize  int64
		maxFiles int
		events   uint64
		// want maps a suffix (0 for the live file) to the sequences it holds.
		want       map[int][]uint64
		wantAbsent []int
	}{
		{
			name:     "three per file, two kept",
			maxSize:  3 * size,
			maxFiles: 2,
			events:   10,
			want: map[int][]uint64{
				0: {10},
				1: {7, 8, 9},
				2: {4, 5, 6},
			},
			// Events 1-3 were in the generation pruned at MaxFiles.
			wantAbsent: []int{3, 4},
		},
		{
			name:     "nothing rotated before the limit is reached",
			maxSize:  10 * size,
			maxFiles: 4,
			events:   4,
			want: map[int][]uint64{
				0: {1, 2, 3, 4},
			},
			wantAbsent: []int{1, 2},
		},
		{
			name:     "rotation disabled keeps one growing file",
			maxSize:  0,
			maxFiles: 3,
			events:   12,
			want: map[int][]uint64{
				0: {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
			},
			wantAbsent: []int{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "events.json")
			s := mustFileSink(t, config.FileOutput{
				Enabled:  true,
				Path:     path,
				MaxSize:  config.Size(tt.maxSize),
				MaxFiles: tt.maxFiles,
			})
			ctx := context.Background()
			for seq := uint64(1); seq <= tt.events; seq++ {
				if err := s.Write(ctx, execEnvelope(seq)); err != nil {
					t.Fatalf("Write %d: %v", seq, err)
				}
			}
			if err := s.Flush(ctx); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			for suffix, want := range tt.want {
				name := path
				if suffix > 0 {
					name = fmt.Sprintf("%s.%d", path, suffix)
				}
				if got := readSequences(t, name); !equalSeq(got, want) {
					t.Errorf("%s holds %v, want %v", filepath.Base(name), got, want)
				}
				fi, err := os.Stat(name)
				if err != nil {
					t.Fatalf("stat %s: %v", name, err)
				}
				if got := fi.Mode().Perm(); got != fs.FileMode(0o640) {
					t.Errorf("%s mode = %04o, want 0640", filepath.Base(name), got)
				}
			}
			for _, suffix := range tt.wantAbsent {
				name := fmt.Sprintf("%s.%d", path, suffix)
				if _, err := os.Stat(name); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s exists, want it pruned at MaxFiles", filepath.Base(name))
				}
			}
		})
	}
}

// MaxFiles below one would mean rotation deletes the only copy of everything
// written since the last roll. One generation is kept instead.
func TestFileRotationKeepsAtLeastOneGeneration(t *testing.T) {
	size := lineSize(t, execEnvelope(1))
	path := filepath.Join(t.TempDir(), "events.json")
	s := mustFileSink(t, config.FileOutput{
		Enabled:  true,
		Path:     path,
		MaxSize:  config.Size(2 * size),
		MaxFiles: 0,
	})
	ctx := context.Background()
	for seq := uint64(1); seq <= 5; seq++ {
		if err := s.Write(ctx, execEnvelope(seq)); err != nil {
			t.Fatalf("Write %d: %v", seq, err)
		}
	}
	if got, want := readSequences(t, path), []uint64{5}; !equalSeq(got, want) {
		t.Errorf("live file holds %v, want %v", got, want)
	}
	if got, want := readSequences(t, path+".1"), []uint64{3, 4}; !equalSeq(got, want) {
		t.Errorf("rotated file holds %v, want %v", got, want)
	}
}

// An event bigger than MaxSize can never fit the budget. Dropping it would be
// exactly the silent loss the project exists to prevent, so it is written
// whole into a file of its own.
func TestFileOversizedEventIsStillWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	s := mustFileSink(t, config.FileOutput{
		Enabled:  true,
		Path:     path,
		MaxSize:  config.Size(32),
		MaxFiles: 4,
	})
	ctx := context.Background()
	for seq := uint64(1); seq <= 3; seq++ {
		if err := s.Write(ctx, execEnvelope(seq)); err != nil {
			t.Fatalf("Write %d: %v", seq, err)
		}
	}
	var all []uint64
	all = append(all, readSequences(t, path+".2")...)
	all = append(all, readSequences(t, path+".1")...)
	all = append(all, readSequences(t, path)...)
	if want := []uint64{1, 2, 3}; !equalSeq(all, want) {
		t.Errorf("sequences across generations = %v, want %v", all, want)
	}
}

func TestFileSyncOnWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	s := mustFileSink(t, config.FileOutput{Enabled: true, Path: path, SyncOnWrite: true})
	if err := s.Write(context.Background(), denialEnvelope(99)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := readSequences(t, path), []uint64{99}; !equalSeq(got, want) {
		t.Errorf("sequences = %v, want %v", got, want)
	}
}

// Under -race this also proves the rotation and the file handle are locked:
// a rename racing an append would produce short or missing lines.
func TestFileConcurrentWrites(t *testing.T) {
	size := lineSize(t, execEnvelope(1))

	tests := []struct {
		name     string
		maxSize  int64
		maxFiles int
	}{
		{name: "no rotation", maxSize: 0, maxFiles: 4},
		{name: "rotating under load", maxSize: 5 * size, maxFiles: 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				writers   = 16
				perWriter = 25
				total     = writers * perWriter
			)
			path := filepath.Join(t.TempDir(), "events.json")
			s := mustFileSink(t, config.FileOutput{
				Enabled:  true,
				Path:     path,
				MaxSize:  config.Size(tt.maxSize),
				MaxFiles: tt.maxFiles,
			})

			var wg sync.WaitGroup
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < perWriter; i++ {
						seq := uint64(w*perWriter + i + 1)
						if err := s.Write(context.Background(), execEnvelope(seq)); err != nil {
							t.Errorf("Write %d: %v", seq, err)
							return
						}
					}
				}(w)
			}
			wg.Wait()
			if err := s.Flush(context.Background()); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			matches, err := filepath.Glob(path + "*")
			if err != nil {
				t.Fatalf("glob: %v", err)
			}
			var got []uint64
			for _, name := range matches {
				got = append(got, readSequences(t, name)...)
			}
			if len(got) != total {
				t.Fatalf("got %d events across %d files, want %d: events were lost",
					len(got), len(matches), total)
			}
			want := make([]uint64, 0, total)
			for seq := uint64(1); seq <= total; seq++ {
				want = append(want, seq)
			}
			sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
			if !equalSeq(got, want) {
				t.Error("the set of delivered sequences does not match what was written")
			}
		})
	}
}

func TestFileWriteAfterCloseIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	s, err := NewFile(config.FileOutput{Enabled: true, Path: path})
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close is idempotent, but a write afterwards must not look accepted.
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := s.Write(context.Background(), execEnvelope(1)); !errors.Is(err, errSinkClosed) {
		t.Errorf("Write after Close = %v, want errSinkClosed", err)
	}
	if err := s.Flush(context.Background()); !errors.Is(err, errSinkClosed) {
		t.Errorf("Flush after Close = %v, want errSinkClosed", err)
	}
}

func TestNewFileRejectsBadConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.FileOutput
	}{
		{name: "empty path", cfg: config.FileOutput{Enabled: true}},
		{name: "blank path", cfg: config.FileOutput{Enabled: true, Path: "   "}},
		{
			name: "unusable directory",
			cfg:  config.FileOutput{Enabled: true, Path: filepath.Join(os.DevNull, "events.json")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewFile(tt.cfg)
			if err == nil {
				_ = s.Close()
				t.Fatal("NewFile succeeded, want an error")
			}
		})
	}
}

func TestFileRejectsNilEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	s := mustFileSink(t, config.FileOutput{Enabled: true, Path: path})
	if err := s.Write(context.Background(), nil); !errors.Is(err, errNilEnvelope) {
		t.Fatalf("err = %v, want errNilEnvelope", err)
	}
	if got := readSequences(t, path); len(got) != 0 {
		t.Errorf("file holds %v, want nothing", got)
	}
}

func equalSeq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
