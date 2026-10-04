package output

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
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

func TestFileDurableCreationSyncsParentsAndRetriesFailures(t *testing.T) {
	for _, failAt := range []string{"file", "directory", "ancestor", "file entry"} {
		t.Run(failAt, func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			path := filepath.Join(base, "new", "nested", "events.json")
			failPath := path
			switch failAt {
			case "directory", "file entry":
				failPath = filepath.Dir(path)
			case "ancestor":
				failPath = base
			}
			failed := false
			boom := errors.New("injected storage sync failure")
			var synced []string
			syncFile := func(f *os.File) error {
				if f.Name() == failPath && !failed && (failAt != "file entry" || slices.Contains(synced, path)) {
					failed = true
					return boom
				}
				synced = append(synced, f.Name())
				return f.Sync()
			}
			cfg := config.FileOutput{Path: path, SyncOnWrite: true}
			if s, err := newFile(cfg, syncFile); !errors.Is(err, boom) {
				if s != nil {
					_ = s.Close()
				}
				t.Fatalf("NewFile with failed %s sync = %v, want storage failure", failAt, err)
			}
			// A failed attempt has left the directories behind. Their entries
			// must still be synced on retry, even though MkdirAll now does nothing.
			synced = nil
			s, err := newFile(cfg, syncFile)
			if err != nil {
				t.Fatalf("NewFile retry: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			want := []string{filepath.Dir(path), filepath.Join(base, "new"), base}
			if len(synced) < len(want) || !slices.Equal(synced[:len(want)], want) {
				t.Errorf("synced paths = %v, want new directory ancestors %v first", synced, want)
			}
			if len(synced) < 2 || !slices.Equal(synced[len(synced)-2:], []string{path, filepath.Dir(path)}) {
				t.Errorf("synced paths = %v, want file contents then its directory entry last", synced)
			}
		})
	}
}

func TestFileDurableWriteWaitsForSyncAndReturnsSyncFailure(t *testing.T) {
	for _, name := range []string{"success", "failure"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "events.json")
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			block := false
			boom := errors.New("injected write sync failure")
			s, err := newFile(config.FileOutput{Path: path, SyncOnWrite: true}, func(f *os.File) error {
				if block && f.Name() == path {
					block = false
					close(entered)
					<-release
					if name == "failure" {
						return boom
					}
				}
				return f.Sync()
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			block = true
			done := make(chan error, 1)
			go func() { done <- s.Write(t.Context(), execEnvelope(1)) }()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("Write returned without synchronizing storage: %v", err)
			}
			select {
			case err := <-done:
				t.Fatalf("Write returned before storage sync completed: %v", err)
			default:
			}
			unblock()
			err = <-done
			if name == "failure" && !errors.Is(err, boom) {
				t.Fatalf("Write error = %v, want storage sync failure", err)
			}
			if name == "success" && err != nil {
				t.Fatalf("Write: %v", err)
			}
		})
	}
}

func TestFileDurableRotationSyncsBeforeReusingNames(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "events.json")
	tracking := false
	shiftSynced, renameSynced, createSynced := false, false, false
	s, err := newFile(config.FileOutput{
		Path: path, SyncOnWrite: true, MaxSize: config.Size(lineSize(t, execEnvelope(1))), MaxFiles: 2,
	}, func(f *os.File) error {
		if tracking && f.Name() == filepath.Dir(path) {
			_, liveErr := os.Stat(path)
			_, recentErr := os.Stat(path + ".1")
			switch {
			case errors.Is(recentErr, fs.ErrNotExist):
				// Archive .1 has moved to .2; its name is about to be reused.
				if !equalSeq(readSequences(t, path+".2"), []uint64{1}) {
					t.Fatal("archive move lost the first event")
				}
				shiftSynced = true
			case errors.Is(liveErr, fs.ErrNotExist):
				if !shiftSynced {
					t.Fatal("rotation replaced .1 before its move to .2 was synced")
				}
				renameSynced = true
			case len(readSequences(t, path)) == 0:
				if !renameSynced {
					t.Fatal("rotation recreated the live file before its archive rename was synced")
				}
				createSynced = true
			}
		}
		return f.Sync()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for seq := uint64(1); seq <= 3; seq++ {
		tracking = seq == 3
		if err := s.Write(t.Context(), execEnvelope(seq)); err != nil {
			t.Fatal(err)
		}
	}
	if !shiftSynced || !renameSynced || !createSynced {
		t.Fatalf("missing durable rotation step: shift=%t rename=%t creation=%t", shiftSynced, renameSynced, createSynced)
	}
	if got := readSequences(t, path); !equalSeq(got, []uint64{3}) {
		t.Fatalf("current file = %v, want event 3", got)
	}
}

func TestFileDurableRotationRejectsUnsyncedRenameAndRecovers(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "events.json")
	boom := errors.New("injected directory sync failure")
	injectFailure := false
	cfg := config.FileOutput{
		Path: path, SyncOnWrite: true, MaxSize: config.Size(lineSize(t, execEnvelope(1))), MaxFiles: 2,
	}
	syncFile := func(f *os.File) error {
		_, err := os.Stat(path)
		if f.Name() == filepath.Dir(path) && errors.Is(err, fs.ErrNotExist) && injectFailure {
			return boom
		}
		return f.Sync()
	}
	s, err := newFile(cfg, syncFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Write(t.Context(), execEnvelope(1)); err != nil {
		t.Fatal(err)
	}
	injectFailure = true
	if err := s.Write(t.Context(), execEnvelope(2)); !errors.Is(err, boom) {
		t.Fatalf("Write after failed rename sync = %v, want storage failure", err)
	}
	if got := readSequences(t, path+".1"); !equalSeq(got, []uint64{1}) {
		t.Fatalf("acknowledged event lost from archive: %v", got)
	}
	if err := s.Write(t.Context(), execEnvelope(2)); !errors.Is(err, boom) {
		t.Fatalf("Write retry with failed rename sync = %v, want storage failure", err)
	}
	// A fresh collector has no memory of the failed rotation. It must still
	// commit the pending rename before creating another live file.
	if reopened, err := newFile(cfg, syncFile); !errors.Is(err, boom) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatalf("NewFile after failed rename sync = %v, want storage failure", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("live file recreated before its archive rename could be synced: %v", err)
	}
	injectFailure = false
	if err := s.Write(t.Context(), execEnvelope(2)); err != nil {
		t.Fatalf("Write retry: %v", err)
	}
	if got := readSequences(t, path); !equalSeq(got, []uint64{2}) {
		t.Fatalf("current file = %v, want retried event 2", got)
	}
}

func TestFileDurableRotationResumesWithoutPruningRetainedEvents(t *testing.T) {
	for _, name := range []string{"same sink", "reopened sink"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "events.json")
			boom := errors.New("injected archive rename sync failure")
			failed := false
			syncFile := func(f *os.File) error {
				_, recentErr := os.Stat(path + ".1")
				_, oldestErr := os.Stat(path + ".2")
				if f.Name() == filepath.Dir(path) && errors.Is(recentErr, fs.ErrNotExist) && oldestErr == nil && !failed {
					failed = true
					return boom
				}
				return f.Sync()
			}
			cfg := config.FileOutput{
				Path: path, SyncOnWrite: true, MaxSize: config.Size(lineSize(t, execEnvelope(1))), MaxFiles: 2,
			}
			s, err := newFile(cfg, syncFile)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			for seq := uint64(1); seq <= 2; seq++ {
				if err := s.Write(t.Context(), execEnvelope(seq)); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Write(t.Context(), execEnvelope(3)); !errors.Is(err, boom) {
				t.Fatalf("Write after archive rename sync failure = %v, want storage failure", err)
			}
			retry := s
			if name == "reopened sink" {
				// No Close: a killed collector cannot sync its pending metadata.
				retry, err = newFile(cfg, syncFile)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = retry.Close() })
			}
			if err := retry.Write(t.Context(), execEnvelope(3)); err != nil {
				t.Fatalf("Write retry: %v", err)
			}
			for suffix, seq := range map[string]uint64{"": 3, ".1": 2, ".2": 1} {
				if got := readSequences(t, path+suffix); !equalSeq(got, []uint64{seq}) {
					t.Errorf("%s holds %v, want retained event %d", path+suffix, got, seq)
				}
			}
		})
	}
}

func TestFileAsyncModeDefersDurabilityUntilFlush(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "new", "events.json")
	var synced []string
	s, err := newFile(config.FileOutput{Path: path}, func(f *os.File) error {
		synced = append(synced, f.Name())
		return f.Sync()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Write(t.Context(), execEnvelope(1)); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 0 {
		t.Fatalf("SyncOnWrite=false synced paths %v before Flush", synced)
	}
	if err := s.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(synced) < 2 || synced[0] != path || synced[1] != filepath.Dir(path) {
		t.Fatalf("Flush synced %v, want file contents and directory entry", synced)
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
