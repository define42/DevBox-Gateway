package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rawTarHeader builds a single 512-byte ustar header block by hand so tests can
// produce archives the standard tar writer refuses to create (truncated bodies,
// regular-file entries with a trailing slash, ...).
func rawTarHeader(name string, size int64, typeflag byte) []byte {
	block := make([]byte, 512)
	copy(block[0:100], name)
	copy(block[100:108], "0000644\x00")
	copy(block[108:116], "0000000\x00")
	copy(block[116:124], "0000000\x00")
	copy(block[124:136], fmt.Sprintf("%011o\x00", size))
	copy(block[136:148], "00000000000\x00")
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	block[156] = typeflag
	copy(block[257:265], "ustar\x0000")
	var sum int
	for _, c := range block {
		sum += int(c)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return block
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// TestAppendNewlineToControlMalformedInput drives every reachable error return:
// invalid gzip data, a corrupt tar header, an entry body shorter than its
// header claims, and an entry the tar writer refuses to re-encode (a regular
// file whose name carries a trailing slash).
func TestAppendNewlineToControlMalformedInput(t *testing.T) {
	truncated := append(rawTarHeader("control", 100, '0'), []byte("short")...)
	slashed := append(rawTarHeader("dir/", 0, '0'), make([]byte, 1024)...)
	cases := []struct {
		name  string
		input []byte
	}{
		{"not gzip", []byte("plainly not a gzip stream")},
		{"corrupt tar header", gzipBytes(t, bytes.Repeat([]byte{0xFF}, 512))},
		{"truncated entry body", gzipBytes(t, truncated)},
		{"regular entry with trailing slash", gzipBytes(t, slashed)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := appendNewlineToControl(tc.input); err == nil {
				t.Fatal("expected an error for malformed control.tar.gz input")
			}
		})
	}
}

// arWithSizeField returns a single-member archive whose header size field has
// been overwritten with the given raw content.
func arWithSizeField(field, body string) []byte {
	m := makeMember("m", body)
	padded := field + strings.Repeat(" ", arSizeEnd-arSizeStart-len(field))
	copy(m.header[arSizeStart:arSizeEnd], padded)
	return writeAr([]arMember{m})
}

func TestParseArMalformedArchives(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr string
	}{
		{"truncated header", []byte(arMagic + "way too short"), "truncated ar header"},
		{"bad size field", arWithSizeField("notanum", "ab"), "bad ar size field"},
		{"truncated member", arWithSizeField("999", "ab"), "truncated ar member"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAr(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("parseAr error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestReadPackageFileErrors covers the destination validation and the source
// failure modes that do not depend on file permissions, so they behave the same
// for root and for the unprivileged CI runner: a directory where a regular file
// is expected and a pseudo-file whose reads fail with EIO.
func TestReadPackageFileErrors(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regular, []byte("content"), 0o600); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	cases := []struct {
		name    string
		file    debFile
		wantErr string
	}{
		{"relative destination", debFile{source: regular, destination: "usr/bin/tool", mode: 0o755}, "absolute"},
		{"root destination", debFile{source: regular, destination: "/", mode: 0o755}, "absolute"},
		{"directory source", debFile{source: t.TempDir(), destination: "/usr/bin/tool", mode: 0o755}, "not a regular file"},
		{"unreadable pseudo file", debFile{source: "/proc/self/mem", destination: "/usr/bin/tool", mode: 0o755}, "read /proc/self/mem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readPackageFile(tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("readPackageFile error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestMakeTarGzipRejectsUnencodableName(t *testing.T) {
	entries := []tarEntry{{name: "bad\x00name", body: []byte("x"), mode: 0o644, modTime: time.Now()}}
	if _, err := makeTarGzip(entries); err == nil {
		t.Fatal("expected error for a tar entry name containing NUL")
	}
}

func TestNewArMemberErrors(t *testing.T) {
	if _, err := newArMember(strings.Repeat("n", 17), []byte("body"), time.Unix(1, 0)); err == nil {
		t.Fatal("expected error for an ar member name longer than 16 bytes")
	}
	// 14 decimal digits overflow the 12-byte ar date field, so the rendered
	// header is no longer exactly 60 bytes.
	overflow := time.Unix(10_000_000_000_000, 0)
	if _, err := newArMember("x", []byte("body"), overflow); err == nil {
		t.Fatal("expected error when the ar header fields overflow the fixed layout")
	}
}

// selfLoopSymlink returns a path whose os.Stat fails with ELOOP — an error that
// is not os.ErrNotExist — forcing the license stat error branch identically for
// root and unprivileged CI runs.
func selfLoopSymlink(t *testing.T) string {
	t.Helper()
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatalf("create symlink loop: %v", err)
	}
	return loop
}

func TestPackageFilesLicenseStatError(t *testing.T) {
	o := options{binarySrc: "bin", unitSrc: "unit", confSrc: "conf", licenseSrc: selfLoopSymlink(t)}
	if _, err := packageFiles(o); err == nil || !strings.Contains(err.Error(), "stat license") {
		t.Fatalf("packageFiles error = %v, want a stat license error", err)
	}
}

func TestWriteDebLicenseStatError(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	o := options{
		version:    "1.0.0",
		arch:       "amd64",
		binarySrc:  bin,
		binaryDest: "/usr/bin/devbox-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: selfLoopSymlink(t),
		out:        filepath.Join(dir, "out.deb"),
	}
	if err := writeDeb(o); err == nil {
		t.Fatal("expected error when the license path cannot be stat-ed")
	}
}

func TestWriteDebDataArchiveError(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	o := options{
		version:    "1.0.0",
		arch:       "amd64",
		binarySrc:  bin,
		binaryDest: "/usr/bin/dev\x00box", // NUL cannot be encoded in a tar name
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: filepath.Join(dir, "LICENSE"),
		out:        filepath.Join(dir, "out.deb"),
	}
	err := writeDeb(o)
	if err == nil || !strings.Contains(err.Error(), "create data archive") {
		t.Fatalf("writeDeb error = %v, want a create data archive error", err)
	}
}

func TestWritePackageFileRenameOntoDirectory(t *testing.T) {
	occupied := filepath.Join(t.TempDir(), "occupied")
	if err := os.Mkdir(occupied, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	err := writePackageFile(occupied, []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "replace output") {
		t.Fatalf("writePackageFile error = %v, want a replace output error", err)
	}
}

// TestMainDefaultOutPath omits -out so main derives the
// dist/<name>_<version>_<arch>.deb default, running from a temp working
// directory that provides the dist/ folder.
func TestMainDefaultOutPath(t *testing.T) {
	prevArgs := os.Args
	prevFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = prevArgs
		flag.CommandLine = prevFlags
	})

	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	t.Chdir(dir)
	if err := os.Mkdir("dist", 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}

	flag.CommandLine = flag.NewFlagSet("mkdeb", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkdeb",
		"-version", "9.9.9",
		"-arch", "amd64",
		"-binary", bin,
		"-unit", unit,
		"-conf", conf,
		"-license", filepath.Join(dir, "LICENSE"),
	}

	main()

	out := filepath.Join(dir, "dist", "devbox-gateway_9.9.9_amd64.deb")
	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("default output stat = %v, %v", info, err)
	}
}

const fatalTrapSentinel = "mkdeb: log.Fatal reached"

// fatalTrapWriter panics from inside log.Fatal's output call so main's error
// branch can run without the process exiting; the test recovers the sentinel.
type fatalTrapWriter struct{}

func (fatalTrapWriter) Write([]byte) (int, error) {
	panic(fatalTrapSentinel)
}

func TestMainFatalOnError(t *testing.T) {
	prevArgs := os.Args
	prevFlags := flag.CommandLine
	prevLogOutput := log.Writer()
	t.Cleanup(func() {
		os.Args = prevArgs
		flag.CommandLine = prevFlags
		log.SetOutput(prevLogOutput)
	})

	dir := t.TempDir()
	flag.CommandLine = flag.NewFlagSet("mkdeb", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkdeb",
		"-binary", filepath.Join(dir, "absent"),
		"-out", filepath.Join(dir, "out.deb"),
	}
	log.SetOutput(fatalTrapWriter{})

	defer func() {
		if r := recover(); r != fatalTrapSentinel {
			t.Fatalf("main did not reach log.Fatal; recovered %v", r)
		}
	}()
	main()
	t.Fatal("main returned even though packaging failed")
}
