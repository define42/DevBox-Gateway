package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebArch(t *testing.T) {
	cases := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "i386", "arm": "armhf", "riscv64": "riscv64"}
	for goarch, want := range cases {
		if got := debArch(goarch); got != want {
			t.Fatalf("debArch(%q) = %q, want %q", goarch, got, want)
		}
	}
}

func TestPackageRelations(t *testing.T) {
	deps := packageRelations()
	want := []string{"libvirt0", "ca-certificates", "libvirt-daemon-system", "qemu-system-x86"}
	for _, dep := range want {
		if !strings.Contains(deps, dep) {
			t.Fatalf("Depends %q missing %q", deps, dep)
		}
	}
}

// The maintainer scripts must not reach into the host firewall, matching the
// cmd/mkrpm policy.
func TestMaintainerScriptsDoNotConfigureFirewall(t *testing.T) {
	forbidden := []string{"firewall-cmd", "firewall-offline-cmd", "--add-service", "--add-port", "22/tcp"}
	for _, script := range []string{postinstScript, prermScript, postrmScript} {
		for _, command := range forbidden {
			if strings.Contains(script, command) {
				t.Fatalf("maintainer script must not contain firewall setup %q", command)
			}
		}
	}
}

// stageInputs writes a binary, unit, and config file into dir and returns their
// paths. The license file is intentionally omitted so tests exercise the
// "no LICENSE in the repo" path by default.
func stageInputs(t *testing.T, dir string) (bin, unit, conf string) {
	t.Helper()
	bin = filepath.Join(dir, "devbox-gateway")
	unit = filepath.Join(dir, "devbox-gateway.service")
	conf = filepath.Join(dir, "devbox-gateway.conf")
	for _, f := range []string{bin, unit, conf} {
		if err := os.WriteFile(f, []byte("content of "+filepath.Base(f)), 0o600); err != nil {
			t.Fatalf("seed %s: %v", f, err)
		}
	}
	return bin, unit, conf
}

// debMagic is the leading magic of an ar archive, which every .deb begins with.
const debMagic = "!<arch>\n"

// TestWriteDeb packages real files staged in a temp dir and checks the archive,
// control metadata, and data directory entries.
func TestWriteDeb(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	out := filepath.Join(dir, "out.deb")

	o := options{
		version:    "1.2.3",
		arch:       "amd64",
		binarySrc:  bin,
		binaryDest: "/usr/bin/devbox-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: filepath.Join(dir, "LICENSE"), // absent: exercises the skip path
		out:        out,
	}
	if err := writeDeb(o); err != nil {
		t.Fatalf("writeDeb: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read deb: %v", err)
	}
	if !strings.HasPrefix(string(data), debMagic) {
		t.Fatalf("output does not start with the ar magic; got %q", data[:min(len(debMagic), len(data))])
	}

	control := readControlFile(t, data)
	if !strings.HasSuffix(control, "\n") {
		t.Fatalf("control file must end with a newline; got %q", control[max(0, len(control)-20):])
	}
	if !strings.Contains(control, "Package: "+packageName) {
		t.Fatalf("control file missing package name:\n%s", control)
	}

	assertDataDirectories(t, data, []string{
		"etc/",
		"etc/devbox-gateway/",
		"lib/",
		"lib/systemd/",
		"lib/systemd/system/",
		"usr/",
		"usr/bin/",
	})
}

func TestWriteDebWithLicense(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	license := filepath.Join(dir, "LICENSE")
	if err := os.WriteFile(license, []byte("license text"), 0o600); err != nil {
		t.Fatalf("seed license: %v", err)
	}
	out := filepath.Join(dir, "out.deb")

	o := options{
		version:    "1.2.3",
		arch:       "amd64",
		binarySrc:  bin,
		binaryDest: "/usr/bin/devbox-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: license,
		out:        out,
	}
	if err := writeDeb(o); err != nil {
		t.Fatalf("writeDeb: %v", err)
	}
	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("output stat = %v, %v", info, err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read deb: %v", err)
	}
	assertDataDirectories(t, data, []string{
		"usr/share/",
		"usr/share/doc/",
		"usr/share/doc/devbox-gateway/",
	})
}

// The config file can hold secrets — a LOCAL_USER_SHA256 list of password
// digests and the SSH tunnel key passphrase — so the data archive must install
// it 0640, never group- or world-readable, no matter how the source file is
// checked out. stageInputs writes the sources 0600, so a pass here also proves
// the mode is set by the manifest rather than copied from disk.
func TestWriteDebFileModes(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	out := filepath.Join(dir, "out.deb")

	o := options{
		version:    "1.2.3",
		arch:       "amd64",
		binarySrc:  bin,
		binaryDest: "/usr/bin/devbox-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: filepath.Join(dir, "LICENSE"), // absent: exercises the skip path
		out:        out,
	}
	if err := writeDeb(o); err != nil {
		t.Fatalf("writeDeb: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read deb: %v", err)
	}

	modes := dataFileModes(t, data)
	want := map[string]int64{
		"usr/bin/devbox-gateway":                    0o755,
		"lib/systemd/system/devbox-gateway.service": 0o644,
		"etc/devbox-gateway/devbox-gateway.conf":    0o640,
	}
	for name, mode := range want {
		got, ok := modes[name]
		if !ok {
			t.Fatalf("data archive missing file %q", name)
		}
		if got != mode {
			t.Errorf("%s mode = %#o, want %#o", name, got, mode)
		}
	}
	if conf := modes["etc/devbox-gateway/devbox-gateway.conf"]; conf&0o007 != 0 {
		t.Errorf("config file must not be world-accessible: mode %#o", conf)
	}
}

func assertDataDirectories(t *testing.T, deb []byte, want []string) {
	t.Helper()

	directories := dataDirectories(t, deb)
	for _, name := range want {
		if !directories[name] {
			t.Errorf("data archive missing directory %q", name)
		}
	}
}

func dataDirectories(t *testing.T, deb []byte) map[string]bool {
	t.Helper()

	members, err := parseAr(deb)
	if err != nil {
		t.Fatalf("parseAr: %v", err)
	}

	var dataArchive []byte
	for i := range members {
		if members[i].name() == "data.tar.gz" {
			dataArchive = members[i].data
			break
		}
	}
	if dataArchive == nil {
		t.Fatal("data.tar.gz not found")
	}

	return tarDirectories(t, dataArchive)
}

// dataFileModes returns the permission bits (masked to 0o7777) of every regular
// file in a .deb's data.tar.gz, keyed by its archive path.
func dataFileModes(t *testing.T, deb []byte) map[string]int64 {
	t.Helper()

	members, err := parseAr(deb)
	if err != nil {
		t.Fatalf("parseAr: %v", err)
	}
	var dataArchive []byte
	for i := range members {
		if members[i].name() == "data.tar.gz" {
			dataArchive = members[i].data
			break
		}
	}
	if dataArchive == nil {
		t.Fatal("data.tar.gz not found")
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(dataArchive))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tarReader := tar.NewReader(gzipReader)
	modes := make(map[string]int64)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if header.Typeflag == tar.TypeReg {
			modes[header.Name] = header.Mode & 0o7777
		}
	}
	return modes
}

func tarDirectories(t *testing.T, dataArchive []byte) map[string]bool {
	t.Helper()

	gzipReader, err := gzip.NewReader(bytes.NewReader(dataArchive))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tarReader := tar.NewReader(gzipReader)
	directories := make(map[string]bool)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if header.Typeflag == tar.TypeDir {
			directories[header.Name] = true
		}
	}
	return directories
}

func TestWriteDebMissingBinary(t *testing.T) {
	o := options{
		version:    "1.0.0",
		arch:       "amd64",
		binarySrc:  filepath.Join(t.TempDir(), "absent"),
		binaryDest: "/usr/bin/devbox-gateway",
		out:        filepath.Join(t.TempDir(), "out.deb"),
	}
	if err := writeDeb(o); err == nil {
		t.Fatal("expected error when the binary source is missing")
	}
}

func TestMainWritesDeb(t *testing.T) {
	prevArgs := os.Args
	prevFlags := flag.CommandLine
	prevLogOutput := log.Writer()
	t.Cleanup(func() {
		os.Args = prevArgs
		flag.CommandLine = prevFlags
		log.SetOutput(prevLogOutput)
	})

	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	out := filepath.Join(dir, "from-main.deb")

	flag.CommandLine = flag.NewFlagSet("mkdeb", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkdeb",
		"-version", "2.0.0",
		"-arch", "amd64",
		"-binary", bin,
		"-unit", unit,
		"-conf", conf,
		"-license", filepath.Join(dir, "LICENSE"),
		"-out", out,
	}

	main()

	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("main output stat = %v, %v", info, err)
	}
}

func TestWriteDebOutputCreateError(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	o := options{
		version:    "1.0.0",
		arch:       "amd64",
		binarySrc:  bin,
		binaryDest: "/usr/bin/devbox-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		out:        filepath.Join(blocker, "out.deb"),
	}
	if err := writeDeb(o); err == nil {
		t.Fatal("expected error creating output under a regular file")
	}
}
