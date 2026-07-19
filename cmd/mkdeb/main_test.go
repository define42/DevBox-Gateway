package main

import (
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

// TestWriteDeb packages real files staged in a temp dir and checks the output is
// an ar archive whose control file ends with a newline.
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
