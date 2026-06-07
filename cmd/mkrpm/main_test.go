package main

import (
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestRPMArch(t *testing.T) {
	cases := map[string]string{"amd64": "x86_64", "arm64": "aarch64", "riscv64": "riscv64"}
	for goarch, want := range cases {
		if got := rpmArch(goarch); got != want {
			t.Fatalf("rpmArch(%q) = %q, want %q", goarch, got, want)
		}
	}
}

func TestPackageRelations(t *testing.T) {
	requires, recommends, err := packageRelations()
	if err != nil {
		t.Fatalf("packageRelations: %v", err)
	}
	if len(requires) != 2 {
		t.Fatalf("requires = %d, want 2 (libvirt-libs, ca-certificates)", len(requires))
	}
	if len(recommends) != 2 {
		t.Fatalf("recommends = %d, want 2 (libvirt-daemon-kvm, qemu-kvm)", len(recommends))
	}
}

// stageInputs writes a binary, unit, and config file into dir and returns their
// paths. The license file is intentionally omitted so tests exercise the
// "no LICENSE in the repo" path by default.
func stageInputs(t *testing.T, dir string) (bin, unit, conf string) {
	t.Helper()
	bin = filepath.Join(dir, "rdp-tls-gateway")
	unit = filepath.Join(dir, "rdp-tls-gateway.service")
	conf = filepath.Join(dir, "rdp-tls-gateway.conf")
	for _, f := range []string{bin, unit, conf} {
		if err := os.WriteFile(f, []byte("content of "+filepath.Base(f)), 0o600); err != nil {
			t.Fatalf("seed %s: %v", f, err)
		}
	}
	return bin, unit, conf
}

// writeRPM packages real files, so the test stages a binary, unit, and config
// file in a temp dir and checks the resulting archive looks like an RPM (the lead
// begins with the magic bytes 0xED 0xAB 0xEE 0xDB).
func TestWriteRPM(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	out := filepath.Join(dir, "out.rpm")

	o := options{
		version:    "1.2.3",
		release:    "1",
		arch:       "x86_64",
		licence:    "Proprietary",
		binarySrc:  bin,
		binaryDest: "/usr/bin/rdp-tls-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: filepath.Join(dir, "LICENSE"), // absent: exercises the skip path
		out:        out,
	}
	if err := writeRPM(o); err != nil {
		t.Fatalf("writeRPM: %v", err)
	}

	data, err := os.ReadFile(out) //nolint:gosec // reads the rpm the test just wrote to a temp dir.
	if err != nil {
		t.Fatalf("read rpm: %v", err)
	}
	magic := []byte{0xED, 0xAB, 0xEE, 0xDB}
	if len(data) < len(magic) || string(data[:4]) != string(magic) {
		t.Fatalf("output does not start with the RPM lead magic; got % x", data[:min(4, len(data))])
	}
}

// TestWriteRPMWithLicense exercises the branch that bundles a LICENSE file when
// one is present alongside the other inputs.
func TestWriteRPMWithLicense(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	license := filepath.Join(dir, "LICENSE")
	if err := os.WriteFile(license, []byte("license text"), 0o600); err != nil {
		t.Fatalf("seed license: %v", err)
	}
	out := filepath.Join(dir, "out.rpm")

	o := options{
		version:    "1.2.3",
		release:    "1",
		arch:       "x86_64",
		licence:    "Apache-2.0",
		binarySrc:  bin,
		binaryDest: "/usr/bin/rdp-tls-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: license,
		out:        out,
	}
	if err := writeRPM(o); err != nil {
		t.Fatalf("writeRPM: %v", err)
	}
	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("output stat = %v, %v", info, err)
	}
}

func TestWriteRPMMissingBinary(t *testing.T) {
	o := options{
		version:    "1.0.0",
		release:    "1",
		arch:       "x86_64",
		licence:    "Proprietary",
		binarySrc:  filepath.Join(t.TempDir(), "absent"),
		binaryDest: "/usr/bin/rdp-tls-gateway",
		out:        filepath.Join(t.TempDir(), "out.rpm"),
	}
	if err := writeRPM(o); err == nil {
		t.Fatal("expected error when the binary source is missing")
	}
}

func TestMainWritesRPM(t *testing.T) {
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
	out := filepath.Join(dir, "from-main.rpm")

	flag.CommandLine = flag.NewFlagSet("mkrpm", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkrpm",
		"-version", "2.0.0",
		"-release", "3",
		"-arch", "x86_64",
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

func TestWriteRPMOutputCreateError(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	o := options{
		version:    "1.0.0",
		release:    "1",
		arch:       "x86_64",
		licence:    "Proprietary",
		binarySrc:  bin,
		binaryDest: "/usr/bin/rdp-tls-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		out:        filepath.Join(blocker, "out.rpm"),
	}
	if err := writeRPM(o); err == nil {
		t.Fatal("expected error creating output under a regular file")
	}
}
