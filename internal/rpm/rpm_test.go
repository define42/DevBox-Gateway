package rpm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/rpmpack"
)

func TestRPMArch(t *testing.T) {
	cases := map[string]string{"amd64": "x86_64", "arm64": "aarch64", "riscv64": "riscv64"}
	for goarch, want := range cases {
		if got := Arch(goarch); got != want {
			t.Fatalf("Arch(%q) = %q, want %q", goarch, got, want)
		}
	}
}

func TestPackageRelations(t *testing.T) {
	requires, err := packageRelations()
	if err != nil {
		t.Fatalf("packageRelations: %v", err)
	}
	want := map[string]bool{
		"libvirt-libs":       true,
		"ca-certificates":    true,
		"libvirt-daemon-kvm": true,
		"qemu-kvm":           true,
	}
	if len(requires) != len(want) {
		t.Fatalf("requires = %d, want %d (%v)", len(requires), len(want), want)
	}
	for _, require := range requires {
		if !want[require.Name] {
			t.Fatalf("unexpected require %q", require.Name)
		}
		delete(want, require.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing requires: %v", want)
	}
}

// The config file can hold secrets such as SNI_HASH_SECRET, so it must be
// installed 0640 and never group- or
// world-readable. The binary and unit carry no secrets and keep their
// conventional world-readable modes.
func TestPackageFileModes(t *testing.T) {
	o := Options{
		BinarySource:      "dist/devbox-gateway",
		BinaryDestination: "/usr/bin/devbox-gateway",
		UnitSource:        "devbox-gateway.service",
		ConfigSource:      "devbox-gateway.conf",
		LicenseSource:     filepath.Join(t.TempDir(), "LICENSE"), // absent: exercises the skip path
	}

	files := packageFiles(o)
	modes := map[string]uint{}
	var conf *packageFile
	for i := range files {
		modes[files[i].destination] = files[i].mode
		if files[i].destination == confDestination {
			conf = &files[i]
		}
	}

	want := map[string]uint{
		o.BinaryDestination: 0o755,
		unitDestination:     0o644,
		confDestination:     0o640,
	}
	for dest, mode := range want {
		got, ok := modes[dest]
		if !ok {
			t.Fatalf("packageFiles missing %q", dest)
		}
		if got != mode {
			t.Errorf("%s mode = %#o, want %#o", dest, got, mode)
		}
	}

	if modes[confDestination]&0o007 != 0 {
		t.Errorf("config file %s must not be world-accessible: mode %#o", confDestination, modes[confDestination])
	}
	if conf == nil {
		t.Fatalf("config file %s not in the install manifest", confDestination)
	}
	if conf.typeFlags&rpmpack.ConfigFile == 0 || conf.typeFlags&rpmpack.NoReplaceFile == 0 {
		t.Errorf("config file must stay %%config(noreplace); got type %v", conf.typeFlags)
	}
}

func TestPostInstallDoesNotConfigureFirewall(t *testing.T) {
	forbidden := []string{
		"firewall-cmd",
		"firewall-offline-cmd",
		"--add-service",
		"--add-port",
		"22/tcp",
	}
	for _, command := range forbidden {
		if strings.Contains(postinScript, command) {
			t.Fatalf("postinScript must not contain firewall setup %q", command)
		}
	}
}

// stageInputs writes a binary, unit, and config file into dir and returns their
// paths. The license file is intentionally omitted so tests exercise the
// absent-LICENSE skip path by default.
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

// Write packages real files, so the test stages a binary, unit, and config
// file in a temp dir and checks the resulting archive looks like an RPM (the lead
// begins with the magic bytes 0xED 0xAB 0xEE 0xDB).
func TestWriteRPM(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	out := filepath.Join(dir, "out.rpm")

	o := Options{
		Version:           "1.2.3",
		Release:           "1",
		Arch:              "x86_64",
		License:           "Proprietary",
		BinarySource:      bin,
		BinaryDestination: "/usr/bin/devbox-gateway",
		UnitSource:        unit,
		ConfigSource:      conf,
		LicenseSource:     filepath.Join(dir, "LICENSE"), // absent: exercises the skip path
		Output:            out,
	}
	if err := Write(o); err != nil {
		t.Fatalf("Write: %v", err)
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

	o := Options{
		Version:           "1.2.3",
		Release:           "1",
		Arch:              "x86_64",
		License:           "Apache-2.0",
		BinarySource:      bin,
		BinaryDestination: "/usr/bin/devbox-gateway",
		UnitSource:        unit,
		ConfigSource:      conf,
		LicenseSource:     license,
		Output:            out,
	}
	if err := Write(o); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("output stat = %v, %v", info, err)
	}
}

func TestWriteRPMMissingBinary(t *testing.T) {
	o := Options{
		Version:           "1.0.0",
		Release:           "1",
		Arch:              "x86_64",
		License:           "Proprietary",
		BinarySource:      filepath.Join(t.TempDir(), "absent"),
		BinaryDestination: "/usr/bin/devbox-gateway",
		Output:            filepath.Join(t.TempDir(), "out.rpm"),
	}
	if err := Write(o); err == nil {
		t.Fatal("expected error when the binary source is missing")
	}
}

func TestWriteRPMOutputCreateError(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	o := Options{
		Version:           "1.0.0",
		Release:           "1",
		Arch:              "x86_64",
		License:           "Proprietary",
		BinarySource:      bin,
		BinaryDestination: "/usr/bin/devbox-gateway",
		UnitSource:        unit,
		ConfigSource:      conf,
		Output:            filepath.Join(blocker, "out.rpm"),
	}
	if err := Write(o); err == nil {
		t.Fatal("expected error creating output under a regular file")
	}
}
