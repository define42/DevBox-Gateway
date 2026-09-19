package deb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeDependencyScanner(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dpkg-shlibdeps"), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestBinaryDependenciesStagesExactBinaryInPrivatePackageDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("gateway with spaces", []byte("exact binary under review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeDependencyScanner(t, `[ "$#" = 3 ] && [ "$1" = --warnings=1 ] && [ "$2" = -O ] && [ -f debian/control ] || exit 41
case "$3" in -e/*/debian/devbox-gateway/usr/bin/devbox-gateway) ;; *) exit 42 ;; esac
[ -d debian/devbox-gateway/DEBIAN ] && [ -L "${3#-e}" ] || exit 43
read -r value < "${3#-e}"
[ "$value" = 'exact binary under review' ] || exit 44
printf '%s\n' 'shlibs:Depends=libc6 (>= 2.34), libvirt0 (>= 9.0.0)'
`)
	dependencies, err := binaryDependencies("gateway with spaces")
	if err != nil {
		t.Fatal(err)
	}
	if dependencies != "libc6 (>= 2.34), libvirt0 (>= 9.0.0)" {
		t.Fatalf("dependencies = %q", dependencies)
	}
	if _, err := os.Stat("debian"); !os.IsNotExist(err) {
		t.Fatalf("scan created debian metadata in the caller's directory: %v", err)
	}
}

func TestParseBinaryDependencies(t *testing.T) {
	tests := []struct {
		name   string
		output string
		valid  bool
	}{
		{"versioned", "shlibs:Depends=libc6 (>= 2.34), libvirt0 (>= 9.0.0)\n", true},
		{"epoch and alternatives", "shlibs:Depends=libvirt0 (>= 1:9.0.0-4+deb12u1) | libvirt0t64, libc6:amd64 (>= 2.34)", true},
		{"empty", "", false},
		{"no dependencies", "shlibs:Depends=\n", false},
		{"unexpected field", "Depends=libc6 (>= 2.34)", false},
		{"extra field", "shlibs:Depends=libc6\nConflicts: other", false},
		{"bad version", "shlibs:Depends=libc6 (>= garbage)", false},
		{"bad separator", "shlibs:Depends=libc6,", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseBinaryDependencies(tt.output)
			if (err == nil) != tt.valid {
				t.Fatalf("parseBinaryDependencies(%q) error = %v, valid = %v", tt.output, err, tt.valid)
			}
		})
	}
}

func TestWriteRejectsFailedDependencyScan(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	fakeDependencyScanner(t, "printf '%s\\n' 'missing library symbols' >&2\nexit 1\n")
	out := filepath.Join(dir, "out.deb")
	err := Write(Options{BinarySource: bin, UnitSource: unit, ConfigSource: conf, Output: out})
	if err == nil || !strings.Contains(err.Error(), "missing library symbols") {
		t.Fatalf("Write error = %v, want scanner diagnostic", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed scan created package: %v", err)
	}
}

func TestBinaryDependenciesRequiresScanner(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := binaryDependencies("binary"); err == nil || !strings.Contains(err.Error(), "dpkg-dev") {
		t.Fatalf("error = %v, want actionable missing-tool error", err)
	}
}

func TestBinaryDependenciesRejectsUnresolvedSymbols(t *testing.T) {
	fakeDependencyScanner(t, "printf '%s\\n' 'symbol virNewerAPI found in none of the libraries' >&2\nprintf '%s\\n' 'shlibs:Depends=libvirt0 (>= 9.0.0)'\n")
	if _, err := binaryDependencies("binary"); err == nil || !strings.Contains(err.Error(), "virNewerAPI") {
		t.Fatalf("error = %v, want unresolved symbol diagnostic", err)
	}
}
