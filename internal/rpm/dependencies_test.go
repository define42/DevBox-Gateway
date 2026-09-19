package rpm

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fakeDependencyScanner(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "elfdeps"), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestBinaryDependenciesScansAbsoluteBinary(t *testing.T) {
	t.Chdir(t.TempDir())
	fakeDependencyScanner(t, `[ "$#" = 2 ] && [ "$1" = --requires ] || exit 41
case "$2" in /*/'gateway with spaces') ;; *) exit 42 ;; esac
printf '%s\n' 'libc.so.6(GLIBC_2.34)(64bit)' 'libvirt.so.0(LIBVIRT_9.0.0)(64bit)'
`)
	dependencies, err := binaryDependencies("gateway with spaces")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"libc.so.6(GLIBC_2.34)(64bit)", "libvirt.so.0(LIBVIRT_9.0.0)(64bit)"}
	if !reflect.DeepEqual(dependencies, want) {
		t.Fatalf("dependencies = %v, want %v", dependencies, want)
	}
}

func TestParseBinaryDependencies(t *testing.T) {
	tests := []struct {
		name   string
		output string
		valid  bool
	}{
		{"versioned", "libc.so.6(GLIBC_2.34)(64bit)\nlibvirt.so.0(LIBVIRT_9.0.0)(64bit)\n", true},
		{"sonames and hash", "libc.so.6()(64bit)\nlibvirt.so.0\nrtld(GNU_HASH)\n", true},
		{"empty", "", false},
		{"whitespace", "\n \n", false},
		{"diagnostic", "elfdeps: cannot read binary", false},
		{"empty line", "libc.so.6\n\nlibvirt.so.0", false},
		{"unclosed capability", "libvirt.so.0(LIBVIRT_9.0.0", false},
		{"invalid version", "libc.so.6(GLIBC_2.34) >= 2.34", false},
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
	fakeDependencyScanner(t, "printf '%s\\n' 'cannot read ELF dependencies' >&2\nexit 1\n")
	out := filepath.Join(dir, "out.rpm")
	err := Write(Options{BinarySource: bin, UnitSource: unit, ConfigSource: conf, Output: out})
	if err == nil || !strings.Contains(err.Error(), "cannot read ELF dependencies") {
		t.Fatalf("Write error = %v, want scanner diagnostic", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed scan created package: %v", err)
	}
}

func TestBinaryDependenciesRejectsEmptyScan(t *testing.T) {
	fakeDependencyScanner(t, "exit 0\n")
	if _, err := binaryDependencies("binary"); err == nil || !strings.Contains(err.Error(), "no binary dependencies") {
		t.Fatalf("error = %v, want empty dependency error", err)
	}
}
