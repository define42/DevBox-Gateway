package rpm

import (
	"path/filepath"
	"testing"

	"github.com/google/rpmpack"
)

// TestAddFilesReadError uses a directory as the binary source: os.Stat
// succeeds (so the mtime lookup passes) but os.ReadFile fails with EISDIR, the
// same way for root and for the unprivileged CI runner.
func TestAddFilesReadError(t *testing.T) {
	rpm, err := rpmpack.NewRPM(rpmpack.RPMMetaData{
		Name:    packageName,
		Version: "1.0.0",
		Release: "1",
		Arch:    "x86_64",
	})
	if err != nil {
		t.Fatalf("NewRPM: %v", err)
	}
	files := []File{{Source: t.TempDir(), Destination: "/usr/bin/devbox-gateway", Mode: 0o755}}
	if err := addFiles(rpm, files); err == nil {
		t.Fatal("expected error when the binary source is a directory")
	}
}

func TestWritePackageEmptyPayload(t *testing.T) {
	p := Package{
		Name:    "empty",
		Version: "1.0.0",
		Release: "1",
		Arch:    "noarch",
		Output:  filepath.Join(t.TempDir(), "out.rpm"),
	}
	if err := WritePackage(p); err == nil {
		t.Fatal("expected error for a package with no files")
	}
}

func TestWritePackageInvalidRequire(t *testing.T) {
	p := Package{
		Name:     "bad-require",
		Version:  "1.0.0",
		Release:  "1",
		Arch:     "noarch",
		Requires: []string{"foo >< 1.0"}, // "><" is not an rpm sense
		Output:   filepath.Join(t.TempDir(), "out.rpm"),
	}
	if err := WritePackage(p); err == nil {
		t.Fatal("expected error for an unparseable require")
	}
}

// TestWriteRPMPayloadWriteError points the output at /dev/full so rpm.Write
// fails with ENOSPC after os.Create succeeded, covering the close-and-return
// error branch.
func TestWriteRPMPayloadWriteError(t *testing.T) {
	dir := t.TempDir()
	bin, unit, conf := stageInputs(t, dir)
	o := Options{
		Version:           "1.0.0",
		Release:           "1",
		Arch:              "x86_64",
		License:           "Proprietary",
		BinarySource:      bin,
		BinaryDestination: "/usr/bin/devbox-gateway",
		UnitSource:        unit,
		ConfigSource:      conf,
		LicenseSource:     filepath.Join(dir, "LICENSE"),
		Output:            "/dev/full",
	}
	if err := Write(o); err == nil {
		t.Fatal("expected error writing the rpm payload to /dev/full")
	}
}
