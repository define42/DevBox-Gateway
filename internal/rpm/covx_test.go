package rpm

import (
	"path/filepath"
	"testing"

	"github.com/google/rpmpack"
)

// TestAddPackageFilesReadError uses a directory as the binary source: os.Stat
// succeeds (so the mtime lookup passes) but os.ReadFile fails with EISDIR, the
// same way for root and for the unprivileged CI runner.
func TestAddPackageFilesReadError(t *testing.T) {
	rpm, err := rpmpack.NewRPM(rpmpack.RPMMetaData{
		Name:    packageName,
		Version: "1.0.0",
		Release: "1",
		Arch:    "x86_64",
	})
	if err != nil {
		t.Fatalf("NewRPM: %v", err)
	}
	o := Options{
		BinarySource:      t.TempDir(),
		BinaryDestination: "/usr/bin/devbox-gateway",
	}
	if err := addPackageFiles(rpm, o); err == nil {
		t.Fatal("expected error when the binary source is a directory")
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
