package main

import (
	"flag"
	"io"
	"log"
	"os"
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
	o := options{
		binarySrc:  t.TempDir(),
		binaryDest: "/usr/bin/devbox-gateway",
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
	o := options{
		version:    "1.0.0",
		release:    "1",
		arch:       "x86_64",
		licence:    "Proprietary",
		binarySrc:  bin,
		binaryDest: "/usr/bin/devbox-gateway",
		unitSrc:    unit,
		confSrc:    conf,
		licenseSrc: filepath.Join(dir, "LICENSE"),
		out:        "/dev/full",
	}
	if err := writeRPM(o); err == nil {
		t.Fatal("expected error writing the rpm payload to /dev/full")
	}
}

// TestMainDefaultOutPath omits -out so main derives the
// dist/<name>-<version>-<release>.<arch>.rpm default, running from a temp
// working directory that provides the dist/ folder.
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

	flag.CommandLine = flag.NewFlagSet("mkrpm", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkrpm",
		"-version", "9.9.9",
		"-release", "7",
		"-arch", "x86_64",
		"-binary", bin,
		"-unit", unit,
		"-conf", conf,
		"-license", filepath.Join(dir, "LICENSE"),
	}

	main()

	out := filepath.Join(dir, "dist", "devbox-gateway-9.9.9-7.x86_64.rpm")
	if info, err := os.Stat(out); err != nil || info.Size() == 0 {
		t.Fatalf("default output stat = %v, %v", info, err)
	}
}

const fatalTrapSentinel = "mkrpm: log.Fatal reached"

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
	flag.CommandLine = flag.NewFlagSet("mkrpm", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkrpm",
		"-binary", filepath.Join(dir, "absent"),
		"-out", filepath.Join(dir, "out.rpm"),
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
