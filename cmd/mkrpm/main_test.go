package main

import (
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func stageInputs(t *testing.T, dir string) (binary, unit, config string) {
	t.Helper()
	binary = filepath.Join(dir, "devbox-gateway")
	unit = filepath.Join(dir, "devbox-gateway.service")
	config = filepath.Join(dir, "devbox-gateway.conf")
	for _, file := range []string{binary, unit, config} {
		if err := os.WriteFile(file, []byte("content of "+filepath.Base(file)), 0o600); err != nil {
			t.Fatalf("seed %s: %v", file, err)
		}
	}
	return binary, unit, config
}

func TestMainWritesRPM(t *testing.T) {
	previousArgs := os.Args
	previousFlags := flag.CommandLine
	previousLogOutput := log.Writer()
	t.Cleanup(func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlags
		log.SetOutput(previousLogOutput)
	})

	dir := t.TempDir()
	binary, unit, config := stageInputs(t, dir)
	output := filepath.Join(dir, "from-main.rpm")

	flag.CommandLine = flag.NewFlagSet("mkrpm", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkrpm",
		"-version", "2.0.0",
		"-release", "3",
		"-arch", "x86_64",
		"-binary", binary,
		"-unit", unit,
		"-conf", config,
		"-license", filepath.Join(dir, "LICENSE"),
		"-out", output,
	}

	main()

	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatalf("main output stat = %v, %v", info, err)
	}
}

func TestMainDefaultOutputPath(t *testing.T) {
	previousArgs := os.Args
	previousFlags := flag.CommandLine
	t.Cleanup(func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlags
	})

	dir := t.TempDir()
	binary, unit, config := stageInputs(t, dir)
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
		"-binary", binary,
		"-unit", unit,
		"-conf", config,
		"-license", filepath.Join(dir, "LICENSE"),
	}

	main()

	output := filepath.Join(dir, "dist", "devbox-gateway-9.9.9-7.x86_64.rpm")
	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatalf("default output stat = %v, %v", info, err)
	}
}

const fatalTrapSentinel = "mkrpm: log.Fatal reached"

type fatalTrapWriter struct{}

func (fatalTrapWriter) Write([]byte) (int, error) {
	panic(fatalTrapSentinel)
}

func TestMainFatalOnError(t *testing.T) {
	previousArgs := os.Args
	previousFlags := flag.CommandLine
	previousLogOutput := log.Writer()
	t.Cleanup(func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlags
		log.SetOutput(previousLogOutput)
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
		if recovered := recover(); recovered != fatalTrapSentinel {
			t.Fatalf("main did not reach log.Fatal; recovered %v", recovered)
		}
	}()
	main()
	t.Fatal("main returned even though packaging failed")
}
