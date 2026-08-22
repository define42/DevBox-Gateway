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

func TestMainWritesDeb(t *testing.T) {
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
	output := filepath.Join(dir, "from-main.deb")

	flag.CommandLine = flag.NewFlagSet("mkdeb", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkdeb",
		"-version", "2.0.0",
		"-arch", "amd64",
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

	flag.CommandLine = flag.NewFlagSet("mkdeb", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkdeb",
		"-version", "9.9.9",
		"-arch", "amd64",
		"-binary", binary,
		"-unit", unit,
		"-conf", config,
		"-license", filepath.Join(dir, "LICENSE"),
	}

	main()

	output := filepath.Join(dir, "dist", "devbox-gateway_9.9.9_amd64.deb")
	if info, err := os.Stat(output); err != nil || info.Size() == 0 {
		t.Fatalf("default output stat = %v, %v", info, err)
	}
}

const fatalTrapSentinel = "mkdeb: log.Fatal reached"

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
	flag.CommandLine = flag.NewFlagSet("mkdeb", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"mkdeb",
		"-binary", filepath.Join(dir, "absent"),
		"-out", filepath.Join(dir, "out.deb"),
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
