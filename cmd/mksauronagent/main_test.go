package main

import (
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

// stageTree writes a fake SauronAgent tree holding every packaging input, with
// the prebuilt binaries in <root>/bin as SauronAgent's `make build` leaves them.
func stageTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{
		"bin/sauronagent",
		"bin/sauronhost",
		"packaging/systemd/sauronagent.service",
		"packaging/systemd/sauronhost.service",
		"packaging/systemd/sauronagent.sysusers.conf",
		"packaging/systemd/sauronagent.tmpfiles.conf",
		"examples/sauronhost.yaml",
		"examples/qemu-vsock.md",
		"docs/protocol.md",
		"docs/security.md",
		"docs/deployment.md",
		"README.md",
		"LICENSE",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte("content of "+name), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	return root
}

// runMain runs main with the given arguments and a fresh flag set, restoring
// the process-wide state afterwards.
func runMain(t *testing.T, args ...string) {
	t.Helper()
	previousArgs := os.Args
	previousFlags := flag.CommandLine
	previousLogOutput := log.Writer()
	t.Cleanup(func() {
		os.Args = previousArgs
		flag.CommandLine = previousFlags
		log.SetOutput(previousLogOutput)
	})

	flag.CommandLine = flag.NewFlagSet("mksauronagent", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = append([]string{"mksauronagent"}, args...)
	main()
}

func TestMainWritesBothFormats(t *testing.T) {
	root := stageTree(t)
	dir := t.TempDir()
	for _, format := range []string{"rpm", "deb"} {
		output := filepath.Join(dir, "from-main."+format)
		runMain(t, "-format", format, "-version", "2.0.0", "-release", "3", "-src", root, "-out", output)
		if info, err := os.Stat(output); err != nil || info.Size() == 0 {
			t.Fatalf("%s output stat = %v, %v", format, info, err)
		}
	}
}

func TestMainDefaultOutputPaths(t *testing.T) {
	root := stageTree(t)
	t.Chdir(t.TempDir())
	if err := os.Mkdir("dist", 0o750); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}

	runMain(t, "-format", "rpm", "-version", "9.9.9", "-release", "7", "-arch", "x86_64", "-src", root)
	runMain(t, "-format", "deb", "-version", "9.9.9", "-arch", "amd64", "-bindir", filepath.Join(root, "bin"), "-src", root)

	for _, output := range []string{"dist/sauronagent-9.9.9-7.x86_64.rpm", "dist/sauronagent_9.9.9_amd64.deb"} {
		if info, err := os.Stat(output); err != nil || info.Size() == 0 {
			t.Fatalf("default output %s stat = %v, %v", output, info, err)
		}
	}
}

const fatalTrapSentinel = "mksauronagent: log.Fatal reached"

type fatalTrapWriter struct{}

func (fatalTrapWriter) Write([]byte) (int, error) {
	panic(fatalTrapSentinel)
}

func TestMainFatalOnUnknownFormat(t *testing.T) {
	previousLogOutput := log.Writer()
	t.Cleanup(func() { log.SetOutput(previousLogOutput) })
	log.SetOutput(fatalTrapWriter{})

	defer func() {
		if recovered := recover(); recovered != fatalTrapSentinel {
			t.Fatalf("main did not reach log.Fatal; recovered %v", recovered)
		}
	}()
	runMain(t, "-format", "zip", "-out", filepath.Join(t.TempDir(), "out.zip"))
	t.Fatal("main returned even though packaging failed")
}
