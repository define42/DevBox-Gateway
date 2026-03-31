package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

func TestMainFatalOnBootError(t *testing.T) {
	if os.Getenv("TEST_MAIN_FATAL_ON_BOOT_ERROR") == "1" {
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainFatalOnBootError$")
	cmd.Env = append(os.Environ(),
		"TEST_MAIN_FATAL_ON_BOOT_ERROR=1",
		"LIBVIRT_URI=bad:///uri",
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected subprocess running main() to fail")
	}
	if !bytes.Contains(output, []byte("Failed to boot gateway")) {
		t.Fatalf("expected fatal boot message, got %q", string(output))
	}
}
