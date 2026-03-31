package virt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgressReaderTracksBytes(t *testing.T) {
	reader := &progressReader{
		reader:      strings.NewReader("hello"),
		total:       5,
		lastPrinted: time.Now().Add(-time.Second),
	}

	buf := make([]byte, 5)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("progressReader.Read: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected to read 5 bytes, got %d", n)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("expected payload %q, got %q", "hello", got)
	}
	if reader.downloaded != 5 {
		t.Fatalf("expected downloaded bytes 5, got %d", reader.downloaded)
	}
}

func TestDownloadWithProgressCreateError(t *testing.T) {
	server := newImageServer(t, []byte("payload"), 200)
	defer server.Close()

	outputPath := filepath.Join(t.TempDir(), "missing", "out.img")
	err := downloadWithProgress(server.URL, outputPath)
	if err == nil {
		t.Fatal("expected output file creation error")
	}
	if _, statErr := os.Stat(outputPath); statErr == nil {
		t.Fatal("expected output file not to exist")
	}
}
