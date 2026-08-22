package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"strings"
	"testing"
)

// readControlFile extracts the `control` file from the control.tar.gz member of
// an in-memory .deb so tests can assert on its contents.
func readControlFile(t *testing.T, deb []byte) string {
	t.Helper()
	members, err := parseAr(deb)
	if err != nil {
		t.Fatalf("parseAr: %v", err)
	}
	for i := range members {
		if members[i].name() == "control.tar.gz" {
			return controlBody(t, members[i].data)
		}
	}
	t.Fatal("control.tar.gz not found")
	return ""
}

// makeControlTarGz builds a minimal control.tar.gz holding a single `control`
// file with the given body, for exercising appendNewlineToControl directly.
func makeControlTarGz(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "control", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func controlBody(t *testing.T, gz []byte) string {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if hdr.Name == "control" {
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			return string(b)
		}
	}
	t.Fatal("control not found")
	return ""
}

func TestAppendNewlineToControlAddsNewline(t *testing.T) {
	gz := makeControlTarGz(t, "Package: x\nDescription: short\n no trailing newline")
	out, changed, err := appendNewlineToControl(gz)
	if err != nil {
		t.Fatalf("appendNewlineToControl: %v", err)
	}
	if !changed {
		t.Fatal("expected changed = true for control lacking a trailing newline")
	}
	if body := controlBody(t, out); !strings.HasSuffix(body, "newline\n") {
		t.Fatalf("control not newline-terminated: %q", body)
	}
}

func TestAppendNewlineToControlIdempotent(t *testing.T) {
	gz := makeControlTarGz(t, "Package: x\n")
	_, changed, err := appendNewlineToControl(gz)
	if err != nil {
		t.Fatalf("appendNewlineToControl: %v", err)
	}
	if changed {
		t.Fatal("expected changed = false when control already ends with a newline")
	}
}

func TestParseArRoundTrip(t *testing.T) {
	// Two members with even and odd sizes to exercise the padding logic.
	m1 := makeMember("debian-binary", "2.0\n") // size 4 (even)
	m2 := makeMember("control.tar.gz", "odd")  // size 3 (odd -> padded)
	packed := writeAr([]arMember{m1, m2})

	members, err := parseAr(packed)
	if err != nil {
		t.Fatalf("parseAr: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2", len(members))
	}
	if members[0].name() != "debian-binary" || string(members[0].data) != "2.0\n" {
		t.Fatalf("member 0 mismatch: %q %q", members[0].name(), members[0].data)
	}
	if members[1].name() != "control.tar.gz" || string(members[1].data) != "odd" {
		t.Fatalf("member 1 mismatch: %q %q", members[1].name(), members[1].data)
	}
}

func TestParseArRejectsBadMagic(t *testing.T) {
	if _, err := parseAr([]byte("not an ar")); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestSetDataUpdatesSizeField(t *testing.T) {
	m := makeMember("control.tar.gz", "abc")
	m.setData([]byte("longer body"))
	if string(m.data) != "longer body" {
		t.Fatalf("data = %q", m.data)
	}
	got := strings.TrimRight(string(m.header[arSizeStart:arSizeEnd]), " ")
	if got != "11" {
		t.Fatalf("size field = %q, want 11", got)
	}
}

// makeMember builds an arMember with a correctly populated header for the given
// name and body, mirroring how the ar writer lays out the size field.
func makeMember(name, body string) arMember {
	var m arMember
	// Pad the whole header with spaces first, then stamp the name and a valid
	// terminator so parseAr can read it back.
	for i := range m.header {
		m.header[i] = ' '
	}
	copy(m.header[:16], name)
	m.header[58] = '`'
	m.header[59] = '\n'
	m.setData([]byte(body))
	return m
}
