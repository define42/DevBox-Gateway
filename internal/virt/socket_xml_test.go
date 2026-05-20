package virt

import "testing"

func TestSerialSocketPathFromDomainXMLInvalidXML(t *testing.T) {
	if _, _, err := serialSocketPathFromDomainXML("<<<not xml"); err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

func TestSerialSocketPathFromDomainXMLSkipsNonUnix(t *testing.T) {
	xml := `<domain><devices>` +
		`<serial type='pty'><source path='/dev/pts/1'/></serial>` +
		`<serial type='unix'><source path='/tmp/devbox.serial.sock'/></serial>` +
		`</devices></domain>`
	path, ok, err := serialSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || path != "/tmp/devbox.serial.sock" {
		t.Fatalf("expected /tmp/devbox.serial.sock, got %q (ok=%v)", path, ok)
	}
}

func TestSerialSocketPathFromDomainXMLSkipsBlankPath(t *testing.T) {
	xml := `<domain><devices>` +
		`<serial type='unix'><source path='   '/></serial>` +
		`<serial type='unix'><source path='/tmp/devbox.serial.sock'/></serial>` +
		`</devices></domain>`
	path, ok, err := serialSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || path != "/tmp/devbox.serial.sock" {
		t.Fatalf("expected /tmp/devbox.serial.sock, got %q (ok=%v)", path, ok)
	}
}

func TestVNCSocketPathFromDomainXMLInvalidXML(t *testing.T) {
	if _, _, err := vncSocketPathFromDomainXML("<<<not xml"); err == nil {
		t.Fatal("expected error for malformed XML")
	}
}

func TestVNCSocketPathFromDomainXMLSkipsNonVNC(t *testing.T) {
	xml := `<domain><devices>` +
		`<graphics type='spice' autoport='no'><listen type='none'/></graphics>` +
		`<graphics type='vnc' autoport='no' socket='/tmp/devbox.vnc.sock'><listen type='socket' socket='/tmp/devbox.vnc.sock'/></graphics>` +
		`</devices></domain>`
	path, ok, err := vncSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || path != "/tmp/devbox.vnc.sock" {
		t.Fatalf("expected /tmp/devbox.vnc.sock, got %q (ok=%v)", path, ok)
	}
}

func TestVNCSocketPathFromDomainXMLUsesListenSocketFallback(t *testing.T) {
	xml := `<domain><devices>` +
		`<graphics type='vnc' autoport='no'><listen type='socket' socket='/tmp/listen-only.vnc.sock'/></graphics>` +
		`</devices></domain>`
	path, ok, err := vncSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || path != "/tmp/listen-only.vnc.sock" {
		t.Fatalf("expected /tmp/listen-only.vnc.sock fallback, got %q (ok=%v)", path, ok)
	}
}

func TestDomainSerialSocketPathNilDomain(t *testing.T) {
	if _, _, err := domainSerialSocketPath(nil); err == nil {
		t.Fatal("expected error for nil domain")
	}
}

func TestDomainVNCSocketPathNilDomain(t *testing.T) {
	if _, _, err := domainVNCSocketPath(nil); err == nil {
		t.Fatal("expected error for nil domain")
	}
}

func TestCleanupDomainSerialSocketNilDomain(t *testing.T) {
	if err := cleanupDomainSerialSocket(nil); err == nil {
		t.Fatal("expected error for nil domain")
	}
}

func TestCleanupDomainVNCSocketNilDomain(t *testing.T) {
	if err := cleanupDomainVNCSocket(nil); err == nil {
		t.Fatal("expected error for nil domain")
	}
}
