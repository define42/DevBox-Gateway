package virt

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUbuntuDomainUsesManagedSerialPTY(t *testing.T) {
	xml := UbuntuDomain("alice-devbox", "alice-devbox_seed.iso", "desktop", 4, 4096)

	// The serial console is a libvirt-managed PTY (read via OpenConsole); the
	// domain XML must not pin a gateway-chosen unix socket path.
	if !strings.Contains(xml, "<serial type='pty'>") {
		t.Fatalf("expected pty serial device in domain XML, got %s", xml)
	}
	if strings.Contains(xml, "type='unix'") || strings.Contains(xml, "mode='bind'") {
		t.Fatalf("did not expect a unix serial socket in domain XML, got %s", xml)
	}
}

func TestSerialSocketPathFromDomainXML(t *testing.T) {
	// A running PTY serial exposes its allocated device via <source path>.
	xml := `<domain><devices><serial type='pty'><source path='/dev/pts/3'/><target port='0'/></serial></devices></domain>`

	path, ok, err := serialSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected serial console to be detected")
	}
	if path != filepath.Clean("/dev/pts/3") {
		t.Fatalf("expected serial console path %q, got %q", "/dev/pts/3", path)
	}
}

func TestSerialSocketPathFromDomainXMLReturnsFalseForLegacyDomain(t *testing.T) {
	xml := `<domain><devices><console type='pty'/></devices></domain>`

	path, ok, err := serialSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected no serial socket path, got %q", path)
	}
	if path != "" {
		t.Fatalf("expected empty path, got %q", path)
	}
}
