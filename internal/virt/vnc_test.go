package virt

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestUbuntuDomainUsesManagedVNCSocket(t *testing.T) {
	xml := UbuntuDomain("alice-devbox", "alice-devbox_seed.iso", "desktop", 4, 4096)

	// libvirt allocates and labels the VNC socket; the domain XML must not pin an
	// explicit graphics socket path (that is what broke socket bind under SELinux).
	if !strings.Contains(xml, "<graphics type='vnc' autoport='no'>") {
		t.Fatalf("expected managed VNC graphics in domain XML, got %s", xml)
	}
	if !strings.Contains(xml, "<listen type='socket'/>") {
		t.Fatalf("expected managed VNC listen socket in domain XML, got %s", xml)
	}
	if strings.Contains(xml, "graphics type='vnc' autoport='no' socket=") {
		t.Fatalf("domain XML must not pin an explicit graphics socket path, got %s", xml)
	}
}

func TestVNCSocketPathFromDomainXML(t *testing.T) {
	xml := `<domain><devices><graphics type='vnc' autoport='no' socket='/tmp/test.vnc.sock'><listen type='socket' socket='/tmp/test.vnc.sock'/></graphics></devices></domain>`

	path, ok, err := vncSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected VNC socket to be detected")
	}
	if path != filepath.Clean("/tmp/test.vnc.sock") {
		t.Fatalf("expected VNC socket path %q, got %q", "/tmp/test.vnc.sock", path)
	}
}

func TestVNCSocketPathFromDomainXMLReturnsFalseForLegacyDomain(t *testing.T) {
	xml := `<domain><devices><graphics type='vnc' autoport='no'><listen type='none'/></graphics></devices></domain>`

	path, ok, err := vncSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected no VNC socket path, got %q", path)
	}
	if path != "" {
		t.Fatalf("expected empty path, got %q", path)
	}
}
