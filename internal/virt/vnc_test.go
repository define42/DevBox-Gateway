package virt

import (
	"path/filepath"
	"rdptlsgateway/internal/config"
	"strings"
	"testing"
)

func TestUbuntuDomainIncludesVNCSocket(t *testing.T) {
	xml := UbuntuDomain("alice-devbox", "alice-devbox_seed.iso", "desktop", "/tmp/alice-devbox.serial.sock", "/tmp/alice-devbox.vnc.sock", 4, 4096)

	if !strings.Contains(xml, "<graphics type='vnc' autoport='no' socket='/tmp/alice-devbox.vnc.sock'>") {
		t.Fatalf("expected VNC graphics socket in domain XML, got %s", xml)
	}
	if !strings.Contains(xml, "<listen type='socket' socket='/tmp/alice-devbox.vnc.sock'/>") {
		t.Fatalf("expected VNC listen socket in domain XML, got %s", xml)
	}
}

func TestVNCSocketDirUsesDerivedDataRoot(t *testing.T) {
	t.Setenv(config.DATA_ROOT_DIR, "/srv/libvirt/devboxes")

	settings := config.NewSettingType(false)
	got := vncSocketDir(settings)
	want := filepath.Join("/srv/libvirt/devboxes", vncSocketSubdir)
	if got != want {
		t.Fatalf("expected VNC socket dir %q, got %q", want, got)
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
