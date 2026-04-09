package virt

import (
	"path/filepath"
	"rdptlsgateway/internal/config"
	"strings"
	"testing"
)

func TestUbuntuDomainWithSerialSocketIncludesUnixSerial(t *testing.T) {
	xml := UbuntuDomain("alice-devbox", "alice-devbox_seed.iso", "desktop", "/tmp/alice-devbox.serial.sock", "/tmp/alice-devbox.vnc.sock", 4, 4096)

	if !strings.Contains(xml, "<serial type='unix'>") {
		t.Fatalf("expected unix serial device in domain XML, got %s", xml)
	}
	if !strings.Contains(xml, "path='/tmp/alice-devbox.serial.sock'") {
		t.Fatalf("expected serial socket path in domain XML, got %s", xml)
	}
	if strings.Contains(xml, "<console type='pty'/>") {
		t.Fatalf("did not expect legacy pty console in domain XML, got %s", xml)
	}
}

func TestSerialSocketDirUsesDerivedDataRoot(t *testing.T) {
	t.Setenv(config.DATA_ROOT_DIR, "/srv/libvirt/devboxes")

	settings := config.NewSettingType(false)
	got := serialSocketDir(settings)
	want := filepath.Join("/srv/libvirt/devboxes", serialSocketSubdir)
	if got != want {
		t.Fatalf("expected serial socket dir %q, got %q", want, got)
	}
}

func TestSerialSocketPathFromDomainXML(t *testing.T) {
	xml := `<domain><devices><serial type='unix'><source mode='bind' path='/tmp/test.serial.sock'/><target port='0'/></serial></devices></domain>`

	path, ok, err := serialSocketPathFromDomainXML(xml)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected unix serial socket to be detected")
	}
	if path != filepath.Clean("/tmp/test.serial.sock") {
		t.Fatalf("expected serial socket path %q, got %q", "/tmp/test.serial.sock", path)
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
