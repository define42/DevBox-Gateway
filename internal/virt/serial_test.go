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
	tests := []struct {
		name           string
		xml            string
		wantPath       string
		wantConfigured bool
	}{
		{
			name:           "allocated PTY",
			xml:            `<domain><devices><serial type='pty'><source path='/dev/pts/3'/><target port='0'/></serial></devices></domain>`,
			wantPath:       filepath.Clean("/dev/pts/3"),
			wantConfigured: true,
		},
		{
			name:           "configured without live source",
			xml:            `<domain><devices><serial type='pty'><target port='0'/></serial></devices></domain>`,
			wantConfigured: true,
		},
		{
			name: "no serial device",
			xml:  `<domain><devices><console type='pty'/></devices></domain>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, configured, err := serialSocketPathFromDomainXML(tc.xml)
			if err != nil {
				t.Fatalf("parse serial XML: %v", err)
			}
			if path != tc.wantPath || configured != tc.wantConfigured {
				t.Fatalf("got (%q, %v), want (%q, %v)", path, configured, tc.wantPath, tc.wantConfigured)
			}
		})
	}
}

func TestSerialSocketPathFromDomainXMLRejectsMalformedXML(t *testing.T) {
	if _, _, err := serialSocketPathFromDomainXML("<domain"); err == nil {
		t.Fatal("expected malformed XML error")
	}
}
