package virt

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestSerialConsoleInterruptAfterCloseIsNoop pins the use-after-free guard: once
// Close has freed the libvirt stream, Interrupt (virStreamAbort) must not touch
// it. A logout callback can call Interrupt after — or concurrently with — the
// bridge's own Close, and aborting a freed stream is a cgo use-after-free that
// crashes the whole process. The libvirt handles are left nil here so the test
// fails loudly (nil dereference) if either method ever reaches the stream after
// freed is set, instead of only crashing against a real libvirt build.
func TestSerialConsoleInterruptAfterCloseIsNoop(t *testing.T) {
	sc := &SerialConsole{freed: true}

	if err := sc.Interrupt(); err != nil {
		t.Fatalf("Interrupt after Close: got %v, want nil no-op", err)
	}
	if err := sc.Close(); err != nil {
		t.Fatalf("second Close: got %v, want nil no-op", err)
	}
}

// TestSerialConsoleInterruptCloseRaceSafe exercises the mutex that serializes
// Interrupt against Close under the race detector. It runs on an already-freed
// console so no real libvirt call is made; it guards against a future change
// that drops the lock and reintroduces the abort/free data race.
func TestSerialConsoleInterruptCloseRaceSafe(_ *testing.T) {
	sc := &SerialConsole{freed: true}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = sc.Interrupt() }()
		go func() { defer wg.Done(); _ = sc.Close() }()
	}
	wg.Wait()
}

func TestDomainXMLUsesManagedSerialPTY(t *testing.T) {
	xml := DomainXML("alice-devbox", "alice-devbox_seed.iso", "desktop", 4, 4096)

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
