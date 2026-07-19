package virt

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"libvirt.org/go/libvirt"
)

func TestViocovSerialSocketPathParsingEdgeCases(t *testing.T) {
	if _, _, err := serialSocketPathFromDomainXML("<domain"); err == nil {
		t.Fatal("expected parse error for malformed XML")
	}

	// A serial device whose source path is blank is skipped.
	xmlDesc := `<domain><devices><serial type='pty'><source path='   '/></serial></devices></domain>`
	path, ok, err := serialSocketPathFromDomainXML(xmlDesc)
	if err != nil {
		t.Fatalf("parsing blank source path: %v", err)
	}
	if ok || path != "" {
		t.Fatalf("expected blank source path to be skipped, got %q", path)
	}

	if _, _, err := domainSerialSocketPath(nil); err == nil {
		t.Fatal("expected error for nil domain")
	}
	if _, _, err := domainSerialSocketPath(&libvirt.Domain{}); err == nil {
		t.Fatal("expected error for an invalid domain handle")
	}
}

func TestViocovVNCSocketPathParsingEdgeCases(t *testing.T) {
	if _, _, err := vncSocketPathFromDomainXML("<domain"); err == nil {
		t.Fatal("expected parse error for malformed XML")
	}

	cases := []struct {
		name string
		xml  string
		path string
		ok   bool
	}{
		{
			name: "non-vnc graphics skipped",
			xml:  `<domain><devices><graphics type='spice' socket='/tmp/spice.sock'/></devices></domain>`,
		},
		{
			name: "listen socket fallback",
			xml:  `<domain><devices><graphics type='vnc'><listen type='socket' socket='/tmp/viocov.vnc'/></graphics></devices></domain>`,
			path: "/tmp/viocov.vnc",
			ok:   true,
		},
		{
			name: "blank socket attributes",
			xml:  `<domain><devices><graphics type='vnc' socket='  '><listen type='socket' socket=' '/></graphics></devices></domain>`,
		},
		{
			name: "listen without socket type",
			xml:  `<domain><devices><graphics type='vnc'><listen type='address' address='127.0.0.1'/></graphics></devices></domain>`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, ok, err := vncSocketPathFromDomainXML(tc.xml)
			if err != nil {
				t.Fatalf("parsing: %v", err)
			}
			if ok != tc.ok || path != tc.path {
				t.Fatalf("got (%q, %v), want (%q, %v)", path, ok, tc.path, tc.ok)
			}
		})
	}

	if _, _, err := domainVNCSocketPath(nil); err == nil {
		t.Fatal("expected error for nil domain")
	}
	if _, _, err := domainVNCSocketPath(&libvirt.Domain{}); err == nil {
		t.Fatal("expected error for an invalid domain handle")
	}
}

func TestViocovConsoleAndVNCUnavailableStates(t *testing.T) {
	missing := viocovUniqueName("absent")
	if _, err := OpenSerialConsole(missing); err == nil || !strings.Contains(err.Error(), "lookup domain") {
		t.Fatalf("OpenSerialConsole(missing): expected lookup error, got %v", err)
	}
	if _, err := OpenVNCConn(missing); err == nil || !strings.Contains(err.Error(), "lookup domain") {
		t.Fatalf("OpenVNCConn(missing): expected lookup error, got %v", err)
	}

	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("stopped")
	viocovDefineDomain(t, conn, name, "")

	if _, err := OpenSerialConsole(name); !errors.Is(err, ErrSerialConsoleNotRunning) {
		t.Fatalf("expected ErrSerialConsoleNotRunning, got %v", err)
	}
	if _, err := OpenVNCConn(name); !errors.Is(err, ErrVNCNotRunning) {
		t.Fatalf("expected ErrVNCNotRunning, got %v", err)
	}
}

func TestViocovSerialConsoleOnRunningDomain(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("serial")
	dom := viocovStartDomain(t, conn, name, "<serial type='pty'><target port='0'/></serial>")

	if !domainTTYReady(dom) {
		t.Fatal("expected running PTY serial to report TTY ready")
	}

	console, err := OpenSerialConsole(name)
	if err != nil {
		t.Fatalf("OpenSerialConsole: %v", err)
	}
	n, err := console.Send([]byte("\n"))
	if err != nil {
		t.Fatalf("console send: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 byte sent, got %d", n)
	}
	if err := console.Close(); err != nil {
		t.Fatalf("console close: %v", err)
	}
}

func TestViocovConsoleAndVNCWithoutDevices(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("nodev")
	viocovStartDomain(t, conn, name, "")

	// A running domain without any console device fails inside OpenConsole.
	if _, err := OpenSerialConsole(name); err == nil || !strings.Contains(err.Error(), "open console") {
		t.Fatalf("expected open-console failure, got %v", err)
	}
	if _, err := OpenVNCConn(name); !errors.Is(err, ErrVNCNotConfigured) {
		t.Fatalf("expected ErrVNCNotConfigured, got %v", err)
	}
}

func TestViocovOpenVNCConnOnRunningDomain(t *testing.T) {
	conn := newTestLibvirtConn(t)
	dir := newLibvirtAccessibleTempDir(t, "viocov-vnc-")
	socketPath := filepath.Join(dir, "vnc.sock")
	name := viocovUniqueName("vnc")
	dom := viocovStartDomain(t, conn, name, fmt.Sprintf("<graphics type='vnc' socket='%s'/>", socketPath))
	viocovWaitForFile(t, socketPath)

	if !domainVNCReady(dom) {
		t.Fatal("expected running VNC domain to report VNC ready")
	}

	vncConn, err := OpenVNCConn(name)
	if err != nil {
		t.Fatalf("OpenVNCConn direct dial: %v", err)
	}
	_ = vncConn.Close()

	// Removing the socket path makes the direct dial fail with ENOENT, forcing
	// either the OpenGraphicsFD fallback or the not-ready classification.
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("remove vnc socket: %v", err)
	}
	fallbackConn, err := OpenVNCConn(name)
	if err != nil {
		if !errors.Is(err, ErrVNCNotReady) {
			t.Fatalf("expected fallback connection or ErrVNCNotReady, got %v", err)
		}
		return
	}
	_ = fallbackConn.Close()
}

func TestViocovOpenVNCViaGraphicsFDRequiresRunningDomain(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("gfx")
	dom := viocovDefineDomain(t, conn, name, "")

	if _, err := openVNCViaGraphicsFD(dom, name); err == nil {
		t.Fatal("expected OpenGraphicsFD to fail for a stopped domain")
	}
}

func TestViocovVNCDebugLogging(t *testing.T) {
	SetVNCDebugLogging(true)
	t.Cleanup(func() { SetVNCDebugLogging(false) })

	// Enabled branch writes through the logger; disabled branch returns early.
	vncDebugf("viocov debug %s", "enabled")
	SetVNCDebugLogging(false)
	vncDebugf("viocov debug %s", "disabled")
}
