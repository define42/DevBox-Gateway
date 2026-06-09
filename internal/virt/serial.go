package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"libvirt.org/go/libvirt"
)

var (
	// ErrSerialConsoleNotConfigured reports that the domain does not expose a serial console.
	ErrSerialConsoleNotConfigured = errors.New("serial console not configured")
	// ErrSerialConsoleNotRunning reports that the domain is not running.
	ErrSerialConsoleNotRunning = errors.New("serial console not running")
	// ErrSerialConsoleNotReady reports that the serial console is not ready yet.
	ErrSerialConsoleNotReady = errors.New("serial console not ready")
)

type domainSerialXML struct {
	Devices struct {
		Serials []domainSerialDeviceXML `xml:"serial"`
	} `xml:"devices"`
}

type domainSerialDeviceXML struct {
	Type   string `xml:"type,attr"`
	Source struct {
		Path string `xml:"path,attr"`
	} `xml:"source"`
}

func serialSocketPathFromDomainXML(xmlDesc string) (string, bool, error) {
	var parsed domainSerialXML
	if err := xml.Unmarshal([]byte(xmlDesc), &parsed); err != nil {
		return "", false, fmt.Errorf("parse domain xml: %w", err)
	}

	// A serial with an allocated source path (a PTY like /dev/pts/N on a running
	// domain, or a unix socket) indicates a usable console. A stopped domain's PTY
	// serial has no source path yet, so this reports the console as unavailable.
	for _, serial := range parsed.Devices.Serials {
		path := filepath.Clean(strings.TrimSpace(serial.Source.Path))
		if path == "" || path == "." {
			continue
		}
		return path, true, nil
	}

	return "", false, nil
}

func domainSerialSocketPath(dom *libvirt.Domain) (string, bool, error) {
	if dom == nil {
		return "", false, fmt.Errorf("domain is nil")
	}
	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		return "", false, fmt.Errorf("get domain xml: %w", err)
	}
	return serialSocketPathFromDomainXML(xmlDesc)
}

// SerialConsole is an open serial-console session backed by a libvirt console
// stream. libvirt performs the underlying socket access itself (as root, over its
// RPC stream), so the gateway never connects to the serial unix socket directly —
// which a non-root or SELinux-confined gateway cannot do because libvirt labels
// that socket with the VM's svirt MCS categories. This is the serial analog of
// OpenVNCConn and how `virsh console` works.
//
// Recv and Send may be called concurrently from one reader and one writer
// goroutine. Interrupt unblocks any in-flight Recv/Send; Close must be called
// only after both goroutines have returned (so it never frees the stream while a
// C call is still using it).
type SerialConsole struct {
	conn   *libvirt.Connect
	dom    *libvirt.Domain
	stream *libvirt.Stream
}

// OpenSerialConsole opens the default serial console of a running domain.
func OpenSerialConsole(name string) (*SerialConsole, error) {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return nil, fmt.Errorf("connect libvirt: %w", err)
	}

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		_, _ = conn.Close()
		return nil, fmt.Errorf("lookup domain %s: %w", name, err)
	}

	active, err := dom.IsActive()
	if err != nil {
		_ = dom.Free()
		_, _ = conn.Close()
		return nil, fmt.Errorf("check domain active %s: %w", name, err)
	}
	if !active {
		_ = dom.Free()
		_, _ = conn.Close()
		return nil, ErrSerialConsoleNotRunning
	}

	// Blocking stream (flags 0): Recv/Send block until data/EOF, so no libvirt
	// event loop is required.
	stream, err := conn.NewStream(0)
	if err != nil {
		_ = dom.Free()
		_, _ = conn.Close()
		return nil, fmt.Errorf("new console stream for %s: %w", name, err)
	}

	// devname "" selects the domain's default console; FORCE evicts a stale
	// client still holding it.
	if err := dom.OpenConsole("", stream, libvirt.DOMAIN_CONSOLE_FORCE); err != nil {
		_ = stream.Free()
		_ = dom.Free()
		_, _ = conn.Close()
		return nil, fmt.Errorf("open console for %s: %w", name, err)
	}

	return &SerialConsole{conn: conn, dom: dom, stream: stream}, nil
}

// Recv reads console output into p. It blocks until data is available and
// returns io.EOF when the console closes.
func (s *SerialConsole) Recv(p []byte) (int, error) { return s.stream.Recv(p) }

// Send writes p to the console. It may perform a partial write (callers should
// loop until all bytes are sent).
func (s *SerialConsole) Send(p []byte) (int, error) { return s.stream.Send(p) }

// Interrupt aborts the stream, unblocking any in-flight Recv/Send so the
// reader/writer goroutines can exit before Close.
func (s *SerialConsole) Interrupt() error { return s.stream.Abort() }

// Close releases the stream, domain, and libvirt connection. Call it only after
// every Recv/Send has returned.
func (s *SerialConsole) Close() error {
	_ = s.stream.Free()
	_ = s.dom.Free()
	_, _ = s.conn.Close()
	return nil
}
