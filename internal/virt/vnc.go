package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"

	"libvirt.org/go/libvirt"
)

var (
	// ErrVNCNotConfigured reports that the domain does not expose a VNC socket.
	ErrVNCNotConfigured = errors.New("vnc not configured")
	// ErrVNCNotRunning reports that the domain is not running.
	ErrVNCNotRunning = errors.New("vnc not running")
	// ErrVNCNotReady reports that the VNC socket path does not exist yet.
	ErrVNCNotReady = errors.New("vnc not ready")
)

// vncDebugLogging gates verbose VNC-backend diagnostics (which connection path
// was used). Enabled from main when DEBUG_CONNECTIONS is set.
var vncDebugLogging atomic.Bool //nolint:gochecknoglobals // package-level debug toggle set once at startup

// SetVNCDebugLogging toggles verbose VNC backend debug logging.
func SetVNCDebugLogging(enabled bool) {
	vncDebugLogging.Store(enabled)
}

func vncDebugf(format string, args ...any) {
	if vncDebugLogging.Load() {
		log.Printf("vnc-debug: "+format, args...)
	}
}

type domainGraphicsXML struct {
	Devices struct {
		Graphics []domainGraphicsDeviceXML `xml:"graphics"`
	} `xml:"devices"`
}

type domainGraphicsDeviceXML struct {
	Type   string `xml:"type,attr"`
	Socket string `xml:"socket,attr"`
	Listen struct {
		Type   string `xml:"type,attr"`
		Socket string `xml:"socket,attr"`
	} `xml:"listen"`
}

func vncSocketPathFromDomainXML(xmlDesc string) (string, bool, error) {
	var parsed domainGraphicsXML
	if err := xml.Unmarshal([]byte(xmlDesc), &parsed); err != nil {
		return "", false, fmt.Errorf("parse domain xml: %w", err)
	}

	for _, graphics := range parsed.Devices.Graphics {
		if strings.TrimSpace(graphics.Type) != "vnc" {
			continue
		}
		if socketPath := cleanGraphicsSocketPath(graphics.Socket); socketPath != "" {
			return socketPath, true, nil
		}
		if strings.TrimSpace(graphics.Listen.Type) == "socket" {
			if socketPath := cleanGraphicsSocketPath(graphics.Listen.Socket); socketPath != "" {
				return socketPath, true, nil
			}
		}
	}

	return "", false, nil
}

func domainVNCSocketPath(dom *libvirt.Domain) (string, bool, error) {
	if dom == nil {
		return "", false, fmt.Errorf("domain is nil")
	}
	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		return "", false, fmt.Errorf("get domain xml: %w", err)
	}
	return vncSocketPathFromDomainXML(xmlDesc)
}

// OpenVNCConn returns a connection to a running domain's VNC server.
//
// It first dials the libvirt-managed VNC unix socket directly. When the gateway
// runs as root with access to libvirt's per-domain runtime directory
// (/var/lib/libvirt/qemu/domain-*/), this is the simplest and most reliable way
// to reach the raw RFB stream.
//
// If the direct dial fails — e.g. the gateway runs in a container that only has
// libvirt's RPC socket mounted (not the per-domain socket path), or is
// SELinux-confined and cannot touch the path — it falls back to libvirt's
// OpenGraphicsFD, which opens the socket inside libvirtd (as root, unconfined by
// svirt) and fd-passes a connected descriptor back. This mirrors how libvirt
// fd-passes the serial console socket. OpenGraphicsFD's QEMU add_client path has
// been observed to hand back an fd that yields no RFB stream on some hosts, so
// the direct dial is preferred whenever the path is reachable.
func OpenVNCConn(name string) (net.Conn, error) {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return nil, fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return nil, fmt.Errorf("check domain active %s: %w", name, err)
	}
	if !active {
		return nil, ErrVNCNotRunning
	}

	socketPath, ok, err := domainVNCSocketPath(dom)
	if err != nil {
		return nil, fmt.Errorf("resolve vnc socket for %s: %w", name, err)
	}
	if !ok {
		return nil, ErrVNCNotConfigured
	}

	// Preferred: dial the libvirt-managed VNC unix socket directly.
	vncConn, dialErr := net.Dial("unix", socketPath)
	if dialErr == nil {
		vncDebugf("vm %q: connected via direct unix socket %s", name, socketPath)
		return vncConn, nil
	}
	vncDebugf("vm %q: direct dial of %s failed (%v); trying OpenGraphicsFD fallback", name, socketPath, dialErr)

	// Fallback: ask libvirtd to open the socket and fd-pass it back.
	fdConn, fdErr := openVNCViaGraphicsFD(dom, name)
	if fdErr == nil {
		vncDebugf("vm %q: connected via OpenGraphicsFD fallback", name)
		return fdConn, nil
	}

	// The socket path not existing yet (boot race) is the documented "not ready"
	// condition the callers retry on.
	if errors.Is(dialErr, fs.ErrNotExist) {
		return nil, ErrVNCNotReady
	}
	return nil, fmt.Errorf("open vnc for %s: dial %s: %w; graphics-fd fallback: %w", name, socketPath, dialErr, fdErr)
}

// openVNCViaGraphicsFD opens the domain's VNC stream through libvirt's
// OpenGraphicsFD so the gateway never touches the socket path itself. idx 0 is
// the domain's first (only) graphics device; SKIPAUTH yields the raw RFB stream
// (the unix-socket VNC has no password), matching a direct dial.
func openVNCViaGraphicsFD(dom *libvirt.Domain, name string) (net.Conn, error) {
	file, err := dom.OpenGraphicsFD(0, libvirt.DOMAIN_OPEN_GRAPHICS_SKIPAUTH)
	if err != nil {
		return nil, fmt.Errorf("open graphics fd for %s: %w", name, err)
	}
	// net.FileConn dups the fd, so the original file can be closed afterwards.
	defer func() { _ = file.Close() }()

	vncConn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("wrap graphics fd for %s: %w", name, err)
	}
	return vncConn, nil
}

func cleanGraphicsSocketPath(path string) string {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || path == "." {
		return ""
	}
	return path
}
