package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"

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
// It uses libvirt's OpenGraphicsFD: libvirt opens the (libvirt-managed) VNC unix
// socket itself — as root, unconfined by svirt — and passes back a connected
// file descriptor. The gateway therefore never touches the socket path, which
// lives in libvirt's per-domain runtime directory
// (/var/lib/libvirt/qemu/domain-*/) that is otherwise unreachable for a non-root
// or SELinux-confined gateway. This mirrors how libvirt fd-passes the serial
// console socket.
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

	// idx 0 = the domain's first (only) graphics device; SKIPAUTH yields the raw
	// RFB stream (the unix-socket VNC has no password), matching a direct dial.
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
