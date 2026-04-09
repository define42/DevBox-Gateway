package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"strings"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	vncSocketSubdir = "vnc"
	vncSocketSuffix = ".vnc.sock"
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

func vncSocketDir(settings *config.SettingsType) string {
	return config.VNCSocketDir(settings)
}

func vncSocketPath(settings *config.SettingsType, name string) string {
	return filepath.Join(vncSocketDir(settings), name+vncSocketSuffix)
}

func ensureVNCSocketDir(settings *config.SettingsType) (string, error) {
	return ensureSocketDir(vncSocketDir(settings), "vnc")
}

func removeVNCSocket(settings *config.SettingsType, name string) error {
	return removeSocketPath(vncSocketPath(settings, name), "vnc")
}

func cleanupDomainVNCSocket(dom *libvirt.Domain) error {
	socketPath, ok, err := domainVNCSocketPath(dom)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return removeSocketPath(socketPath, "vnc")
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

// VNCSocketPathForDomain returns the VNC socket path for a running domain.
func VNCSocketPathForDomain(name string) (string, error) {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return "", fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return "", fmt.Errorf("check domain active %s: %w", name, err)
	}
	if !active {
		return "", ErrVNCNotRunning
	}

	socketPath, ok, err := domainVNCSocketPath(dom)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrVNCNotConfigured
	}

	return socketPath, nil
}

// DialVNCSocket connects to the VNC socket for a running domain.
func DialVNCSocket(name string, timeout time.Duration) (net.Conn, error) {
	socketPath, err := VNCSocketPathForDomain(name)
	if err != nil {
		return nil, err
	}

	vncConn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrVNCNotReady
		}
		return nil, fmt.Errorf("dial vnc socket %s: %w", socketPath, err)
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
