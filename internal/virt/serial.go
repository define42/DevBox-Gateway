package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"strconv"
	"strings"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	serialSocketSubdir = "serial"
	serialSocketSuffix = ".serial.sock"
)

var (
	ErrSerialConsoleNotConfigured = errors.New("serial console not configured")
	ErrSerialConsoleNotRunning    = errors.New("serial console not running")
	ErrSerialConsoleNotReady      = errors.New("serial console not ready")
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

func serialSocketDir(settings *config.SettingsType) string {
	if settings != nil {
		if configured := filepath.Clean(strings.TrimSpace(settings.Get(config.VIRT_SERIAL_SOCKET_DIR))); configured != "" && configured != "." {
			return configured
		}
	}

	_, poolPath := storagePoolConfig(settings)
	return filepath.Join(poolPath, serialSocketSubdir)
}

func serialSocketPath(settings *config.SettingsType, name string) string {
	return filepath.Join(serialSocketDir(settings), name+serialSocketSuffix)
}

func ensureSerialSocketDir(settings *config.SettingsType) (string, error) {
	return ensureSocketDir(serialSocketDir(settings), "serial")
}

func removeSerialSocket(settings *config.SettingsType, name string) error {
	return removeSocketPath(serialSocketPath(settings, name), "serial")
}

func cleanupDomainSerialSocket(dom *libvirt.Domain) error {
	socketPath, ok, err := domainSerialSocketPath(dom)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return removeSocketPath(socketPath, "serial")
}

func serialSocketPathFromDomainXML(xmlDesc string) (string, bool, error) {
	var parsed domainSerialXML
	if err := xml.Unmarshal([]byte(xmlDesc), &parsed); err != nil {
		return "", false, fmt.Errorf("parse domain xml: %w", err)
	}

	for _, serial := range parsed.Devices.Serials {
		if strings.TrimSpace(serial.Type) != "unix" {
			continue
		}
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

func SerialSocketPathForDomain(name string) (string, error) {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return "", fmt.Errorf("connect libvirt: %w", err)
	}
	defer conn.Close()

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
		return "", ErrSerialConsoleNotRunning
	}

	socketPath, ok, err := domainSerialSocketPath(dom)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrSerialConsoleNotConfigured
	}

	return socketPath, nil
}

func DialSerialSocket(name string, timeout time.Duration) (net.Conn, error) {
	socketPath, err := SerialSocketPathForDomain(name)
	if err != nil {
		return nil, err
	}

	serialConn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrSerialConsoleNotReady
		}
		return nil, fmt.Errorf("dial serial socket %s: %w", socketPath, err)
	}
	return serialConn, nil
}

func socketOwnership() (int, int, bool, error) {
	owner, hasOwner, err := parseSocketOwnershipEnv(volumeOwnerEnv)
	if err != nil {
		return 0, 0, false, err
	}
	group, hasGroup, err := parseSocketOwnershipEnv(volumeGroupEnv)
	if err != nil {
		return 0, 0, false, err
	}
	if !hasOwner && !hasGroup {
		return 0, 0, false, nil
	}

	if !hasOwner {
		owner = -1
	}
	if !hasGroup {
		group = -1
	}

	return owner, group, true, nil
}

func parseSocketOwnershipEnv(envVar string) (int, bool, error) {
	raw := strings.TrimSpace(os.Getenv(envVar))
	if raw == "" {
		return 0, false, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false, fmt.Errorf("invalid %s %q: %w", envVar, raw, err)
	}
	return value, true, nil
}

func removeSocketPath(socketPath, socketLabel string) error {
	socketPath = filepath.Clean(strings.TrimSpace(socketPath))
	if socketPath == "" || socketPath == "." {
		return nil
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s socket %s: %w", socketLabel, socketPath, err)
	}
	return nil
}
