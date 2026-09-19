package storage

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"

	"github.com/define42/devbox-gateway/internal/backendidentity"
	"github.com/define42/devbox-gateway/internal/cloudinit"
	"github.com/define42/devbox-gateway/internal/config"

	"github.com/google/uuid"
	"libvirt.org/go/libvirt"
)

// CreateSeedISOToPool builds a cloud-init seed ISO and uploads it to the storage pool.
func CreateSeedISOToPool(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
	credentials backendidentity.Credentials,
) error {
	return CreateSeedISOToPoolWithSettings(nil, conn, storagePoolName, volumeName, username, cloudInitPasswordHash, hostname, credentials)
}

// CreateSeedISOToPoolWithSettings builds and uploads a seed ISO using explicit settings.
func CreateSeedISOToPoolWithSettings(
	settings *config.Settings,
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
	credentials backendidentity.Credentials,
) error {
	userData, metaData, networkConfig, err := cloudInitSeedData(username, cloudInitPasswordHash, hostname, credentials)
	if err != nil {
		return err
	}
	seedISOData, err := cloudinit.CreateSeedISO(userData, metaData, networkConfig)
	if err != nil {
		return err
	}

	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return err
	}
	defer func() {
		if err := pool.Free(); err != nil {
			log.Printf("pool free error: %v", err)
		}
	}()

	volXML, err := VolumeCreateXMLWithSettings(settings, pool, volumeName, uint64(len(seedISOData)), "raw")
	if err != nil {
		return err
	}

	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = vol.Free()
	}()

	if err := UploadSeedISO(conn, vol, seedISOData); err != nil {
		return err
	}

	return ApplyVolumePermissions(settings, vol)
}

func cloudInitSeedData(username, cloudInitPasswordHash, hostname string, credentials backendidentity.Credentials) (*cloudinit.UserData, *cloudinit.MetaData, *cloudinit.NetworkConfig, error) {
	if _, err := backendidentity.TLSConfig(credentials.CertificatePEM, credentials.ServerName); err != nil {
		return nil, nil, nil, fmt.Errorf("validate seed backend identity: %w", err)
	}
	if _, err := tls.X509KeyPair([]byte(credentials.CertificatePEM), []byte(credentials.PrivateKeyPEM)); err != nil {
		return nil, nil, nil, fmt.Errorf("validate seed backend key: %w", err)
	}
	userData := &cloudinit.UserData{
		Output: &cloudinit.Output{
			All: "| tee -a /var/log/cloud-init-output.log",
		},
		Keyboard: &cloudinit.Keyboard{
			Layout:  "dk",
			Variant: "",
		},
		Users: []cloudinit.User{
			{
				Name: username,
				// Require the account password to escalate to root (sudo prompts)
				// rather than passwordless sudo, so a hijacked desktop session
				// cannot silently become root without knowing the password.
				Sudo:       "ALL=(ALL) ALL",
				Shell:      "/bin/bash",
				LockPasswd: false,
				Passwd:     cloudInitPasswordHash,
			},
		},
		WriteFiles: backendIdentityFiles(credentials),
		RunCmd: []string{
			"systemctl enable --now serial-getty@ttyS0.service",
			// Keep this last so cloud-init reports a provisioning failure even
			// when its generated runcmd shell does not enable errexit.
			"/usr/local/sbin/devbox-configure-rdp",
		},
	}

	metaData := &cloudinit.MetaData{
		InstanceID:    uuid.New().String(),
		LocalHostname: hostname,
	}

	networkConfig := &cloudinit.NetworkConfig{
		Network: cloudinit.Network{
			Version: 2,
			Ethernets: cloudinit.Ethernets{
				All: cloudinit.Ethernet{
					Match: &cloudinit.InterfaceMatch{
						Name: "en*",
					},
					DHCP4:    true,
					DHCP6:    false,
					AcceptRA: false,
				},
			},
		},
	}

	return userData, metaData, networkConfig, nil
}

func backendIdentityFiles(credentials backendidentity.Credentials) []cloudinit.WriteFile {
	return []cloudinit.WriteFile{
		{
			Path: "/etc/xrdp/devbox-cert.pem", Owner: "root:root", Permissions: "0644",
			Content: credentials.CertificatePEM, Defer: true,
		},
		{
			Path: "/etc/xrdp/devbox-key.pem", Owner: "root:xrdp", Permissions: "0640",
			Content: credentials.PrivateKeyPEM, Defer: true,
		},
		{
			Path: "/usr/local/sbin/devbox-configure-rdp", Owner: "root:root", Permissions: "0700",
			Content: configureRDPScript, Defer: true,
		},
	}
}

// The base image supplies xrdp and Python (also required by cloud-init). No
// private material is interpolated into commands or printed to cloud-init logs.
const configureRDPScript = `#!/bin/sh
set -eu
python3 - <<'PY'
import configparser
from pathlib import Path

path = Path('/etc/xrdp/xrdp.ini')
config = configparser.ConfigParser(interpolation=None, strict=False)
config.optionxform = str
with path.open() as source:
    config.read_file(source)
if not config.has_section('Globals'):
    raise RuntimeError('xrdp configuration is missing [Globals]')
for option in list(config['Globals']):
    if option.lower() in ('certificate', 'key_file', 'security_layer', 'ssl_protocols'):
        config.remove_option('Globals', option)
config.set('Globals', 'certificate', '/etc/xrdp/devbox-cert.pem')
config.set('Globals', 'key_file', '/etc/xrdp/devbox-key.pem')
config.set('Globals', 'security_layer', 'tls')
config.set('Globals', 'ssl_protocols', 'TLSv1.2, TLSv1.3')
with path.open('w') as destination:
    config.write(destination, space_around_delimiters=False)
PY
systemctl restart xrdp.service
`

// UploadSeedISO uploads seedISOData into vol.
func UploadSeedISO(conn *libvirt.Connect, vol *libvirt.StorageVol, seedISOData []byte) error {
	stream, err := conn.NewStream(0)
	if err != nil {
		return err
	}
	defer func() {
		_ = stream.Free()
	}()

	if err := vol.Upload(stream, 0, uint64(len(seedISOData)), 0); err != nil {
		return err
	}

	if err := stream.SendAll(StreamReaderChunks(bytes.NewReader(seedISOData))); err != nil {
		_ = stream.Abort()
		return err
	}

	return stream.Finish()
}
