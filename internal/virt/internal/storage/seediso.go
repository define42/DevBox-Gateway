package storage

import (
	"bytes"
	"log"

	"github.com/define42/devbox-gateway/internal/cloudinit"
	"github.com/define42/devbox-gateway/internal/config"

	"github.com/google/uuid"
	"libvirt.org/go/libvirt"
)

// CreateUbuntuSeedISOToPool builds a cloud-init seed ISO and uploads it to the storage pool.
func CreateUbuntuSeedISOToPool(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
) error {
	return CreateUbuntuSeedISOToPoolWithSettings(nil, conn, storagePoolName, volumeName, username, cloudInitPasswordHash, hostname)
}

// CreateUbuntuSeedISOToPoolWithSettings builds and uploads a seed ISO using explicit settings.
func CreateUbuntuSeedISOToPoolWithSettings(
	settings *config.SettingsType,
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
) error {
	userData, metaData, networkConfig := ubuntuSeedData(username, cloudInitPasswordHash, hostname)
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

func ubuntuSeedData(username, cloudInitPasswordHash, hostname string) (*cloudinit.UserData, *cloudinit.MetaData, *cloudinit.NetworkConfig) {
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
		RunCmd: []string{
			"systemctl enable --now serial-getty@ttyS0.service",
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

	return userData, metaData, networkConfig
}

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
