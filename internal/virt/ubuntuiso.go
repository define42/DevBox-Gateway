package virt

import (
	"bytes"
	"fmt"
	"rdptlsgateway/internal/config"

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
	return createUbuntuSeedISOToPoolWithSettings(nil, conn, storagePoolName, volumeName, username, cloudInitPasswordHash, hostname)
}

func createUbuntuSeedISOToPoolWithSettings(
	settings *config.SettingsType,
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
) error {
	userData, metaData, networkConfig := ubuntuSeedData(username, cloudInitPasswordHash, hostname)
	seedISOData, err := CreateSeedISO(userData, metaData, networkConfig)
	if err != nil {
		return err
	}

	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return err
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	volXML, err := storageVolCreateXMLWithSettings(settings, pool, volumeName, uint64(len(seedISOData)), "raw")
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

	if err := uploadSeedISO(conn, vol, seedISOData); err != nil {
		return err
	}

	return applyStorageVolPermissions(settings, vol)
}

func ubuntuSeedData(username, cloudInitPasswordHash, hostname string) (*SeedUserData, *SeedMetaData, *SeedNetworkConfig) {
	userData := &SeedUserData{
		Output: &SeedOutput{
			All: "| tee -a /var/log/cloud-init-output.log",
		},
		Keyboard: &SeedKeyboard{
			Layout:  "dk",
			Variant: "",
		},
		Users: []SeedUser{
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

	metaData := &SeedMetaData{
		InstanceID:    uuid.New().String(),
		LocalHostname: hostname,
	}

	networkConfig := &SeedNetworkConfig{
		Network: SeedNetwork{
			Version: 2,
			Ethernets: SeedEthernets{
				All: SeedEthernet{
					Match: &SeedInterfaceMatch{
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

func uploadSeedISO(conn *libvirt.Connect, vol *libvirt.StorageVol, seedISOData []byte) error {
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

	if err := stream.SendAll(streamReaderChunks(bytes.NewReader(seedISOData))); err != nil {
		_ = stream.Abort()
		return err
	}

	return stream.Finish()
}
