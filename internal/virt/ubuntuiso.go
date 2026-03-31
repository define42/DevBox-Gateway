package virt

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/uuid"
	"libvirt.org/go/libvirt"
)

func CreateUbuntuSeedISOToPool(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
) error {

	// 2. Build cloud-init data
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
				Name:       username,
				Sudo:       "ALL=(ALL) NOPASSWD:ALL",
				Shell:      "/bin/bash",
				LockPasswd: false,
				Passwd:     cloudInitPasswordHash,
			},
		},
		SSHPwAuth: true,
		RunCmd: []string{
			"systemctl enable --now serial-getty@ttyS0.service",
		},
	}

	id := uuid.New()
	metaData := &SeedMetaData{
		InstanceID:    id.String(),
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

	// 3. Build the seed ISO in memory.
	seedISOData, err := CreateSeedISO(userData, metaData, networkConfig)
	if err != nil {
		return err
	}

	// 4. Lookup storage pool
	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return err
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	// 5. Create volume for ISO
	volXML, err := storageVolCreateXML(pool, volumeName, uint64(len(seedISOData)), "raw")
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

	// 6. Upload ISO into the volume
	src := bytes.NewReader(seedISOData)

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

	if err := stream.SendAll(func(_ *libvirt.Stream, nbytes int) ([]byte, error) {
		buf := make([]byte, nbytes)
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
		return buf[:n], nil
	}); err != nil {
		_ = stream.Abort()
		return err
	}

	return stream.Finish()
}
