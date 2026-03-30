package virt

import (
	"fmt"
	"io"
	"os"

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
	userData := []byte(`#cloud-config
output:
  all: '| tee -a /var/log/cloud-init-output.log'
keyboard:
  layout: dk
  variant: ''
users:
  - name: ` + username + `
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: ` + cloudInitPasswordHash + `
ssh_pwauth: true
runcmd:
  - systemctl enable --now serial-getty@ttyS0.service
`)

	fmt.Println("userData:", string(userData))

	id := uuid.New()
	metaData := []byte(`instance-id: ` + id.String() + `
local-hostname: ` + hostname + `
`)

	networkConfig := []byte(`#cloud-config
network:
  version: 2
  ethernets:
    all:
      match:
        name: "en*"
      dhcp4: true
	  dhcp6: false
	  accept-ra: false
`)

	// 3. Create temporary ISO
	tmpFile, err := os.CreateTemp("", "seed-*.iso")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	iso := SeedISO{
		UserData:      userData,
		MetaData:      metaData,
		NetworkConfig: networkConfig,
	}

	if err := iso.Create(tmpFile.Name()); err != nil {
		return err
	}

	info, err := os.Stat(tmpFile.Name())
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
	permXML, err := storageVolPermissionsXML()
	if err != nil {
		return err
	}
	pathXML := ""
	if permXML != "" {
		pathXML, err = storageVolPathXML(pool, volumeName)
		if err != nil {
			return err
		}
	}
	volXML := fmt.Sprintf(`
<volume>
  <name>%s</name>
  <capacity unit="bytes">%d</capacity>
  <target>
    <format type="raw"/>%s%s
  </target>
</volume>`, volumeName, info.Size(), pathXML, permXML)

	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return err
	}
	defer func() {
		_ = vol.Free()
	}()

	// 6. Upload ISO into the volume
	src, err := os.Open(tmpFile.Name())
	if err != nil {
		return err
	}
	defer src.Close()

	stream, err := conn.NewStream(0)
	if err != nil {
		return err
	}
	defer func() {
		_ = stream.Free()
	}()

	if err := vol.Upload(stream, 0, uint64(info.Size()), 0); err != nil {
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
